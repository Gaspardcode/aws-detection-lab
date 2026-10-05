# Stack "detection" : règles EventBridge, Lambdas triage / réponse / athena_runner.
# JETABLE (détruit chaque soir), mais à appliquer APRÈS network, workload et logging :
# il retrouve le VPC, l'SG d'isolement et le bucket patients par leurs noms.
#
# Pièges d'AWS traités ici :
#   - les événements IAM sont GLOBAUX : ils n'existent que sur le bus par défaut de
#     us-east-1. Les règles marquées "global": true dans meta.json sont donc doublées
#     d'une règle de transfert us-east-1 -> bus de la région principale ;
#   - la politique de référence du bucket patients est photographiée dans SSM au moment
#     de l'apply : l'appliquer sur un bucket déjà trafiqué figerait la politique piégée.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }
  backend "s3" {
    key = "detection/terraform.tfstate"
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = var.project
      Stack     = "detection"
      ManagedBy = "terraform"
    }
  }
}

# Les événements IAM arrivent ici
provider "aws" {
  alias  = "use1"
  region = "us-east-1"
  default_tags {
    tags = {
      Project   = var.project
      Stack     = "detection"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  rules_dir       = "${path.module}/../../rules"
  lambdas_dir     = "${path.module}/../../lambdas"
  log_bucket      = "${var.project}-log-archive-${local.account_id}"
  patients_bucket = "${var.project}-patients-${local.account_id}"
  workgroup       = "${var.project}-detection"
  database        = "adl_logs"

  # rules/<id>/meta.json et rules/<id>/pattern.json -> une règle EventBridge par pattern.json
  rule_meta     = { for p in fileset(local.rules_dir, "*/meta.json") : dirname(p) => jsondecode(file("${local.rules_dir}/${p}")) }
  pattern_rules = { for id, m in local.rule_meta : id => m if fileexists("${local.rules_dir}/${id}/pattern.json") }
  global_rules  = { for id, m in local.pattern_rules : id => m if try(m.global, false) }
}

# --- ressources retrouvées par nom (pas de couplage de states) ---------------
data "aws_vpc" "main" {
  tags = { Project = var.project, Name = "${var.project}-vpc" }
}

data "aws_security_group" "isolation" {
  vpc_id = data.aws_vpc.main.id
  name   = "${var.project}-isolation"
}

data "aws_s3_bucket_policy" "patients" {
  bucket = local.patients_bucket
}

resource "aws_ssm_parameter" "baseline_policy" {
  name        = "/${var.project}/baseline-bucket-policy"
  type        = "String"
  tier        = "Standard"
  value       = data.aws_s3_bucket_policy.patients.policy
  description = "Politique de reference du bucket patients (restauree par la Lambda de reponse)"
}

# ---------------------------------------------------------------------------
# Déduplication : une ligne par alerte récente, expirée par TTL
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "dedup" {
  name         = "${var.project}-alert-dedup"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"

  attribute {
    name = "pk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = false
  }
}

# ---------------------------------------------------------------------------
# Paquets Lambda : handler.py + (triage, athena_runner) les règles embarquées
# ---------------------------------------------------------------------------
data "archive_file" "triage" {
  type        = "zip"
  output_path = "${path.module}/.build/triage.zip"

  source {
    content  = file("${local.lambdas_dir}/triage/handler.py")
    filename = "handler.py"
  }
  dynamic "source" {
    for_each = local.rule_meta
    content {
      content  = file("${local.rules_dir}/${source.key}/meta.json")
      filename = "rules/${source.key}/meta.json"
    }
  }
}

data "archive_file" "response" {
  type        = "zip"
  output_path = "${path.module}/.build/response.zip"

  source {
    content  = file("${local.lambdas_dir}/response/handler.py")
    filename = "handler.py"
  }
}

data "archive_file" "athena_runner" {
  type        = "zip"
  output_path = "${path.module}/.build/athena_runner.zip"

  source {
    content  = file("${local.lambdas_dir}/athena_runner/handler.py")
    filename = "handler.py"
  }
  dynamic "source" {
    for_each = { for id, m in local.rule_meta : id => m if m.kind == "query" }
    content {
      content  = file("${local.rules_dir}/${source.key}/query.sql")
      filename = "rules/${source.key}/query.sql"
    }
  }
}

# ---------------------------------------------------------------------------
# IAM : un rôle par Lambda, droits au plus juste
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "triage" {
  name               = "${var.project}-triage"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role" "response" {
  name               = "${var.project}-response"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role" "athena_runner" {
  name               = "${var.project}-athena-runner"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "logs" {
  for_each = {
    triage        = aws_iam_role.triage.name
    response      = aws_iam_role.response.name
    athena_runner = aws_iam_role.athena_runner.name
  }
  role       = each.value
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "aws_iam_policy_document" "triage" {
  statement {
    sid       = "Dedup"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.dedup.arn]
  }
  statement {
    sid       = "ReadWebhook"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${local.account_id}:parameter${var.webhook_param}"]
  }
  statement {
    sid       = "InvokeResponse"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.response.arn]
  }
  statement {
    sid       = "EnrichUserTags"
    actions   = ["iam:ListUserTags"]
    resources = ["arn:aws:iam::${local.account_id}:user/*"]
  }
  statement {
    sid       = "EnrichHistory"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"] # pas de ressource possible pour cette action
  }
}

resource "aws_iam_role_policy" "triage" {
  name   = "triage"
  role   = aws_iam_role.triage.id
  policy = data.aws_iam_policy_document.triage.json
}

# Réponse : un statement par action, pour pouvoir en retirer une sans toucher aux autres
data "aws_iam_policy_document" "response" {
  statement {
    sid       = "DisableAccessKey"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${local.account_id}:user/lab/*"] # seuls les utilisateurs du lab
  }
  statement {
    sid       = "IsolateDescribe"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeVolumes"]
    resources = ["*"]
  }
  statement {
    sid       = "IsolateSnapshot"
    actions   = ["ec2:CreateSnapshot"]
    resources = ["arn:aws:ec2:${var.region}:${local.account_id}:volume/*", "arn:aws:ec2:${var.region}::snapshot/*"]
  }
  statement {
    sid       = "IsolateTagSnapshot"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:${var.region}::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:CreateAction"
      values   = ["CreateSnapshot"]
    }
  }
  statement {
    sid     = "IsolateSwapSecurityGroup"
    actions = ["ec2:ModifyInstanceAttribute"]
    resources = [
      "arn:aws:ec2:${var.region}:${local.account_id}:instance/*",
      "arn:aws:ec2:${var.region}:${local.account_id}:security-group/${data.aws_security_group.isolation.id}",
    ]
  }
  statement {
    sid       = "IsolateTagInstance"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:aws:ec2:${var.region}:${local.account_id}:instance/*"]
  }
  statement {
    sid       = "RestoreBucketPolicy"
    actions   = ["s3:PutBucketPolicy"]
    resources = ["arn:aws:s3:::${local.patients_bucket}"]
  }
  statement {
    sid       = "ReadBaselinePolicy"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.baseline_policy.arn]
  }
}

resource "aws_iam_role_policy" "response" {
  name   = "response"
  role   = aws_iam_role.response.id
  policy = data.aws_iam_policy_document.response.json
}

data "aws_iam_policy_document" "athena_runner" {
  statement {
    sid       = "RunQueries"
    actions   = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults"]
    resources = ["arn:aws:athena:${var.region}:${local.account_id}:workgroup/${local.workgroup}"]
  }
  statement {
    sid     = "ReadCatalog"
    actions = ["glue:GetDatabase", "glue:GetTable", "glue:GetPartitions"]
    resources = [
      "arn:aws:glue:${var.region}:${local.account_id}:catalog",
      "arn:aws:glue:${var.region}:${local.account_id}:database/${local.database}",
      "arn:aws:glue:${var.region}:${local.account_id}:table/${local.database}/*",
    ]
  }
  statement {
    sid       = "ReadLogs"
    actions   = ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"]
    resources = ["arn:aws:s3:::${local.log_bucket}", "arn:aws:s3:::${local.log_bucket}/*"]
  }
  statement {
    sid       = "WriteResults"
    actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["arn:aws:s3:::${local.log_bucket}/athena-results/*"]
  }
  statement {
    sid       = "InvokeTriage"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.triage.arn]
  }
}

resource "aws_iam_role_policy" "athena_runner" {
  name   = "athena-runner"
  role   = aws_iam_role.athena_runner.id
  policy = data.aws_iam_policy_document.athena_runner.json
}

# ---------------------------------------------------------------------------
# Lambdas
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = toset(["triage", "response", "athena-runner"])
  name              = "/aws/lambda/${var.project}-${each.key}"
  retention_in_days = 14
}

resource "aws_lambda_function" "response" {
  function_name    = "${var.project}-response"
  role             = aws_iam_role.response.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.response.output_path
  source_code_hash = data.archive_file.response.output_base64sha256
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      DRY_RUN               = tostring(var.response_dry_run)
      ISOLATION_SG          = data.aws_security_group.isolation.id
      PATIENTS_BUCKET       = local.patients_bucket
      BASELINE_POLICY_PARAM = aws_ssm_parameter.baseline_policy.name
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

resource "aws_lambda_function" "triage" {
  function_name    = "${var.project}-triage"
  role             = aws_iam_role.triage.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.triage.output_path
  source_code_hash = data.archive_file.triage.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      DEDUP_TABLE       = aws_dynamodb_table.dedup.name
      WEBHOOK_PARAM     = var.webhook_param
      RESPONSE_FUNCTION = "${var.project}-response"
      ENRICH_HISTORY    = tostring(var.enrich_history)
      RESPONSE_DRY_RUN  = tostring(var.response_dry_run)
      RUNBOOK_BASE_URL  = var.runbook_base_url
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

resource "aws_lambda_function" "athena_runner" {
  function_name    = "${var.project}-athena-runner"
  role             = aws_iam_role.athena_runner.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.athena_runner.output_path
  source_code_hash = data.archive_file.athena_runner.output_base64sha256
  timeout          = 300
  memory_size      = 128

  environment {
    variables = {
      WORKGROUP       = local.workgroup
      DATABASE        = local.database
      TRIAGE_FUNCTION = "${var.project}-triage"
      QUERY_TIMEOUT   = "240"
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

# ---------------------------------------------------------------------------
# Règles temps réel : une par rules/<id>/pattern.json
# ---------------------------------------------------------------------------
module "rule" {
  source   = "./modules/rule"
  for_each = local.pattern_rules

  rule_id              = each.key
  description          = each.value.title
  pattern              = file("${local.rules_dir}/${each.key}/pattern.json")
  attack               = each.value.attack
  target_arn           = aws_lambda_function.triage.arn
  lambda_function_name = aws_lambda_function.triage.function_name
  name_prefix          = var.project
}

# Findings GuardDuty : tout ce qui est de sévérité >= 4
module "guardduty" {
  source = "./modules/rule"

  rule_id     = "guardduty"
  description = "Findings GuardDuty de severite moyenne ou plus"
  pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 4] }] }
  })
  target_arn           = aws_lambda_function.triage.arn
  lambda_function_name = aws_lambda_function.triage.function_name
  name_prefix          = var.project
}

# --- Transfert des événements IAM (us-east-1) vers le bus de la région principale ---
data "aws_iam_policy_document" "events_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "forward" {
  name               = "${var.project}-forward-events"
  assume_role_policy = data.aws_iam_policy_document.events_trust.json
}

resource "aws_iam_role_policy" "forward" {
  name = "put-events-home-bus"
  role = aws_iam_role.forward.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:PutEvents"
      Resource = "arn:aws:events:${var.region}:${local.account_id}:event-bus/default"
    }]
  })
}

module "forward_global" {
  source    = "./modules/rule"
  providers = { aws = aws.use1 }
  for_each  = local.global_rules

  rule_id      = "fwd-${each.key}"
  description  = "Transfert us-east-1 vers ${var.region} : ${each.value.title}"
  pattern      = file("${local.rules_dir}/${each.key}/pattern.json")
  attack       = each.value.attack
  target_arn   = "arn:aws:events:${var.region}:${local.account_id}:event-bus/default"
  role_arn     = aws_iam_role.forward.arn
  wrap_rule_id = false
  name_prefix  = var.project
}

# ---------------------------------------------------------------------------
# Règles volumétriques : exécution horaire d'athena_runner
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "athena_schedule" {
  name                = "${var.project}-athena-schedule"
  description         = "Execute les requetes volumetriques (rules/*/query.sql)"
  schedule_expression = var.athena_schedule
}

resource "aws_cloudwatch_event_target" "athena_schedule" {
  rule = aws_cloudwatch_event_rule.athena_schedule.name
  arn  = aws_lambda_function.athena_runner.arn
}

resource "aws_lambda_permission" "athena_schedule" {
  statement_id  = "AllowEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.athena_runner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.athena_schedule.arn
}
