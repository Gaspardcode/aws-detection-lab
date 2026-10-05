# Stack "bootstrap" : ce qui doit exister avant tout le reste et ne se détruit
# jamais pendant le projet. State LOCAL (problème de l'œuf et de la poule) :
# garder terraform.tfstate hors du dépôt (.gitignore) et en sauvegarde.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project   = var.project
      Stack     = "bootstrap"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  state_bucket = "${var.project}-tfstate-${local.account_id}"
}

# ---------------------------------------------------------------------------
# Garde-fou de compte : aucun bucket public, quel que soit le stack.
# (Stratus "s3-backdoor-bucket-policy" ouvre vers un compte externe, pas au
# public : ce blocage ne gêne pas le scénario.)
# ---------------------------------------------------------------------------
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Bucket du state Terraform (verrou natif S3 via use_lockfile, TF >= 1.10)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "tfstate" {
  bucket = local.state_bucket
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

# SSE-S3 assumé : une clé KMS dédiée coûte 1 $/mois et n'apporte rien ici,
# l'accès au state étant déjà limité aux admins du compte de lab.
#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    id     = "anciennes-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

data "aws_iam_policy_document" "tfstate" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate.json
}

# ---------------------------------------------------------------------------
# Budgets : alerte e-mail à 80 % / 100 % réels et 100 % prévisionnel.
# Compte en "free plan" : la consommation est payée par des crédits. Les
# crédits sont EXCLUS du calcul, sinon le coût net reste à 0 $ et aucune
# alerte ne part : on suit donc la vitesse à laquelle on brûle les crédits.
# ---------------------------------------------------------------------------
resource "aws_budgets_budget" "monthly" {
  for_each = toset([for l in var.budget_limits_usd : tostring(l)])

  name         = "${var.project}-${each.value}usd"
  budget_type  = "COST"
  limit_amount = each.value
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_types {
    include_credit = false
    include_refund = false
  }

  dynamic "notification" {
    for_each = [
      { type = "ACTUAL", threshold = 80 },
      { type = "ACTUAL", threshold = 100 },
      { type = "FORECASTED", threshold = 100 },
    ]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.alert_email]
    }
  }
}

# ---------------------------------------------------------------------------
# Rôle "attaquant" : utilisé uniquement par Stratus Red Team.
# Stratus crée et détruit ses propres ressources, il lui faut des droits larges.
# L'intérêt du rôle séparé : dans CloudTrail, toute action d'attaque porte
# l'ARN "assumed-role/lab-attaquant/..." -> vérité terrain pour mesurer la
# détection, et facile à exclure du bruit ou à filtrer dans Athena.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "attacker_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_iam_role" "attacker" {
  name                 = "lab-attaquant"
  description          = "Role reserve a Stratus Red Team (verite terrain des attaques)"
  assume_role_policy   = data.aws_iam_policy_document.attacker_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "attacker_admin" {
  role       = aws_iam_role.attacker.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
