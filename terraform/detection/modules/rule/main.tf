# Module "rule" : une règle de détection EventBridge -> cible.
# Réutilisé pour chaque dossier rules/<id>/pattern.json, pour le transfert des
# événements IAM (us-east-1 -> région principale) et pour les findings GuardDuty.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

resource "aws_cloudwatch_event_rule" "this" {
  name          = "${var.name_prefix}-${var.rule_id}"
  description   = var.description
  event_pattern = var.pattern
  tags          = { Attack = join(",", var.attack) }
}

resource "aws_cloudwatch_event_target" "this" {
  rule     = aws_cloudwatch_event_rule.this.name
  arn      = var.target_arn
  role_arn = var.role_arn

  dynamic "input_transformer" {
    for_each = var.wrap_rule_id ? [1] : []
    content {
      input_template = "{\"rule_id\":\"${var.rule_id}\",\"event\":<aws.events.event.json>}"
    }
  }
}

resource "aws_lambda_permission" "events" {
  count         = var.lambda_function_name == null ? 0 : 1
  statement_id  = "AllowEventBridge-${var.rule_id}"
  action        = "lambda:InvokeFunction"
  function_name = var.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}
