output "state_bucket" {
  value = aws_s3_bucket.tfstate.bucket
}

output "attacker_role_arn" {
  value = aws_iam_role.attacker.arn
}

# À copier dans terraform/backend.hcl (non versionné)
output "backend_hcl" {
  value = <<-EOT
    bucket       = "${aws_s3_bucket.tfstate.bucket}"
    region       = "${var.region}"
    encrypt      = true
    use_lockfile = true
  EOT
}
