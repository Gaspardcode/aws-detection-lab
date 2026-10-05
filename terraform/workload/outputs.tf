output "patients_bucket" {
  value = aws_s3_bucket.patients.bucket
}

output "patients_key_arn" {
  value = aws_kms_key.patients.arn
}

output "app_instance_id" {
  value = aws_instance.app.id
}

output "dev_user" {
  value = aws_iam_user.dev.name
}
