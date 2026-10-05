output "log_bucket" {
  value = aws_s3_bucket.logs.bucket
}

output "log_bucket_arn" {
  value = aws_s3_bucket.logs.arn
}
