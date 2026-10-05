output "trail_arn" {
  value = aws_cloudtrail.main.arn
}

output "athena_workgroup" {
  value = aws_athena_workgroup.detection.name
}

output "glue_database" {
  value = aws_glue_catalog_database.logs.name
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}
