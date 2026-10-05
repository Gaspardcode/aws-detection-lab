output "triage_function" {
  value = aws_lambda_function.triage.function_name
}

output "response_function" {
  value = aws_lambda_function.response.function_name
}

output "athena_runner_function" {
  value = aws_lambda_function.athena_runner.function_name
}

output "rules_deployed" {
  value = sort(keys(local.pattern_rules))
}
