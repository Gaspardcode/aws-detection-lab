output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "app_sg_id" {
  value = aws_security_group.app.id
}

output "isolation_sg_id" {
  value = aws_security_group.isolation.id
}

output "s3_endpoint_id" {
  value = aws_vpc_endpoint.s3.id
}
