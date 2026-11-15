output "cluster_name" {
  description = "ECS cluster name."
  value       = aws_ecs_cluster.main.name
}

output "service_name" {
  description = "ECS service name."
  value       = aws_ecs_service.app.name
}

output "ecr_repository_url" {
  description = "Registry the pipeline pushes images to."
  value       = aws_ecr_repository.app.repository_url
}

output "log_group_name" {
  description = "Where the service logs go."
  value       = aws_cloudwatch_log_group.app.name
}

output "vpc_id" {
  description = "Lab VPC."
  value       = aws_vpc.main.id
}
