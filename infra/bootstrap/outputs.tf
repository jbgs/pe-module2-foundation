output "state_bucket_name" {
  description = "Name of the remote state bucket, to pass to the backend of other stacks."
  value       = aws_s3_bucket.state.id
}

output "region" {
  description = "Region of the state bucket."
  value       = var.region
}
