output "plan_role_arn" {
  description = "Role for terraform plan in CI (pull requests and main). Set as a repository variable."
  value       = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  description = "Role for terraform apply in CI (main only). Set as a repository variable."
  value       = aws_iam_role.apply.arn
}

output "permissions_boundary_arn" {
  description = "Boundary every role created by the apply role must carry."
  value       = aws_iam_policy.boundary.arn
}
