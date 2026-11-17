output "audit_bucket" {
  description = "Name of the audit bucket (it contains the account ID, so it is not committed anywhere)."
  value       = aws_s3_bucket.audit.id
}

output "writer_role_arn" {
  description = "Role that the pipeline assumes, on main only, to write audit records."
  value       = aws_iam_role.writer.arn
}

output "retention" {
  description = "Object Lock mode and days applied to every new object."
  value       = "GOVERNANCE, ${var.retention_days} day(s)"
}
