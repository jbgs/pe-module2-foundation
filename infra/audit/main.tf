# The audit store: where the audit records of agent runs are kept so that the pipeline that wrote them cannot
# change them afterwards. Applied from a laptop with an administrator profile, like the other stacks that the
# pipeline itself depends on, because the pipeline's own role must not be able to create or loosen it.
#
# Three things make a record here hard to change:
#   1. Object Lock (governance mode): a written object cannot be deleted or overwritten until its retention ends,
#      by anyone who has not been explicitly granted the permission to bypass it. The pipeline's role is not.
#   2. Write once: the bucket refuses any write that does not say "only if the object does not exist yet", so a
#      record cannot be replaced by writing a new version under the same name.
#   3. A writer that can only write: the role the pipeline assumes can put an object under one prefix. It cannot
#      read, delete, change the lock, the versioning or the policy; the bucket policy denies it all of those as well.

data "aws_caller_identity" "current" {}

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

locals {
  account_id = data.aws_caller_identity.current.account_id

  # The account ID is in the name only to make it globally unique. It is computed here, never written in the code.
  bucket_name = "${var.name_prefix}-audit-${local.account_id}"
  bucket_arn  = "arn:aws:s3:::${local.bucket_name}"
  writer_name = "${var.name_prefix}-gha-audit-writer"
  writer_arn  = "arn:aws:iam::${local.account_id}:role/${local.writer_name}"
  prefix      = "agent-runs/"

  oidc_host       = "token.actions.githubusercontent.com"
  sub_prefix      = "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}"
  sub_main_branch = "${local.sub_prefix}:ref:refs/heads/main"
}

# ---------------------------------------------------------------------------------------
# The bucket
# ---------------------------------------------------------------------------------------

resource "aws_s3_bucket" "audit" {
  bucket = local.bucket_name

  # Object Lock can only be switched on when a bucket is created.
  object_lock_enabled = true

  # Never delete a bucket that still holds records by accident. Cleaning up a lab is a deliberate act: see the README.
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket = aws_s3_bucket.audit.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# The bucket owner owns every object, and ACLs play no part.
resource "aws_s3_bucket_ownership_controls" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      local.bucket_arn,
      "${local.bucket_arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Write once. A write must carry the header If-None-Match: *, which S3 honours only if no object with that name
  # exists. Without it, writing the same name again would only add a new version on top of the locked one.
  statement {
    sid       = "DenyAWriteThatCouldReplaceARecord"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["true"]
    }
  }

  # The identity policy of the writer grants nothing but PutObject; this denies the rest explicitly, so that a
  # permission added to the role by mistake later would still not work.
  statement {
    sid         = "DenyTheWriterEverythingButWriting"
    effect      = "Deny"
    not_actions = ["s3:PutObject"]
    resources = [
      local.bucket_arn,
      "${local.bucket_arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = [local.writer_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [aws_s3_bucket_public_access_block.audit]
}

# ---------------------------------------------------------------------------------------
# The writer: assumable only by runs on the main branch, and able to do nothing but write
# ---------------------------------------------------------------------------------------

data "aws_iam_policy_document" "trust_writer" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # The immutable IDs of the owner and the repository, as in the other roles: a repository deleted and recreated
    # under the same name has other IDs and cannot assume this role. Main only: a pull request, whose workflow
    # its author can change, never writes to the store.
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [local.sub_main_branch]
    }
  }
}

resource "aws_iam_role" "writer" {
  name                 = local.writer_name
  description          = "GitHub Actions: write audit records of agent runs, once, and nothing else"
  assume_role_policy   = data.aws_iam_policy_document.trust_writer.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "writer" {
  statement {
    sid       = "WriteTheRecordsOfARun"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/${local.prefix}*"]
  }
}

resource "aws_iam_role_policy" "writer" {
  name   = "write-audit-records"
  role   = aws_iam_role.writer.id
  policy = data.aws_iam_policy_document.writer.json
}
