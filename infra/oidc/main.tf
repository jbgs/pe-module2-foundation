# Trust between GitHub Actions and this AWS account, with no long-lived keys.
# Each workflow run asks GitHub for a short-lived signed token; AWS validates it and returns
# credentials that expire in about an hour. Two roles split read-only planning from applying.

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  repo       = "${var.github_owner}/${var.github_repo}"

  # The `sub` claim is what pins a role to this repository and to a specific kind of run.
  # Without a tight condition on it, any repository on GitHub could assume the role.
  sub_pull_request = "repo:${local.repo}:pull_request"
  sub_main_branch  = "repo:${local.repo}:ref:refs/heads/main"

  oidc_host = "token.actions.githubusercontent.com"

  state_bucket_arn = "arn:aws:s3:::${var.state_bucket_name}"
}

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

# ---------------------------------------------------------------------------------------
# Trust policies
# ---------------------------------------------------------------------------------------

# Plan role: assumable by pull requests and by the main branch of this repository only.
data "aws_iam_policy_document" "trust_plan" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [local.sub_pull_request, local.sub_main_branch]
    }
  }
}

# Apply role: assumable ONLY by runs on the main branch of this repository. A pull request,
# including one opened from a fork, can never assume it and so can never change infrastructure.
data "aws_iam_policy_document" "trust_apply" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [local.sub_main_branch]
    }
  }
}

# ---------------------------------------------------------------------------------------
# Plan role: read-only, plus the state lock file
# ---------------------------------------------------------------------------------------

resource "aws_iam_role" "plan" {
  name                 = "${var.name_prefix}-gha-plan"
  description          = "GitHub Actions: terraform plan (read-only) for pull requests and main"
  assume_role_policy   = data.aws_iam_policy_document.trust_plan.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_read_only" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_state" {
  statement {
    sid       = "StateBucketList"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [local.state_bucket_arn]
  }

  statement {
    sid       = "StateRead"
    actions   = ["s3:GetObject"]
    resources = ["${local.state_bucket_arn}/*"]
  }

  # S3 native locking writes a small .tflock object next to the state file.
  statement {
    sid       = "StateLockOnly"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.state_bucket_arn}/*.tflock"]
  }
}

resource "aws_iam_role_policy" "plan_state" {
  name   = "state-read-and-lock"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_state.json
}

# ---------------------------------------------------------------------------------------
# Permissions boundary: the ceiling for every role the pipeline is allowed to create
# ---------------------------------------------------------------------------------------

data "aws_iam_policy_document" "boundary" {
  statement {
    sid = "TaskRuntimeOnly"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${var.name_prefix}-boundary"
  description = "Ceiling for roles created by the apply role; widen in a reviewed pull request"
  policy      = data.aws_iam_policy_document.boundary.json
}

# ---------------------------------------------------------------------------------------
# Apply role: least privilege to start, widened later in reviewed pull requests
# ---------------------------------------------------------------------------------------

resource "aws_iam_role" "apply" {
  name                 = "${var.name_prefix}-gha-apply"
  description          = "GitHub Actions: terraform apply, main branch of this repository only"
  assume_role_policy   = data.aws_iam_policy_document.trust_apply.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "apply" {
  # Remote state.
  statement {
    sid       = "StateBucketList"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [local.state_bucket_arn]
  }

  statement {
    sid       = "StateObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${local.state_bucket_arn}/*"]
  }

  # Container registry.
  statement {
    sid       = "EcrAuthToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid       = "EcrRepositories"
    actions   = ["ecr:*"]
    resources = ["arn:aws:ecr:${var.region}:${local.account_id}:repository/${var.name_prefix}-*"]
  }

  # ECS: describe and register are not resource-scopable; mutations are limited to the prefix.
  statement {
    sid = "EcsReadAndRegister"
    actions = [
      "ecs:Describe*",
      "ecs:List*",
      "ecs:RegisterTaskDefinition",
      "ecs:DeregisterTaskDefinition",
    ]
    resources = ["*"]
  }

  statement {
    sid = "EcsManagePrefixed"
    actions = [
      "ecs:CreateCluster",
      "ecs:UpdateCluster",
      "ecs:DeleteCluster",
      "ecs:PutClusterCapacityProviders",
      "ecs:CreateService",
      "ecs:UpdateService",
      "ecs:DeleteService",
      "ecs:TagResource",
      "ecs:UntagResource",
    ]
    resources = [
      "arn:aws:ecs:${var.region}:${local.account_id}:cluster/${var.name_prefix}-*",
      "arn:aws:ecs:${var.region}:${local.account_id}:service/${var.name_prefix}-*/*",
      "arn:aws:ecs:${var.region}:${local.account_id}:task-definition/${var.name_prefix}-*:*",
    ]
  }

  # Logs.
  statement {
    sid       = "LogsDescribe"
    actions   = ["logs:DescribeLogGroups", "logs:ListTagsForResource"]
    resources = ["*"]
  }

  statement {
    sid = "LogsManagePrefixed"
    actions = [
      "logs:CreateLogGroup",
      "logs:DeleteLogGroup",
      "logs:PutRetentionPolicy",
      "logs:TagResource",
      "logs:UntagResource",
    ]
    resources = ["arn:aws:logs:${var.region}:${local.account_id}:log-group:/${var.name_prefix}/*"]
  }

  # Networking for the dev service: security groups in the default VPC. Security group ARNs
  # cannot be prefix-scoped on create, so this is the widest part; narrow it when a VPC is added.
  statement {
    sid       = "Ec2Describe"
    actions   = ["ec2:Describe*"]
    resources = ["*"]
  }

  statement {
    sid = "Ec2SecurityGroups"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:CreateTags",
      "ec2:DeleteTags",
    ]
    resources = ["*"]
  }

  # Network for the dev service: a VPC with public subnets and an internet gateway, no NAT. The
  # EC2 API cannot scope these create actions by name prefix, so they are the widest part of the
  # role. This block was added in a reviewed pull request, when the environment needed it.
  statement {
    sid = "Ec2Network"
    actions = [
      "ec2:CreateVpc",
      "ec2:DeleteVpc",
      "ec2:ModifyVpcAttribute",
      "ec2:CreateSubnet",
      "ec2:DeleteSubnet",
      "ec2:ModifySubnetAttribute",
      "ec2:CreateInternetGateway",
      "ec2:DeleteInternetGateway",
      "ec2:AttachInternetGateway",
      "ec2:DetachInternetGateway",
      "ec2:CreateRouteTable",
      "ec2:DeleteRouteTable",
      "ec2:CreateRoute",
      "ec2:DeleteRoute",
      "ec2:AssociateRouteTable",
      "ec2:DisassociateRouteTable",
      "ec2:ModifySecurityGroupRules",
    ]
    resources = ["*"]
  }

  # IAM: only roles with the lab prefix, and every new role must carry the permissions boundary,
  # so the apply role cannot mint a more powerful role than the boundary allows.
  statement {
    sid       = "IamCreateRoleWithBoundary"
    actions   = ["iam:CreateRole", "iam:PutRolePermissionsBoundary"]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.name_prefix}-*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PermissionsBoundary"
      values   = [aws_iam_policy.boundary.arn]
    }
  }

  statement {
    sid = "IamManagePrefixedRoles"
    actions = [
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:TagRole",
      "iam:UntagRole",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:AttachRolePolicy",
      "iam:DetachRolePolicy",
      "iam:ListInstanceProfilesForRole",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.name_prefix}-*"]
  }

  statement {
    sid       = "IamPassRoleToEcsTasks"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.name_prefix}-*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["ecs-tasks.amazonaws.com"]
    }
  }

  statement {
    sid       = "IamReadManagedPolicies"
    actions   = ["iam:GetPolicy", "iam:GetPolicyVersion"]
    resources = ["arn:aws:iam::aws:policy/*"]
  }

  # First ECS use in a fresh account needs its service-linked role.
  statement {
    sid       = "EcsServiceLinkedRole"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["ecs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "apply" {
  name   = "lab-foundation-apply"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply.json
}
