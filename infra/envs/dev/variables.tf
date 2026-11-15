variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

# No default on purpose: this repository is public, so the account ID is never committed.
variable "allowed_account_id" {
  description = "The only AWS account this stack may run against."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.allowed_account_id))
    error_message = "allowed_account_id must be a 12-digit AWS account ID."
  }
}

# No default on purpose: who may reach the service is a decision, not a convenience. The service
# only returns static JSON, but "the whole internet" should be chosen deliberately.
variable "allowed_ingress_cidrs" {
  description = "CIDR blocks allowed to reach the service port."
  type        = list(string)

  validation {
    condition     = length(var.allowed_ingress_cidrs) > 0 && alltrue([for c in var.allowed_ingress_cidrs : can(cidrnetmask(c))])
    error_message = "allowed_ingress_cidrs must be a non-empty list of valid IPv4 CIDR blocks."
  }
}

variable "name_prefix" {
  description = "Prefix for every resource; the apply role may only touch names with this prefix."
  type        = string
  default     = "pe-lab"
}

variable "vpc_cidr" {
  description = "CIDR block of the lab VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "container_port" {
  description = "Port the service listens on."
  type        = number
  default     = 8080
}

variable "cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 256
}

variable "memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 512
}

# The image tag is the commit SHA in CI. Tags are immutable, so rolling back is deploying an older tag.
variable "image_tag" {
  description = "Image tag to run."
  type        = string
  default     = "bootstrap"
}

# Zero until an image exists in the registry; the pipeline raises it. Keeping the service at zero
# also keeps the lab free when nothing is being worked on.
variable "desired_count" {
  description = "Number of tasks to run."
  type        = number
  default     = 0

  validation {
    condition     = var.desired_count >= 0 && var.desired_count <= 2
    error_message = "desired_count must be between 0 and 2 for this lab."
  }
}

variable "log_retention_days" {
  description = "Days to keep service logs."
  type        = number
  default     = 7
}

variable "ecr_keep_images" {
  description = "Number of most recent images to keep in the registry."
  type        = number
  default     = 10
}
