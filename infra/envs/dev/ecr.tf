resource "aws_ecr_repository" "app" {
  name = "${var.name_prefix}-app"

  # Immutable tags: a version is never overwritten, so a tag always means the same image and a
  # rollback is simply deploying an older tag. This is also what makes the record trustworthy.
  image_tag_mutability = "IMMUTABLE"

  # A lab environment must be destroyable and recreatable even when it holds images.
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the most recent images only"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.ecr_keep_images
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
