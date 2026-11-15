## What and why
<!-- One or two sentences: what changes, and the reason. -->

## Evidence
- [ ] Automated checks pass (build, tests, lint, security scan)
- [ ] For infrastructure changes: the `terraform plan` output was read and matches the intent
- [ ] I can destroy and recreate what this change touches from code

## Rollback
<!-- How this change is reversed if it goes wrong (previous image tag, revert commit, destroy). -->

## Safety
- [ ] No secrets, tokens or real AWS account identifiers in the diff
- [ ] No manual change was made in the console that this PR depends on

## AI assistance
<!-- If an AI tool wrote or reviewed any part of this change, say which part. AI changes follow the same path as any other. -->
