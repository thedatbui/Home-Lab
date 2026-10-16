# 08 — CI/CD Security Pipeline

## Objective

Run security checks before deployment so that vulnerabilities and secrets are detected during development, not only after exploitation.

## Commands

Run the same checks locally when validating a change:

```bash
bandit -r . -x instance
semgrep --config auto .
pip-audit
gitleaks detect --source .
```