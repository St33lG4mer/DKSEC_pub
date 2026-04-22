# Security Policy

## Supported Versions

This project is currently maintained on the main branch.

## Reporting a Vulnerability

If you discover a security issue, do not open a public issue with exploit details.

Please report privately to the project maintainer and include:
- A clear description of the issue
- Steps to reproduce
- Impact assessment
- Suggested mitigation (if available)

Expected response process:
- Initial acknowledgement within 72 hours
- Triage and severity assessment
- Fix development and validation
- Coordinated disclosure after a fix is available

## Secrets and Credentials Handling

Never commit real credentials to the repository.

Use these rules:
- Keep local credentials only in untracked files such as .env.
- Use placeholder values in examples and documentation.
- Rotate credentials immediately if exposure is suspected.
- Remove leaked secrets from Git history and force-push rewritten history when needed.

Current controls in this repository:
- Pre-commit Gitleaks hook via .pre-commit-config.yaml
- Repository scan config in .gitleaks.toml
- CI secret scanning in .github/workflows/secret-scan.yml

## Local Security Checks

Recommended before pushing:

```powershell
pre-commit run --all-files
```

Optional full history check:

```powershell
gitleaks detect --source . --redact --log-opts="--all" --config=.gitleaks.toml
```

## Incident Response Checklist

If a secret is leaked:
1. Revoke or rotate exposed credentials immediately.
2. Remove secret-containing files from current tree.
3. Rewrite Git history to purge leaked content.
4. Force-push rewritten branches and tags.
5. Ask collaborators to re-clone or hard reset.
6. Re-run secret scans and verify zero findings.
