# Security Policy

## Supported Scope

This public repository is intended for defensive analysis, reporting, and documentation. It should not be used to publish secrets, raw captured data, or operational capture/exfiltration components.

## Reporting a Security Issue

If you discover a security problem in the public analysis code or documentation:

1. Do not open a public issue with sensitive details.
2. Share a private report with the repository owner.
3. Include reproduction steps, affected files, and any recommended mitigation.

## Sensitive Data Handling

- Never commit API keys, webhook URLs, or access tokens.
- Never publish raw keystroke logs or unsanitized lab output.
- Keep any sample files committed under `logs/` or `reports/` sanitized and safe for public review.
- Rotate any secret that may have been stored locally before making the repository public.
