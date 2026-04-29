# Contributing

Thanks for contributing to `Project Keylogger`.

This public repository is limited to defensive documentation, analysis code, sanitized sample artifacts, and reporting improvements. Contributions should keep that scope intact.

## Good Contributions

- documentation improvements
- clearer setup instructions
- tests for analysis and parsing logic
- charting, reporting, and explanation refinements
- sanitized sample data and reproducible examples

## Out of Scope

Please do not submit pull requests that add:

- active capture workflows
- persistence or stealth enhancements
- exfiltration features
- raw sensitive logs
- credentials, tokens, or webhook URLs

## Development Notes

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Keep generated logs, reports, and local-only runtime files untracked.
4. Prefer environment variables for secrets and API keys.

## Pull Request Checklist

- documentation matches the current behavior
- no secrets are present in code or examples
- no raw captured data is included
- changes stay within the public analysis-and-reporting scope
