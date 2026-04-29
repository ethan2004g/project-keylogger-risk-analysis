# Project Keylogger

**Team:** Key

Project Keylogger is a defensive research repository that explains how keyboard-input exposure can be studied through risk analysis, sanitized logs, and reporting workflows. The GitHub version is intentionally centered on **explanation, analysis, and documentation** rather than on distributing operational capture or exfiltration code.

## What This Repository Includes

This repository is meant to explain three parts of the project:

- how input events can be evaluated for security risk
- how sanitized session logs can be reconstructed into readable context
- how AI-assisted summaries and charts can help communicate findings

The repository also includes a sanitized sample log and example report images so the public analysis workflow can be reviewed without recreating local capture steps.

## How The Project Is Structured

- `risk_analysis.py` contains the rule-based risk model and session summary logic.
- `ai_analysis.py` parses a sanitized event log, reconstructs text by window, and produces AI-assisted summaries plus charts.
- `config.py` contains local configuration defaults with secrets sourced from environment variables only.
- `logs/sanitized_session_log.txt` is a committed, sanitized example input for the public workflow.
- `reports/` contains committed example PNG outputs generated from sanitized data.
- `requirements.txt` installs the analysis and reporting dependencies needed for the public repo.

## How The Analysis Works

The public workflow is built around sanitized event data rather than live collection. A session log is parsed into structured events, grouped by application window, and then evaluated in two layers:

1. a rule-based model that flags likely credential or information-leakage contexts
2. an optional AI analysis step that summarizes likely sensitivity in reconstructed text

The result is a set of charts and written findings that explain which parts of a session appear most sensitive and why.

## Risk Model

The analysis code classifies events across three teaching-focused vectors:

| Vector | Purpose |
|--------|---------|
| `CredentialHarvest` | Highlights windows and input contexts that resemble authentication or payment flows. |
| `InformationLeakage` | Measures how even routine typing can leak behavioral or sensitive context. |
| `PersistenceVulnerability` | Documents the impact persistence would have, while keeping persistence disabled in this project. |

The public repository emphasizes this analytical layer because it is the part most useful for explanation, reporting, and classroom discussion.

## Safe Setup

Use the GitHub version of this project for **analysis and reporting only**.

```bash
cd "Project-ShadowScript"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Optional environment variables:

- `OPENAI_API_KEY` for AI-assisted analysis

## Analysis Workflow

1. Review the committed sample log in `logs/sanitized_session_log.txt`, or prepare your own **sanitized** log from an authorized lab session.
2. Install the dependencies from `requirements.txt`.
3. Set `OPENAI_API_KEY` for AI-assisted scoring. The script exits early if no API key is configured.
4. Run the analysis locally:

```bash
python ai_analysis.py path\to\sanitized_log.txt
```

If no path is provided, the script uses `config.LOG_PATH`, which points to the committed sample log.

Generated output is written to `reports/` with timestamped filenames such as `risk_overview_YYYYMMDD_HHMMSS.png`, `ai_sensitivity_YYYYMMDD_HHMMSS.png`, and `ai_summaries_YYYYMMDD_HHMMSS.png`.

The repository already tracks a small set of example charts in `reports/` for documentation purposes. New timestamped outputs are typically left untracked, but any changes to the committed example artifacts should be reviewed carefully before they are committed.

## What Is Kept Out Of GitHub

The default `.gitignore` is configured to keep the following local-only items out of a new GitHub repository:

- local virtual environments and cache directories
- additional raw logs and generated reports
- environment files and local-only secrets
- local runtime entrypoints such as `run.py`
- local-only capture components such as `keylogger.py`

If you plan to publish this repository, keep the public focus on explanation, analysis, and documentation. Do not upload raw captured data, live credentials, API keys, or operational capture/exfiltration code.

## Project Identity

- **Project Name:** Project Keylogger
- **Team Name:** Team Key

## Disclaimer

This repository should only be used for authorized security education, defensive analysis, and controlled-lab reporting. Any collected data should be sanitized before publication, and any secrets previously stored in local files should be rotated before the repository is made public.
