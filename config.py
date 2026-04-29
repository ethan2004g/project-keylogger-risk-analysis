"""
Project Keylogger — Team Key
Public configuration for the GitHub-safe analysis and reporting workflow.
"""

import os

# ----- Project Identity -----
TEAM_NAME = "Key"
PROJECT_NAME = "Project Keylogger"

# ----- Sanitized Input Source -----
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILENAME = "sanitized_session_log.txt"
LOG_PATH = os.path.join(LOG_DIR, LOG_FILENAME)

# ----- Risk Analysis (rule-based, per keystroke) -----
ENABLE_RISK_ANALYSIS = True
WRITE_RISK_SUMMARY_ON_EXIT = True

# ----- AI Risk Analysis (OpenAI + statistical graphs) -----
ENABLE_AI_ANALYSIS = False
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o-mini"
GRAPH_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
