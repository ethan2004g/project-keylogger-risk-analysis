"""
Project Keylogger — Team Key
Risk Analysis: data sensitivity and risk profile of unencrypted local input.
Maps keystroke context to three primary risk vectors for lab reporting.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ---------------------------------------------------------------------------
# Risk Vectors (Project Keylogger core model)
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RiskVector(str, Enum):
    """Three primary risk vectors for unencrypted input capture."""
    CREDENTIAL_HARVEST = "CredentialHarvest"
    INFORMATION_LEAKAGE = "InformationLeakage"
    PERSISTENCE_VULNERABILITY = "PersistenceVulnerability"


@dataclass
class RiskAssessment:
    level: RiskLevel
    vectors: list[RiskVector] = field(default_factory=list)
    summary: str = ""


# ---------------------------------------------------------------------------
# Credential Harvest Risk
# Highest risk: admin/financial passwords; can bypass MFA if session token
# is captured via the same hook (e.g. cookie/token typed or pasted).
# ---------------------------------------------------------------------------

_CREDENTIAL_WINDOW_PATTERNS = re.compile(
    r"\b(password|login|sign\s*in|signin|log\s*in|credentials?|auth|"
    r"bank(ing)?|paypal|venmo|stripe|checkout|payment|billing|"
    r"admin(istrator)?|root|sudo|mfa|2fa|otp|verification|"
    r"vpn|remote\s*desktop|rdp|ssh|azure|aws\s*console)\b",
    re.IGNORECASE,
)

def _credential_harvest_risk(window_title: str, key_str: str) -> tuple[RiskLevel, bool]:
    """Assess Credential Harvest risk from window context and key type."""
    if not window_title:
        return RiskLevel.LOW, False
    if _CREDENTIAL_WINDOW_PATTERNS.search(window_title):
        # Special keys often used in password flows (paste, visibility toggle)
        if any(x in key_str.upper() for x in ("<ENTER>", "<TAB>", "PASTE", "CONTROL")):
            return RiskLevel.HIGH, True
        return RiskLevel.HIGH, True
    return RiskLevel.LOW, False


# ---------------------------------------------------------------------------
# Information Leakage
# "Non-sensitive" typing still enables behavioral profiling, corporate
# intelligence, and highly targeted phishing (social engineering).
# ---------------------------------------------------------------------------

def _information_leakage_risk(key_str: str) -> tuple[RiskLevel, bool]:
    """Any captured keystroke contributes to information leakage risk."""
    # Printable characters = content that can be profiled
    if key_str and not key_str.startswith("<") and len(key_str) == 1:
        return RiskLevel.MEDIUM, True
    if key_str and key_str.startswith("<"):
        return RiskLevel.LOW, True  # Still behavioral signal (shortcuts, etc.)
    return RiskLevel.LOW, True


# ---------------------------------------------------------------------------
# Persistence Vulnerability
# Risk increases exponentially if the logger achieves boot-level persistence;
# we do NOT implement persistence (ethical guardrail). This vector is
# documented for educational context only.
# ---------------------------------------------------------------------------

def _persistence_vulnerability_note() -> str:
    """Persistence is disabled in this lab; report note only."""
    return "PersistenceDisabled"  # No boot persistence = lower real-world risk


# ---------------------------------------------------------------------------
# Combined assessment per keystroke
# ---------------------------------------------------------------------------

def assess_keystroke(key_str: str, window_title: str) -> RiskAssessment:
    """
    Analyze a single keystroke event against the three risk vectors.
    Returns level, primary vector(s), and a short summary for logging.
    """
    vectors: list[RiskVector] = []
    level = RiskLevel.LOW

    # 1. Credential Harvest
    cred_level, cred_applies = _credential_harvest_risk(window_title, key_str)
    if cred_applies:
        vectors.append(RiskVector.CREDENTIAL_HARVEST)
        if cred_level == RiskLevel.HIGH:
            level = RiskLevel.HIGH

    # 2. Information Leakage (always applies to some degree)
    info_level, _ = _information_leakage_risk(key_str)
    vectors.append(RiskVector.INFORMATION_LEAKAGE)
    if info_level == RiskLevel.MEDIUM and level != RiskLevel.HIGH:
        level = RiskLevel.MEDIUM

    # 3. Persistence: not implemented; annotate for reporting
    persistence_note = _persistence_vulnerability_note()
    # We don't add PERSISTENCE_VULNERABILITY to vectors when disabled;
    # we only mention it in summary when generating the report.

    if level == RiskLevel.HIGH:
        summary = f"CREDENTIAL_HARVEST|{persistence_note}"
    elif level == RiskLevel.MEDIUM:
        summary = f"INFORMATION_LEAKAGE|{persistence_note}"
    else:
        summary = f"INFORMATION_LEAKAGE|{persistence_note}"

    return RiskAssessment(level=level, vectors=vectors, summary=summary)


def format_risk_for_log(assessment: RiskAssessment) -> str:
    """Compact string for appending to a log line (e.g. [HIGH|CredentialHarvest])."""
    vec_str = "+".join(v.value for v in assessment.vectors[:2])  # Max 2 for brevity
    return f"[{assessment.level.value}|{vec_str}]"


# ---------------------------------------------------------------------------
# Session risk summary (for exit report)
# ---------------------------------------------------------------------------

class SessionRiskSummary:
    """Running summary of risk events for the current session."""
    def __init__(self):
        self.credential_harvest_events = 0
        self.information_leakage_events = 0
        self.max_level = RiskLevel.LOW
        self.windows_with_credential_context: set[str] = set()

    def record(self, assessment: RiskAssessment, window_title: str) -> None:
        if RiskVector.CREDENTIAL_HARVEST in assessment.vectors:
            self.credential_harvest_events += 1
            if window_title:
                self.windows_with_credential_context.add(window_title[:80])
        if RiskVector.INFORMATION_LEAKAGE in assessment.vectors:
            self.information_leakage_events += 1
        if assessment.level == RiskLevel.HIGH:
            self.max_level = RiskLevel.HIGH
        elif assessment.level == RiskLevel.MEDIUM and self.max_level != RiskLevel.HIGH:
            self.max_level = RiskLevel.MEDIUM

    def report_lines(self) -> list[str]:
        lines = [
            "--- Risk Analysis Summary ---",
            f"Max observed level: {self.max_level.value}",
            f"Credential Harvest risk events: {self.credential_harvest_events}",
            f"Information Leakage risk events: {self.information_leakage_events}",
            "Persistence: Disabled (no boot-level persistence; ethical guardrail).",
        ]
        if self.windows_with_credential_context:
            lines.append("Windows with credential-related context:")
            for w in sorted(self.windows_with_credential_context)[:20]:
                lines.append(f"  - {w}")
        lines.append("---")
        return lines
