import os
import sys

from src.normalization.finding import SEVERITIES, Finding

# Gitleaks reports no severity of its own, so we choose a default here.
# A later step moves this into configs/policies.yaml.
SECRET_SEVERITY = "HIGH"

# Different tools use different words for the same idea.
SEVERITY_ALIASES = {
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "UNKNOWN": "MEDIUM",
    "ERROR": "HIGH",
    "NEGLIGIBLE": "INFO",
}


def normalize_severity(raw: str) -> str:
    """Translate any tool's severity word into our scale.

    Unknown values are treated as HIGH (fail safe): if we are ever wrong,
    we want to block a build, not wave a vulnerability through.
    """
    value = (raw or "").strip().upper()
    if value in SEVERITIES:
        return value
    if value in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[value]
    print(
        f"warning: unknown severity {raw!r}, treating as HIGH",
        file=sys.stderr,
    )
    return "HIGH"


def _rel(path: str) -> str:
    """Show paths relative to where the scan was run."""
    return os.path.relpath(path)


def from_bandit(raw: dict) -> list[Finding]:
    """Convert Bandit's JSON output into Finding objects."""
    return [
        Finding(
            tool="bandit",
            rule_id=r["test_id"],
            severity=normalize_severity(r["issue_severity"]),
            title=r["issue_text"],
            file=_rel(r["filename"]),
            line=r["line_number"],
            fix=r.get("more_info", ""),
        )
        for r in raw.get("results", [])
    ]


def from_gitleaks(raw: list) -> list[Finding]:
    """Convert Gitleaks' JSON findings into Finding objects."""
    return [
        Finding(
            tool="gitleaks",
            rule_id=leak["RuleID"],
            severity=SECRET_SEVERITY,
            title=leak["Description"],
            file=_rel(leak["File"]),
            line=leak["StartLine"],
            fix=(
                "Remove the secret from source, rotate it, and load it "
                "from a secrets manager or environment variable."
            ),
        )
        for leak in raw
    ]