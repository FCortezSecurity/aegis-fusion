import os
import sys

from src.normalization.finding import SEVERITIES, Finding
from src.policy.config import severity_for

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


def from_gitleaks(raw: list, policy: dict | None = None) -> list[Finding]:
    """Convert Gitleaks' JSON findings into Finding objects."""
    policy = policy or {}
    return [
        Finding(
            tool="gitleaks",
            rule_id=leak["RuleID"],
            severity=normalize_severity(
                severity_for(policy, "gitleaks", leak["RuleID"])
            ),
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


def from_pip_audit(raw: dict, policy: dict) -> list[Finding]:
    """Convert pip-audit output into Finding objects (one per unique vuln)."""
    findings = []
    for dep in raw.get("dependencies", []):
        seen = set()
        for v in dep.get("vulns", []):
            if v["id"] in seen:
                continue
            seen.add(v["id"])
            fixes = v.get("fix_versions") or []
            findings.append(
                Finding(
                    tool="pip-audit",
                    rule_id=v["id"],
                    severity=normalize_severity(
                        severity_for(policy, "pip-audit", v["id"])
                    ),
                    title=f"{dep['name']} {dep['version']} has a known vulnerability",
                    file=f"{dep['name']}=={dep['version']}",
                    fix=(
                        "Upgrade to one of: " + ", ".join(fixes)
                        if fixes
                        else "No fixed version listed"
                    ),
                )
            )
    return findings


def from_checkov(raw: dict, policy: dict) -> list[Finding]:
    """Convert Checkov's failed checks into Finding objects."""
    return [
        Finding(
            tool="checkov",
            rule_id=c["check_id"],
            severity=normalize_severity(
                severity_for(policy, "checkov", c["check_id"])
            ),
            title=f"{c['check_name']} ({c['resource']})",
            file=_rel(c["file_path"]),
            line=c["file_line_range"][0],
            fix=c.get("guideline") or "",
        )
        for c in raw.get("failed", [])
    ]


def from_trivy_config(raw: list, policy: dict) -> list[Finding]:
    """Convert Trivy's Dockerfile findings into Finding objects.

    Trivy reports its own severity; a policy rule can still override it.
    """
    return [
        Finding(
            tool="trivy",
            rule_id=f["id"],
            severity=normalize_severity(
                severity_for(policy, "trivy", f["id"], fallback=f["severity"])
            ),
            title=f["title"],
            file=_rel(f["file"]),
            line=f["line"],
            fix=f.get("resolution", ""),
        )
        for f in raw
    ]