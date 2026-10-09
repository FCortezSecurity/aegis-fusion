from dataclasses import dataclass

from src.normalization.finding import SEVERITIES, Finding

DEFAULT_FAIL_ON = ["CRITICAL", "HIGH"]


@dataclass(frozen=True)
class Verdict:
    """The result of checking findings against the policy."""

    passed: bool
    counts: dict      # severity -> number of findings
    blocking: list    # findings at a fail_on level
    warnings: list    # findings at a warn_on level


def _levels(policy: dict, key: str, default: list) -> set:
    levels = policy.get("thresholds", {}).get(key, default)
    unknown = set(levels) - set(SEVERITIES)
    if unknown:
        # A typo in the policy must never silently disable a gate.
        raise ValueError(f"Unknown severity in thresholds.{key}: {sorted(unknown)}")
    return set(levels)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by tool and file for stable output."""
    return sorted(
        findings,
        key=lambda f: (SEVERITIES.index(f.severity), f.tool, f.file, f.line),
    )


def evaluate(findings: list[Finding], policy: dict) -> Verdict:
    """Decide pass or fail. The build fails if any finding is at a fail_on level."""
    fail_on = _levels(policy, "fail_on", DEFAULT_FAIL_ON)
    warn_on = _levels(policy, "warn_on", [])

    counts = {severity: 0 for severity in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1

    blocking = sort_findings([f for f in findings if f.severity in fail_on])
    warnings = sort_findings([f for f in findings if f.severity in warn_on])

    return Verdict(
        passed=not blocking,
        counts=counts,
        blocking=blocking,
        warnings=warnings,
    )