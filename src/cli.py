import argparse
import sys
from collections import Counter
from pathlib import Path

import yaml

from src.normalization.adapters import (
    from_bandit,
    from_checkov,
    from_gitleaks,
    from_pip_audit,
    from_trivy_config,
    from_trivy_image,
)
from src.normalization.finding import SEVERITIES, Finding
from src.policy.config import DEFAULT_POLICY_PATH, load_policy
from src.policy.engine import Verdict, evaluate
from src.scanners.bandit_scanner import run_bandit
from src.scanners.checkov_scanner import run_checkov
from src.scanners.gitleaks_scanner import run_gitleaks
from src.scanners.pip_audit_scanner import run_pip_audit
from src.scanners.trivy_scanner import run_trivy_config, run_trivy_image

EXIT_PASS = 0   # policy satisfied
EXIT_FAIL = 1   # policy violated: findings at a fail_on level
EXIT_ERROR = 2  # the scan itself broke (Docker down, bad policy file, ...)

TOOLS = ["bandit", "pip-audit", "gitleaks", "checkov", "trivy"]
DEFAULT_SHOWN = 15


def collect_findings(target: Path, image: str | None, policy: dict) -> list[Finding]:
    """Run every scanner and return all findings in the common format."""
    findings: list[Finding] = []
    findings += from_bandit(run_bandit(target))
    findings += from_pip_audit(run_pip_audit(target), policy)
    findings += from_gitleaks(run_gitleaks(target), policy)
    findings += from_checkov(run_checkov(target), policy)
    findings += from_trivy_config(run_trivy_config(target), policy)
    if image:
        findings += from_trivy_image(run_trivy_image(image), policy)
    return findings


def _clip(text: str, width: int = 90) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


def print_report(
    target: Path, findings: list[Finding], verdict: Verdict, show_all: bool
) -> None:
    print(f"Aegis Fusion scan of {target}\n")

    by_tool = Counter(f.tool for f in findings)
    print("Findings by tool")
    for tool in TOOLS:
        print(f"  {tool:<10} {by_tool.get(tool, 0)}")

    print("\nFindings by severity")
    for severity in SEVERITIES:
        print(f"  {severity:<9} {verdict.counts[severity]}")

    shown = verdict.blocking if show_all else verdict.blocking[:DEFAULT_SHOWN]
    print(f"\nBlocking findings ({len(verdict.blocking)})")
    for f in shown:
        location = f"{f.file}:{f.line}" if f.line else f.file
        print(f"  [{f.severity}] {f.tool} {f.rule_id} {location} - {_clip(f.title)}")
    hidden = len(verdict.blocking) - len(shown)
    if hidden:
        print(f"  ...and {hidden} more (run with --all to list everything)")

    print(f"\nWarnings: {len(verdict.warnings)}")
    if verdict.passed:
        print("\nRESULT: PASS")
    else:
        print(f"\nRESULT: FAIL ({len(verdict.blocking)} blocking finding(s))")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis", description="Aegis Fusion: security scanning automation"
    )
    parser.add_argument("target", type=Path, help="Folder to scan")
    parser.add_argument(
        "--image", help="Also scan this container image, e.g. python:3.8-slim"
    )
    parser.add_argument(
        "--policy", type=Path, default=DEFAULT_POLICY_PATH, help="Policy YAML file"
    )
    parser.add_argument(
        "--all", action="store_true", help="List every blocking finding"
    )
    args = parser.parse_args(argv)

    if not args.target.exists():
        parser.error(f"Target not found: {args.target}")

    try:
        policy = load_policy(args.policy)
        findings = collect_findings(args.target, args.image, policy)
        verdict = evaluate(findings, policy)
    except (RuntimeError, ValueError, OSError, yaml.YAMLError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print_report(args.target, findings, verdict, args.all)
    return EXIT_PASS if verdict.passed else EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())