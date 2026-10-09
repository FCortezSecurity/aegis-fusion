import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from src.normalization.finding import SEVERITIES, Finding
from src.policy.engine import Verdict, sort_findings

SCHEMA_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _entry(items: list[Finding], title: str | None = None) -> dict:
    """Build one report row from one finding, or from a group of findings."""
    worst = min(items, key=lambda f: SEVERITIES.index(f.severity))
    single = len(items) == 1
    return {
        "tool": worst.tool,
        "severity": worst.severity,
        "title": title or worst.title,
        "file": worst.file,
        "line": worst.line,
        "count": len(items),
        "rule_ids": sorted({f.rule_id for f in items}),
        "fix": worst.fix
        if single
        else "Upgrade the package to a release that fixes these advisories.",
    }


def group_findings(findings: list[Finding]) -> list[dict]:
    """Collapse pip-audit findings into one row per package.

    Every other finding stays as its own row. Rows are sorted most severe first.
    """
    entries = []
    packages = defaultdict(list)
    for f in findings:
        if f.tool == "pip-audit":
            packages[f.file].append(f)
        else:
            entries.append(_entry([f]))
    for package, items in packages.items():
        entries.append(
            _entry(items, title=f"{package}: {len(items)} known vulnerabilities")
        )
    return sorted(
        entries,
        key=lambda e: (SEVERITIES.index(e["severity"]), e["tool"], e["file"], e["line"]),
    )


def build_report(target: str, findings: list[Finding], verdict: Verdict) -> dict:
    """The machine-readable report: every finding, plus the verdict."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now(),
        "target": target,
        "result": "PASS" if verdict.passed else "FAIL",
        "counts": verdict.counts,
        "blocking_count": len(verdict.blocking),
        "warning_count": len(verdict.warnings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }


def write_json(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def _cell(text) -> str:
    """Make text safe inside a Markdown table cell."""
    return " ".join(str(text).split()).replace("|", "\\|")


def _location(entry: dict) -> str:
    if entry["line"]:
        return f"{entry['file']}:{entry['line']}"
    return entry["file"]


def _table(entries: list[dict]) -> list[str]:
    lines = [
        "| Severity | Tool | Rule | Location | Description | Remediation |",
        "|---|---|---|---|---|---|",
    ]
    for e in entries:
        rule = e["rule_ids"][0] if e["count"] == 1 else f"{e['count']} advisories"
        lines.append(
            "| "
            + " | ".join(
                [
                    e["severity"],
                    e["tool"],
                    _cell(rule),
                    f"`{_cell(_location(e))}`",
                    _cell(e["title"]),
                    _cell(e["fix"]),
                ]
            )
            + " |"
        )
    return lines


def render_markdown(
    target: str,
    findings: list[Finding],
    verdict: Verdict,
    generated_at: str | None = None,
) -> str:
    """The human-readable report."""
    generated_at = generated_at or _now()
    by_tool = Counter(f.tool for f in findings)

    lines = [
        "# Aegis Fusion security report",
        "",
        f"- **Target:** `{target}`",
        f"- **Result:** {'PASS' if verdict.passed else 'FAIL'}",
        f"- **Generated:** {generated_at}",
        "",
        "## Summary",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    lines += [f"| {s} | {verdict.counts[s]} |" for s in SEVERITIES]

    lines += ["", "## Findings by tool", "", "| Tool | Findings |", "|---|---|"]
    lines += [f"| {tool} | {n} |" for tool, n in sorted(by_tool.items())]

    blocking = group_findings(verdict.blocking)
    lines += [
        "",
        f"## Blocking findings ({len(verdict.blocking)})",
        "",
        "_Dependency vulnerabilities are grouped by package._",
        "",
    ]
    lines += _table(blocking) if blocking else ["None."]

    warnings = group_findings(verdict.warnings)
    lines += ["", f"## Warnings ({len(verdict.warnings)})", ""]
    lines += _table(warnings) if warnings else ["None."]

    return "\n".join(lines) + "\n"