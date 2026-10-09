import json

from src.normalization.finding import Finding
from src.policy.engine import evaluate
from src.reporting.report import (
    build_report,
    group_findings,
    render_markdown,
    write_json,
)

POLICY = {"thresholds": {"fail_on": ["CRITICAL", "HIGH"], "warn_on": ["MEDIUM"]}}


def dep(rule, pkg="django==2.2.0", severity="HIGH"):
    return Finding(
        "pip-audit", rule, severity, f"{pkg} has a known vulnerability", pkg, 0, "Upgrade"
    )


def code(severity="HIGH", rule="B602"):
    return Finding("bandit", rule, severity, "shell=True", "app.py", 11, "Use shell=False")


def test_group_collapses_dependency_findings_by_package():
    findings = [dep("A"), dep("B"), dep("C"), dep("D", pkg="flask==0.12.2"), code()]
    entries = group_findings(findings)
    assert len(entries) == 3
    django = next(e for e in entries if e["file"] == "django==2.2.0")
    assert django["count"] == 3
    assert django["rule_ids"] == ["A", "B", "C"]
    assert django["title"] == "django==2.2.0: 3 known vulnerabilities"


def test_group_keeps_worst_severity():
    entries = group_findings([dep("A", severity="LOW"), dep("B", severity="CRITICAL")])
    assert entries[0]["severity"] == "CRITICAL"


def test_group_sorts_most_severe_first():
    entries = group_findings([code("LOW", "B1"), code("CRITICAL", "B2")])
    assert entries[0]["severity"] == "CRITICAL"


def test_build_report_fields():
    findings = [code("HIGH"), code("MEDIUM", "B3")]
    report = build_report("samples", findings, evaluate(findings, POLICY))
    assert report["schema_version"] == 1
    assert report["target"] == "samples"
    assert report["result"] == "FAIL"
    assert report["counts"]["HIGH"] == 1
    assert len(report["findings"]) == 2


def test_write_json_creates_folders_and_round_trips(tmp_path):
    report = build_report("samples", [], evaluate([], POLICY))
    path = tmp_path / "out" / "report.json"
    write_json(path, report)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["result"] == "PASS"
    assert loaded["findings"] == []


def test_markdown_groups_dependencies_and_has_table():
    findings = [dep("A"), dep("B"), code()]
    md = render_markdown(
        "samples", findings, evaluate(findings, POLICY), generated_at="2026-01-01"
    )
    assert "# Aegis Fusion security report" in md
    assert "**Result:** FAIL" in md
    assert "django==2.2.0: 2 known vulnerabilities" in md
    assert "| Severity | Tool | Rule | Location | Description | Remediation |" in md


def test_markdown_escapes_pipes_in_table_cells():
    f = Finding("bandit", "B1", "HIGH", "a | b", "app.py", 1, "x")
    md = render_markdown("t", [f], evaluate([f], POLICY), generated_at="x")
    assert "a \\| b" in md


def test_markdown_pass_report_says_none():
    md = render_markdown("t", [], evaluate([], POLICY), generated_at="x")
    assert "**Result:** PASS" in md
    assert "None." in md