import pytest

from src.normalization.finding import Finding
from src.policy.engine import evaluate, sort_findings

POLICY = {"thresholds": {"fail_on": ["CRITICAL", "HIGH"], "warn_on": ["MEDIUM"]}}


def make(severity: str, tool: str = "bandit", rule: str = "X1") -> Finding:
    return Finding(tool, rule, severity, "title", "app.py", 1)


def test_no_findings_passes():
    verdict = evaluate([], POLICY)
    assert verdict.passed
    assert verdict.counts["CRITICAL"] == 0


def test_medium_only_passes_with_warning():
    verdict = evaluate([make("MEDIUM")], POLICY)
    assert verdict.passed
    assert len(verdict.warnings) == 1
    assert verdict.blocking == []


def test_high_finding_fails():
    verdict = evaluate([make("HIGH"), make("LOW")], POLICY)
    assert not verdict.passed
    assert len(verdict.blocking) == 1


def test_critical_fails():
    assert not evaluate([make("CRITICAL")], POLICY).passed


def test_counts_every_severity():
    findings = [make("HIGH"), make("HIGH"), make("LOW"), make("INFO")]
    counts = evaluate(findings, POLICY).counts
    assert counts["HIGH"] == 2
    assert counts["LOW"] == 1
    assert counts["INFO"] == 1
    assert counts["CRITICAL"] == 0


def test_typo_in_policy_raises_instead_of_disabling_gate():
    bad = {"thresholds": {"fail_on": ["CRITCAL"]}}
    with pytest.raises(ValueError):
        evaluate([make("CRITICAL")], bad)


def test_missing_fail_on_uses_safe_default():
    verdict = evaluate([make("HIGH")], {"thresholds": {}})
    assert not verdict.passed


def test_sort_puts_most_severe_first():
    ordered = sort_findings([make("LOW"), make("CRITICAL"), make("MEDIUM")])
    assert [f.severity for f in ordered] == ["CRITICAL", "MEDIUM", "LOW"]