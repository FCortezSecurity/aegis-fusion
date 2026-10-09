from src.normalization.adapters import (
    from_bandit,
    from_gitleaks,
    normalize_severity,
)


def test_bandit_adapter_maps_fields():
    raw = {
        "results": [
            {
                "test_id": "B602",
                "issue_severity": "HIGH",
                "issue_text": "subprocess call with shell=True",
                "filename": "app.py",
                "line_number": 11,
                "more_info": "https://bandit.readthedocs.io/",
            }
        ]
    }
    findings = from_bandit(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "bandit"
    assert f.rule_id == "B602"
    assert f.severity == "HIGH"
    assert f.line == 11


def test_bandit_adapter_handles_no_results():
    assert from_bandit({"results": []}) == []


def test_gitleaks_adapter_defaults_to_high():
    raw = [
        {
            "RuleID": "generic-api-key",
            "Description": "Detected a Generic API Key",
            "File": "config.py",
            "StartLine": 2,
        }
    ]
    findings = from_gitleaks(raw)
    assert findings[0].tool == "gitleaks"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 2


def test_normalize_severity_known_values():
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity(" Medium ") == "MEDIUM"


def test_normalize_severity_aliases():
    assert normalize_severity("MODERATE") == "MEDIUM"
    assert normalize_severity("error") == "HIGH"


def test_normalize_severity_unknown_fails_safe(capsys):
    assert normalize_severity("SPICY") == "HIGH"
    assert "unknown severity" in capsys.readouterr().err


def test_normalize_severity_empty_fails_safe():
    assert normalize_severity("") == "HIGH"