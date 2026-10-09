from src.normalization.adapters import (
    from_checkov,
    from_pip_audit,
    from_trivy_config,
)
from src.policy.config import load_policy, severity_for

POLICY = {
    "thresholds": {"fail_on": ["CRITICAL", "HIGH"], "warn_on": ["MEDIUM"]},
    "severity_map": {
        "checkov": {"default": "MEDIUM", "rules": {"CKV_AWS_24": "HIGH"}},
        "pip-audit": {"default": "HIGH"},
    },
}


def test_severity_for_rule_override():
    assert severity_for(POLICY, "checkov", "CKV_AWS_24") == "HIGH"


def test_severity_for_tool_default():
    assert severity_for(POLICY, "checkov", "CKV_OTHER") == "MEDIUM"


def test_severity_for_uses_fallback_when_tool_unmapped():
    assert severity_for(POLICY, "trivy", "DS-1", fallback="LOW") == "LOW"


def test_severity_for_unknown_tool_fails_safe():
    assert severity_for(POLICY, "mystery", "X") == "HIGH"


def test_real_policy_file_loads():
    policy = load_policy()
    assert "CRITICAL" in policy["thresholds"]["fail_on"]


def test_pip_audit_adapter_dedupes_and_skips_clean_packages():
    raw = {
        "dependencies": [
            {
                "name": "flask",
                "version": "0.12.2",
                "vulns": [
                    {"id": "PYSEC-1", "fix_versions": ["1.0"]},
                    {"id": "PYSEC-1", "fix_versions": ["1.0"]},
                ],
            },
            {"name": "clean", "version": "1.0", "vulns": []},
        ]
    }
    findings = from_pip_audit(raw, POLICY)
    assert len(findings) == 1
    assert findings[0].file == "flask==0.12.2"
    assert findings[0].severity == "HIGH"


def test_checkov_adapter_uses_policy_severity():
    raw = {
        "failed": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "SSH open to the world",
                "resource": "aws_security_group.open",
                "file_path": "main.tf",
                "file_line_range": [7, 17],
                "guideline": "https://example.com/guide",
            }
        ]
    }
    f = from_checkov(raw, POLICY)[0]
    assert f.severity == "HIGH"
    assert f.line == 7
    assert f.tool == "checkov"


def test_trivy_config_adapter_keeps_tools_own_severity():
    raw = [
        {
            "id": "DS-0002",
            "severity": "HIGH",
            "title": "Image user should not be root",
            "file": "Dockerfile",
            "line": 3,
            "resolution": "Add a non-root USER",
        }
    ]
    f = from_trivy_config(raw, POLICY)[0]
    assert f.severity == "HIGH"
    assert f.tool == "trivy"