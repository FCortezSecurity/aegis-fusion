from src.normalization.adapters import from_trivy_image

POLICY = {"thresholds": {"fail_on": ["CRITICAL", "HIGH"]}}


def vuln(**overrides):
    base = {
        "image": "python:3.8-slim",
        "id": "CVE-2026-0001",
        "package": "openssl",
        "installed": "3.0.14",
        "fixed": "3.0.19",
        "severity": "CRITICAL",
        "title": "Heap overflow",
    }
    base.update(overrides)
    return base


def test_image_adapter_keeps_trivy_severity():
    f = from_trivy_image([vuln()], POLICY)[0]
    assert f.severity == "CRITICAL"
    assert f.tool == "trivy"
    assert f.file == "python:3.8-slim"
    assert "Upgrade openssl to 3.0.19" in f.fix


def test_image_adapter_handles_missing_fix():
    f = from_trivy_image([vuln(fixed="")], POLICY)[0]
    assert "No fix available" in f.fix


def test_image_adapter_empty_list():
    assert from_trivy_image([], POLICY) == []