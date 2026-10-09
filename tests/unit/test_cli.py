import json

from src import cli
from src.normalization.finding import Finding


def finding(severity):
    return Finding("bandit", "B1", severity, "title", "app.py", 1, "fix")


def fake_scan(monkeypatch, findings):
    monkeypatch.setattr(cli, "collect_findings", lambda target, image, policy: findings)


def test_fail_exit_code_and_reports_written(monkeypatch, tmp_path):
    fake_scan(monkeypatch, [finding("HIGH")])
    out_json = tmp_path / "out" / "r.json"
    out_md = tmp_path / "out" / "r.md"
    code = cli.main(
        [str(tmp_path), "--json", str(out_json), "--markdown", str(out_md)]
    )
    assert code == cli.EXIT_FAIL
    assert json.loads(out_json.read_text(encoding="utf-8"))["result"] == "FAIL"
    assert "**Result:** FAIL" in out_md.read_text(encoding="utf-8")


def test_pass_exit_code(monkeypatch, tmp_path):
    fake_scan(monkeypatch, [finding("LOW")])
    assert cli.main([str(tmp_path)]) == cli.EXIT_PASS


def test_scan_error_exit_code_and_no_report(monkeypatch, tmp_path, capsys):
    def boom(target, image, policy):
        raise RuntimeError("Docker not found")

    monkeypatch.setattr(cli, "collect_findings", boom)
    out_json = tmp_path / "r.json"
    code = cli.main([str(tmp_path), "--json", str(out_json)])
    assert code == cli.EXIT_ERROR
    assert not out_json.exists()
    assert "Docker not found" in capsys.readouterr().err