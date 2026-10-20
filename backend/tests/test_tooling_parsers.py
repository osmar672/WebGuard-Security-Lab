import json

from app.tooling.runner import _parse_external, _result


def test_semgrep_json_stdout_is_normalized_when_no_report_file():
    stdout = json.dumps({"results": [{"check_id": "python.lang.security.audit.eval-detected",
        "path": "src/app.py", "start": {"line": 42, "col": 3},
        "extra": {"message": "Avoid dynamic evaluation", "severity": "ERROR"}}]})
    summary, findings = _parse_external("semgrep", stdout, None, None)
    assert summary["parsed_findings"] == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["rule_id"] == "python.lang.security.audit.eval-detected"
    assert findings[0]["evidence"]["line"] == 42


def test_testssl_json_list_is_normalized():
    report = [{"id": "TLS1_0", "severity": "HIGH", "finding": "TLS 1.0 enabled", "ip": "203.0.113.10"}]
    summary, findings = _parse_external("testssl", "", None, "https://example.com/")
    assert summary["parsed_findings"] == 0
    summary, findings = _parse_external("testssl", json.dumps(report), None, "https://example.com/")
    assert summary["parsed_findings"] == 1 and findings[0]["severity"] == "high"


def test_result_redacts_secret_match_fields_before_persistence():
    result = _result("gitleaks", {"status": "ok"}, [{"title": "Secret detected", "severity": "high",
        "evidence": {"rule_id": "generic-api-key", "match": "super-secret-value", "file": "settings.py"}}])
    assert result["findings"][0]["evidence"]["match"] == "[REDACTED]"
    assert "super-secret-value" not in json.dumps(result)


def test_sbom_report_output_is_not_exposed_in_generic_findings():
    from app.tooling.reports import build_pdf_report
    pdf = build_pdf_report({"report_type": "webguard_workspace_scan", "scan_id": "scan1", "state": "completed",
                            "findings": [{"title": "TLS (weak) certificate", "severity": "medium", "description": "Example\nvalue"}]})
    assert pdf.startswith(b"%PDF-1.4") and b"xref" in pdf and br"TLS \(weak\)" in pdf


def test_sbom_external_command_is_configured_for_cyclonedx(monkeypatch, tmp_path):
    from app.config import Settings
    from app.tooling.runner import _external_command
    import app.tooling.runner as runner

    workspace = tmp_path / "source"
    workspace.mkdir()
    settings = Settings(workspace_scan_root=str(workspace), trivy_path="trivy")
    monkeypatch.setattr(runner.shutil, "which", lambda _name: "/usr/local/bin/trivy")
    argv, report = _external_command("sbom", None, settings, "quick", tmp_path)
    assert argv[0] == "/usr/local/bin/trivy"
    assert "cyclonedx" in argv and "--output" in argv
    assert report is not None and report.name == "sbom.cdx.json"
    assert str(workspace.resolve()) == argv[-1]


def test_tool_subprocess_preserves_configured_playwright_browser_path(monkeypatch, tmp_path):
    import os
    import sys
    from app.tooling.runner import _run_command

    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/webguard-browsers")
    result = _run_command(
        [sys.executable, "-c", "import os; print(os.environ.get('PLAYWRIGHT_BROWSERS_PATH', 'missing'))"],
        timeout=5, cwd=tmp_path, cancel_check=None,
    )
    assert result["returncode"] == 0
    assert result["stdout"].strip() == "/opt/webguard-browsers"
