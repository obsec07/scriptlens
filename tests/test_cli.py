import json
import os
import subprocess
import sys

import pytest

from scriptlens.cli import main


@pytest.mark.parametrize("command", [[], ["scan"], ["analyze"]])
def test_help_plain_under_forced_color(command):
    result = subprocess.run(
        [sys.executable, "-m", "scriptlens", *command, "--help"],
        env=dict(os.environ, FORCE_COLOR="1", PYTHON_COLORS="1"),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "usage:" in result.stdout
    assert "\x1b" not in result.stdout + result.stderr


def test_local_analysis_saves_json_automatically_and_masks_credentials(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    code = tmp_path / "app.js"
    code.write_text(
        "fetch('/save',{method:'POST',body:JSON.stringify({name, password:'temporary-password-value'})})"
    )
    assert (
        main(
            [
                "analyze",
                str(code),
                "--base-url",
                "https://example.test",
                "--raw",
                "--color",
                "always",
                "--show-curl",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    reports = list((tmp_path / "scriptlens-results").glob("*.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text())
    assert report["endpoints"][0]["method"] == "POST"
    assert "temporary-password-value" not in reports[0].read_text() + output
    assert "\x1b" not in output
    assert "Saved:" not in output
    assert reports[0].stat().st_mode & 0o777 == 0o600
    assert report["sources"][0]["sha256"]


def test_existing_output_file_is_never_overwritten(tmp_path, capsys):
    source = tmp_path / "app.js"
    source.write_text("fetch('/api')")
    output = tmp_path / "report.json"
    output.write_text("keep me")
    assert main(["analyze", str(source), "-o", str(output)]) == 2
    assert output.read_text() == "keep me"


def test_incomplete_source_saves_failure_in_json(tmp_path, capsys):
    source = tmp_path / "app.js"
    source.write_text("function broken( {")
    output = tmp_path / "report.json"
    assert main(["analyze", str(source), "-o", str(output)]) == 3
    assert json.loads(output.read_text())["complete"] is False
    assert "[SKIP]" not in capsys.readouterr().out


def test_only_result_label_is_colored_and_json_remains_plain(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("NO_COLOR", raising=False)
    source = tmp_path / "app.js"
    source.write_text("fetch('/api',{method:'POST'})")
    output = tmp_path / "report.json"
    assert main(["analyze", str(source), "-o", str(output), "--color", "always"]) == 0
    console = capsys.readouterr().out
    assert "\x1b[36m[POST]\x1b[0m" in console
    assert "\x1b" not in output.read_text()
    assert "\x1b" not in next(line for line in console.splitlines() if line.startswith("Saved:"))


def test_no_color_overrides_forced_result_color(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NO_COLOR", "1")
    source = tmp_path / "app.js"
    source.write_text("fetch('/api',{method:'POST'})")
    assert main(["analyze", str(source), "-o", str(tmp_path / "r.json"), "--color", "always"]) == 0
    assert "\x1b" not in capsys.readouterr().out


@pytest.mark.parametrize("raw", [False, True])
def test_limit_reason_visible_by_default_but_raw_stays_quiet(tmp_path, capsys, raw):
    source = tmp_path / "bundle.js"
    source.write_text("fetch('/api')" * 20)
    output = tmp_path / "report.json"
    command = ["analyze", str(source), "--max-bytes", "20", "-o", str(output)]
    assert main(command + (["--raw"] if raw else [])) == 3
    console = capsys.readouterr().out
    report = json.loads(output.read_text())
    assert report["diagnostics"][0]["code"] == "file_byte_limit"
    assert report["settings"]["max_bytes"] == 20
    if raw:
        assert console == ""
    else:
        assert "local file byte limit reached (20 bytes)" in console
        assert "Increase --max-bytes" in console
        assert "\x1b" not in console


def test_parser_limit_can_be_raised_and_failed_parse_not_counted_as_analyzed(tmp_path, capsys):
    source = tmp_path / "app.js"
    source.write_text("fetch('/api')")
    small, large = tmp_path / "small.json", tmp_path / "large.json"
    assert main(["analyze", str(source), "--max-nodes", "2", "-o", str(small)]) == 3
    assert json.loads(small.read_text())["summary"]["analyzed_sources"] == 0
    assert "increase --max-nodes" in capsys.readouterr().out
    assert main(["analyze", str(source), "--max-nodes", "100", "-o", str(large)]) == 0
    assert len(json.loads(large.read_text())["endpoints"]) == 1
