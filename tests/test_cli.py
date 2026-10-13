import json
import os
import subprocess
import sys

import pytest

from scriptlens.cli import main
from scriptlens.network import Fetcher, Response


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


@pytest.mark.parametrize(
    "arguments,expected",
    [
        (["-u", "example.test"], ["https://example.test/"]),
        (["-u", "https://example.test/app"], ["https://example.test/app"]),
        (["-u", "http://example.test/"], ["http://example.test/"]),
        (["-u", "LIST"], ["https://example.test/", "https://other.test/app"]),
        (
            ["-u", "example.test", "-u", "https://other.test/app"],
            ["https://example.test/", "https://other.test/app"],
        ),
        (["scan", "-d", "example.test"], ["https://example.test/"]),
        (["scan", "-l", "LIST"], ["https://example.test/", "https://other.test/app"]),
        (["example.test"], ["https://example.test/"]),
        (["-u", "LIST", "--number-of-domains", "1"], ["https://example.test/"]),
        (["-u", "LIST", "-number-of-domaint", "1"], ["https://example.test/"]),
        (["-u", "LIST", "-n", "50000"], ["https://example.test/", "https://other.test/app"]),
    ],
)
def test_simple_input_flows_save_json(tmp_path, monkeypatch, capsys, arguments, expected):
    monkeypatch.chdir(tmp_path)
    listing = tmp_path / "domains.txt"
    listing.write_text("example.test\nhttps://other.test/app\nhttps://example.test/\n")
    requested = []

    async def fake_get(self, url, kind):
        requested.append(url)
        return Response(
            url, url, 200, b"<script>fetch('/api')</script>", {"content-type": "text/html"}
        )

    monkeypatch.setattr(Fetcher, "get", fake_get)
    assert main([str(listing) if arg == "LIST" else arg for arg in arguments]) == 0
    report = json.loads(next((tmp_path / "scriptlens-results").glob("*.json")).read_text())
    assert report["targets"] == expected
    assert requested == expected
    assert len(report["endpoints"]) == len(expected)


@pytest.mark.parametrize("arguments", [[], ["--help"], ["scan", "--help"]])
def test_basic_help_is_short_and_points_to_advanced_help(arguments, capsys):
    with pytest.raises(SystemExit) as exc:
        main(arguments)
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "-u" in output and "domains.txt" in output
    assert "--help-all" in output
    assert "--max-nodes" not in output and "--scope" not in output
    assert "\x1b" not in output


def test_advanced_help_exposes_existing_controls(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help-all"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    assert "--max-nodes" in output and "--scope" in output and "--insecure" in output
    assert "\x1b" not in output


def test_missing_list_does_not_start_a_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["-u", "missing.txt"]) == 2
    assert "input list file does not exist" in capsys.readouterr().err
    assert not (tmp_path / "scriptlens-results").exists()


@pytest.mark.parametrize("count", ["0", "-1", "100001", "abc"])
def test_invalid_target_count_fails_before_scan(count):
    with pytest.raises(SystemExit) as exc:
        main(["-u", "example.test", "-n", count])
    assert exc.value.code == 2
