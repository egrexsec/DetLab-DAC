from contextlib import contextmanager
from pathlib import Path
import os
import tempfile
from typer.testing import CliRunner
from detlab.main import app

runner = CliRunner()


@contextmanager
def isolated_workspace():
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        try:
            yield Path(tmpdir)
        finally:
            os.chdir(previous)

SAMPLE_DETECTION = """id: DET-0001
title: Suspicious Encoded PowerShell
description: Detects PowerShell launched with encoded command arguments.
logsource:
  product: windows
  service: sysmon
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: experimental
author: Mell0wx
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Administrative scripts using encoded commands
tests:
  - name: Atomic Red Team T1059.001
    source: atomic-red-team
    test_id: "1"
detection:
  selection:
    EventID: 1
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
"""


def write_sample_detection():
    detections = Path("detections/windows")
    detections.mkdir(parents=True, exist_ok=True)
    (detections / "encoded_powershell.yaml").write_text(SAMPLE_DETECTION, encoding="utf-8")


def test_validate_passes_for_sample_detections():
    with isolated_workspace():
        write_sample_detection()
        result = runner.invoke(app, ["validate", "detections"])
        assert result.exit_code == 0, result.output
        assert "PASS" in result.output


def test_report_generates_markdown():
    with isolated_workspace():
        write_sample_detection()
        result = runner.invoke(
            app,
            ["report", "detections", "--format", "markdown", "--output", "reports/coverage.md"],
        )
        assert result.exit_code == 0, result.output
        assert Path("reports/coverage.md").exists()


def test_map_attck_generates_json():
    with isolated_workspace():
        write_sample_detection()
        result = runner.invoke(app, ["map-attck", "detections", "--output", "reports/attack-map.json"])
        assert result.exit_code == 0, result.output
        assert Path("reports/attack-map.json").exists()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert "0.1.0" in result.output
