from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from detlab.main import app

runner = CliRunner()

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



def write_sample_detection(base: Path):
    detections = base / "detections" / "windows"
    detections.mkdir(parents=True, exist_ok=True)
    sample_path = detections / "encoded_powershell.yaml"
    sample_path.write_text(SAMPLE_DETECTION, encoding="utf-8")
    return sample_path



def test_validate_passes_for_sample_detections(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        write_sample_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(app, ["validate", "detections"])
        assert result.exit_code == 0, result.output
        assert "PASS" in result.output



def test_report_generates_markdown(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        write_sample_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(
            app,
            ["report", "detections", "--format", "markdown", "--output", "reports/coverage.md"],
        )
        assert result.exit_code == 0, result.output
        assert Path("reports/coverage.md").exists()



def test_attack_report_generates_markdown(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        write_sample_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(
            app,
            ["attack", "report", "detections", "--format", "markdown", "--output", "reports/attack.md"],
        )
        assert result.exit_code == 0, result.output
        assert Path("reports/attack.md").exists()



def test_convert_single_detection_to_splunk(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        sample_path = write_sample_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(
            app,
            ["convert", str(sample_path), "--target", "splunk", "--output", "exports/test.spl"],
        )
        assert result.exit_code == 0, result.output
        assert Path("exports/test.spl").exists()



def test_map_attck_generates_json(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        write_sample_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(app, ["map-attck", "detections", "--output", "reports/attack-map.json"])
        assert result.exit_code == 0, result.output
        assert Path("reports/attack-map.json").exists()



def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0, result.output
    assert "0.1.0" in result.output
