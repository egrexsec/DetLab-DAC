from pathlib import Path
from tempfile import TemporaryDirectory

import yaml
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



MARKDOWN_DETECTION = """---
id: DET-3101
name: Encoded PowerShell
content_kind: hunt
status: validated
severity: high
author: mell0wx
domain:
  - endpoint
platforms:
  - windows
logsource:
  product: mde
  service: advanced_hunting
attack:
  technique: T1059.001
  tactic: execution
triage_steps:
  - step: Validate the parent process and user context.
    priority: high
investigation_steps:
  - step: Review nearby process and network activity.
    priority: high
response_actions:
  - title: Isolate the endpoint if execution is suspicious.
    priority: high
tests:
  - name: Analyst validation
    source: markdown-curation
    test_id: encoded-powershell-v1
---

# Encoded PowerShell

Markdown-only detection used for CLI regression coverage.

## Query
```kusto
DeviceProcessEvents
| where ProcessCommandLine has "-enc"
```
"""



def write_markdown_detection(base: Path) -> Path:
    detections = base / "playbook"
    detections.mkdir(parents=True, exist_ok=True)
    sample_path = detections / "encoded-powershell.md"
    sample_path.write_text(MARKDOWN_DETECTION, encoding="utf-8")
    return sample_path



def test_validate_passes_for_sample_detections(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        write_sample_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(app, ["validate", "detections"])
        assert result.exit_code == 0, result.output
        assert "PASS" in result.output



def test_validate_passes_for_markdown_only_detections(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        write_markdown_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(app, ["validate", "playbook"])
        assert result.exit_code == 0, result.output
        assert "encoded-powershell.md" in result.output
        assert "PASS" in result.output



def test_score_generates_json_for_markdown_only_source(monkeypatch):
    with TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        write_markdown_detection(base)
        monkeypatch.chdir(base)
        result = runner.invoke(
            app,
            ["score", "playbook", "--format", "json", "--output", "reports/score.json"],
        )
        assert result.exit_code == 0, result.output
        score_path = Path("reports/score.json")
        assert score_path.exists()
        payload = yaml.safe_load(score_path.read_text(encoding="utf-8"))
        assert payload
        assert payload[0]["title"] == "Encoded PowerShell"



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
