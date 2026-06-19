from pathlib import Path

from fastapi.testclient import TestClient

from detlab import api as api_module
from detlab.domain import build_detection_catalog, build_detection_workspace, load_detections

client = TestClient(api_module.app)

SAMPLE_MARKDOWN = """---
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
  - mde
logsource:
  product: mde
  service: advanced_hunting
attack:
  technique: T1059.001
  tactic: execution
attack_context:
  - technique: T1027
    tactic: defense-evasion
    name: Obfuscated Files or Information
    coverage: partial
    rationale: Encoded commands frequently overlap with obfuscation.
data_sources:
  - name: DeviceProcessEvents
    kind: process
    provider: mde
triage_steps:
  - step: Validate the affected user, host, and parent process.
    priority: high
investigation_steps:
  - step: Collect command-line history and nearby network activity.
    priority: high
falsepositives:
  - Administrative automation using encoded commands.
artifacts:
  - name: PowerShell operational logs
    category: event_log
    path: Microsoft-Windows-PowerShell/Operational
velociraptor_artifacts:
  - Windows.EventLogs.PowerShell
related_detections:
  - detection_id: DET-3102
    relationship: follow_on
    rationale: Encoded PowerShell often leads into additional staging.
response_actions:
  - title: Isolate the endpoint if execution is suspicious.
    priority: high
tests:
  - name: Analyst validation
    source: markdown-curation
    test_id: encoded-powershell-v1
---

# Encoded PowerShell

This markdown knowledge entry captures PowerShell execution hunting guidance for encoded command usage.

## Query
```kusto
DeviceProcessEvents
| where ProcessCommandLine has_any ("-enc", "-encodedcommand")
```

## Triage Guidance
- Validate the affected user, host, and parent process.

## Investigation Steps
- Collect command-line history and nearby network activity.
"""


def _write_markdown_source(tmp_path: Path) -> Path:
    source_dir = tmp_path / 'playbook-source'
    source_dir.mkdir()
    (source_dir / 'README.md').write_text('# Playbook Source\n\nCatalog landing page only.\n', encoding='utf-8')
    (source_dir / 'encoded-powershell.md').write_text(SAMPLE_MARKDOWN, encoding='utf-8')
    return source_dir



def test_load_detections_supports_markdown_only_sources(tmp_path: Path):
    source_dir = _write_markdown_source(tmp_path)

    detections = load_detections(str(source_dir))

    assert len(detections) == 1
    detection = detections[0]
    assert detection.id == 'DET-3101'
    assert detection.title == 'Encoded PowerShell'
    assert detection.attack.technique == 'T1059.001'
    assert detection.attack_context[0].technique == 'T1027'
    assert detection.logsource.product == 'mde'
    assert detection.detection.selection['SourcePath'] == 'encoded-powershell.md'
    assert detection.detection.selection['QueryLanguage'] == 'kusto'
    assert 'QueryText' in detection.detection.selection



def test_markdown_source_populates_catalog_and_workspace(tmp_path: Path):
    source_dir = _write_markdown_source(tmp_path)

    catalog = build_detection_catalog(str(source_dir))

    assert catalog['total'] == 1
    entry = catalog['detections'][0]
    assert entry['title'] == 'Encoded PowerShell'
    assert 'DeviceProcessEvents' in entry['data_sources']

    workspace = build_detection_workspace(entry['id'], str(source_dir))

    assert workspace is not None
    assert workspace['overview']['attack_mappings']['primary']['technique'] == 'T1059.001'
    assert workspace['overview']['content_source']['path'] == 'encoded-powershell.md'
    assert workspace['overview']['query']['language'] == 'kusto'
    assert 'ProcessCommandLine' in workspace['overview']['query']['text']
    assert workspace['overview']['detection_logic']['selection']['ContentKind'] == 'hunt'
    assert workspace['investigation_guidance']['triage_steps']
    assert workspace['response_actions'][0]['title'] == 'Isolate the endpoint if execution is suspicious.'



def test_dashboard_endpoint_exposes_markdown_source_content(tmp_path: Path):
    source_dir = _write_markdown_source(tmp_path)

    response = client.get('/dashboard', params={'path': str(source_dir)})

    assert response.status_code == 200
    body = response.json()
    assert body['summary']['total_detections'] == 1
    assert body['source']['mode'] == 'local'
    assert any(item.endswith('encoded-powershell.md') for item in body['reports']['files'])
    assert body['scoring'][0]['title'] == 'Encoded PowerShell'
