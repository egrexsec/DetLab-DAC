from copy import deepcopy

import yaml

from detlab.contracts import CANONICAL_MODEL_VERSION
from detlab.eql import export_eql_detection
from detlab.kql import export_kql_detection
from detlab.models import Detection
from detlab.sigma_export import export_sigma_detection
from detlab.splunk import export_splunk_detection

_TEMPLATE_DETECTION_PAYLOAD = {
    "id": "DET-1000",
    "title": "Suspicious PowerShell Network Retrieval",
    "description": "Detects suspicious PowerShell retrieving remote content and launching follow-on execution.",
    "logsource": {
        "product": "windows",
        "service": "sysmon",
    },
    "attack": {
        "technique": "T1059.001",
        "tactic": "execution",
    },
    "severity": "high",
    "status": "experimental",
    "author": "DetLab",
    "domain": ["endpoint"],
    "platforms": ["windows"],
    "references": [
        "https://attack.mitre.org/techniques/T1059/001/",
    ],
    "falsepositives": [
        "Administrative automation that legitimately retrieves remote content.",
    ],
    "tests": [
        {
            "name": "Atomic validation",
            "source": "atomic-red-team",
            "test_id": "template-1",
        }
    ],
    "detection": {
        "selection": {
            "EventID": 1,
            "Image|endswith": "\\powershell.exe",
            "CommandLine|contains": [
                "Invoke-WebRequest",
                "DownloadString",
            ],
        },
        "condition": "selection",
    },
}

_MARKDOWN_TEMPLATE = """---
id: DET-1001
name: Markdown Suspicious PowerShell Hunt
author: DetLab
status: experimental
severity: medium
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
tests:
  - name: Analyst validation
    source: markdown-curation
    test_id: template-markdown-1
---

# Markdown Suspicious PowerShell Hunt

Detects suspicious PowerShell retrieving remote content and launching follow-on execution.

## Query
```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "DownloadString")
```
"""


def _template_detection() -> Detection:
    return Detection.model_validate(deepcopy(_TEMPLATE_DETECTION_PAYLOAD))



def build_detection_templates() -> dict[str, object]:
    detection = _template_detection()
    yaml_template = yaml.safe_dump(deepcopy(_TEMPLATE_DETECTION_PAYLOAD), sort_keys=False)
    return {
        "canonical_model_version": CANONICAL_MODEL_VERSION,
        "default_format": "yaml",
        "templates": {
            "yaml": {
                "label": "Canonical YAML",
                "description": "Primary DetLab authoring template for canonical detections.",
                "content": yaml_template,
            },
            "markdown": {
                "label": "Markdown detection",
                "description": "Markdown-authored detection or hunt template with frontmatter and query block.",
                "content": _MARKDOWN_TEMPLATE,
            },
            "sigma": {
                "label": "Sigma",
                "description": "Rendered Sigma template that round-trips through DetLab normalization.",
                "content": export_sigma_detection(detection),
            },
            "splunk": {
                "label": "Splunk",
                "description": "Rendered Splunk SPL template that round-trips through DetLab normalization.",
                "content": export_splunk_detection(detection),
            },
            "kql": {
                "label": "KQL",
                "description": "Rendered KQL template that round-trips through DetLab normalization.",
                "content": export_kql_detection(detection),
            },
            "eql": {
                "label": "EQL",
                "description": "Rendered EQL template that round-trips through DetLab normalization.",
                "content": export_eql_detection(detection),
            },
        },
    }
