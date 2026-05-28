# DetLab

DetLab is an open-source detection-as-code CLI for validating detection content, mapping detections to MITRE ATT&CK, and generating coverage reports for security teams.

It is built for defenders who want to treat detections like code: versioned, tested, reviewable, and automation-friendly.

## Why DetLab exists

Detection content often lives in scattered notes, SIEM dashboards, or undocumented rules. DetLab helps turn that into a structured workflow with:
- Schema validation for detection files
- ATT&CK technique mapping
- Reproducible test references
- Markdown and JSON coverage reports
- GitHub Actions-friendly automation

## Features

- Validate YAML detection files
- Enforce required metadata
- Check ATT&CK ID formatting
- Ensure every detection has at least one test reference
- Generate simple ATT&CK coverage reports
- Integrate with CI for pull request validation

## Installation

```bash
git clone https://github.com/egrexsec/DetLab-DAC.git
cd DetLab-DAC
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Quick start

Validate detections:

```bash
detlab validate detections
```

Generate a markdown report:

```bash
detlab report detections --format markdown --output reports/coverage.md
```

Generate ATT&CK mapping JSON:

```bash
detlab map-attck detections --output reports/attack-map.json
```

## Example detection structure

```text
detections/
├── windows/
│   ├── encoded_powershell.yml
│   └── local_admin_creation.yml
└── cloud/
    └── aws_root_login.yml
```

## Example workflow

1. Add or update a detection YAML file in `detections/`
2. Run `detlab validate detections`
3. Run `detlab report detections`
4. Open a pull request
5. Let GitHub Actions verify linting and tests

## Detection schema

Each detection should include:
- `id`
- `title`
- `description`
- `logsource`
- `attack`
- `severity`
- `status`
- `author`
- `references`
- `falsepositives`
- `tests`
- `detection`

Example:

```yaml
id: DET-0001
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
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
  condition: selection
```

## Roadmap

- v0.1: Validation, ATT&CK mapping, markdown/json reports
- v0.2: Sigma import/export
- v0.3: Splunk and KQL exporters
- v0.4: Microsoft 365 / Entra ID support
- v0.5: AWS CloudTrail support

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

## Security

Please read [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

MIT
