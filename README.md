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
- ATT&CK Navigator layer generation
- Sigma rule import support

## Features

- Validate YAML detection files
- Enforce required metadata
- Check ATT&CK ID formatting
- Ensure every detection has at least one test reference
- Generate ATT&CK coverage reports
- Generate ATT&CK Navigator layers
- Import Sigma rules into DetLab format
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

Generate ATT&CK Navigator layer:

```bash
detlab navigator detections --output reports/navigator.json
```

Import Sigma rules:

```bash
detlab sigma-import sigma_rules --output detections/imported
```

## Example detection structure

```text
detections/
├── windows/
│   ├── encoded_powershell.yml
│   └── user_account_creation.yml
├── imported/
│   └── sigma_rule.yml
└── cloud/
    └── aws_root_login.yml
```

## Example workflow

1. Add or import a detection YAML file into `detections/`
2. Run `detlab validate detections`
3. Run `detlab report detections`
4. Run `detlab navigator detections`
5. Open a pull request
6. Let GitHub Actions verify linting, tests, detection validation, report generation, navigator export, and Sigma conversions

## Roadmap

- v0.1: Validation, ATT&CK mapping, markdown/json reports
- v0.2: Sigma import/export
- v0.3: Splunk and KQL exporters
- v0.4: Microsoft 365 / Entra ID support
- v0.5: AWS CloudTrail support

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please read [SECURITY.md](SECURITY.md).

## License

MIT
