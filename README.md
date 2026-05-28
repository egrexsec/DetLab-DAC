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
- Sigma rule export support
- PyPI distribution support
- Splunk SPL export support
- Microsoft Sentinel KQL export support
- Elastic EQL export support

## Features

- Validate YAML detection files
- Enforce required metadata
- Check ATT&CK ID formatting
- Ensure every detection has at least one test reference
- Generate ATT&CK coverage reports
- Generate ATT&CK Navigator layers
- Import Sigma rules into DetLab format
- Export detections into Sigma YAML
- Export detections into Splunk SPL
- Export detections into Microsoft Sentinel KQL
- Export detections into Elastic EQL
- Release-ready PyPI packaging
- Integrate with CI for pull request validation

## Installation

### Development install

```bash
git clone https://github.com/egrexsec/DetLab-DAC.git
cd DetLab-DAC
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### PyPI install

```bash
pip install detlab
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

Export Sigma rules:

```bash
detlab export-sigma detections --output exports/sigma
```

Export Splunk SPL:

```bash
detlab export-splunk detections --output exports/splunk
```

Export Microsoft Sentinel KQL:

```bash
detlab export-kql detections --output exports/kql
```

Export Elastic EQL:

```bash
detlab export-eql detections --output exports/eql
```

## Example workflow

1. Add or import a detection YAML file into `detections/`
2. Run `detlab validate detections`
3. Run `detlab report detections`
4. Run `detlab navigator detections`
5. Run `detlab export-sigma detections`
6. Run `detlab export-splunk detections`
7. Run `detlab export-kql detections`
8. Run `detlab export-eql detections`
9. Open a pull request
10. Let GitHub Actions verify linting, tests, detection validation, report generation, navigator export, Sigma conversions, package builds, and exporter logic

## Release workflow

Create a release tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions will:
- Build package distributions
- Verify distributions with Twine
- Publish to PyPI

## Roadmap

- v0.1: Validation, ATT&CK mapping, markdown/json reports
- v0.2: Sigma import/export
- v0.3: Splunk, KQL, and EQL exporters
- v0.4: Microsoft 365 / Entra ID support
- v0.5: AWS CloudTrail support

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please read [SECURITY.md](SECURITY.md).

## License

MIT
