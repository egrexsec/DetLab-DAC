# DetLab

DetLab is an open-source detection-as-code platform for validating detections, generating analytics, exporting detections across platforms, and managing reusable behavioral detection content.

## Core Capabilities

- Detection validation
- ATT&CK mapping
- ATT&CK analytics
- Detection maturity scoring
- Behavioral sequence detections
- Sigma import/export
- Splunk SPL export
- Microsoft Sentinel KQL export
- Elastic EQL export
- HTML dashboard generation
- Detection pack management
- Governance reporting
- CI/CD integration

## Detection Packs

DetLab now supports reusable detection packs.

### Example Structure

```text
packs/
  windows-core/
    pack.yml
    detections/

  insider-threat/
    pack.yml
    detections/
```

### Example Manifest

```yaml
name: windows-core
version: 1.0.0
maintainer: Mell0wx
platforms:
  - splunk
  - sentinel
  - elastic

attack_tactics:
  - execution
  - persistence
```

## Pack Features

- Pack manifest validation
- Version tracking
- Supported backend tracking
- ATT&CK coverage summaries
- Pack maturity scoring
- Dependency tracking
- Reusable detection libraries

## Example Pack Workflows

### Validate Pack

```bash
detlab pack validate packs/windows-core
```

### Generate Pack Report

```bash
detlab pack report packs/windows-core --format markdown
```

## Behavioral Sequence Example

```yaml
sequence:
  within: 5m

  events:
    - name: PowerShell Execution
      selection:
        Image: powershell.exe

    - name: Suspicious Network Connection
      selection:
        DestinationPort: 4444
```

## Platform Export Matrix

| Backend | Supported |
|---|---|
| Sigma | Yes |
| Splunk SPL | Yes |
| Microsoft Sentinel KQL | Yes |
| Elastic EQL | Yes |

## Governance + Analytics

DetLab supports:

- ATT&CK tactic coverage analysis
- Detection quality scoring
- Weak detection identification
- Maturity distributions
- HTML executive dashboards
- Behavioral analytics foundations

## Roadmap

- Pack publishing
- Community registry
- Interactive dashboards
- Correlation rule generation
- Behavioral detection packs
- Threat-informed analytics

## License

MIT
