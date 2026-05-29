# DetLab

DetLab is an advanced detection engineering platform for validating, translating, scoring, packaging, and distributing behavioral detections across multiple security backends.

## Platform Capabilities

- Detection validation
- ATT&CK mapping and analytics
- Detection maturity scoring
- Behavioral sequence detections
- Multi-platform export pipelines
- HTML analytics dashboards
- Detection pack management
- Pack registry workflows
- Governance reporting
- CI/CD integration

## Detection Pack Registry

DetLab now supports registry-oriented detection pack workflows.

## Pack Lifecycle

```text
Build -> Publish -> Install -> Validate -> Analyze
```

## Supported Workflows

### Build Detection Pack

```bash
detlab pack build packs/windows-core
```

Creates:
- distributable archives
- checksum metadata
- semantic version metadata

### Publish Detection Pack

```bash
detlab pack publish packs/windows-core
```

Creates:
- registry archives
- registry metadata manifests
- reusable distributable bundles

### Install Detection Pack

```bash
detlab pack install windows-core
```

Supports:
- local registry cache
- reusable deployments
- portable content workflows

## Registry Metadata Example

```json
{
  "name": "windows-core",
  "version": "1.0.0",
  "checksum": "sha256-value",
  "archive": "windows-core-1.0.0.tar.gz"
}
```

## Detection Pack Structure

```text
packs/
  windows-core/
    pack.yml
    detections/
```

## Behavioral Detection Example

```yaml
sequence:
  within: 5m

  events:
    - name: PowerShell Execution
      selection:
        Image: powershell.exe

    - name: Network Connection
      selection:
        DestinationPort: 4444
```

## Supported Export Targets

| Backend | Support |
|---|---|
| Sigma | Yes |
| Splunk SPL | Yes |
| Microsoft Sentinel KQL | Yes |
| Elastic EQL | Yes |

## Governance Features

- ATT&CK coverage analytics
- Weak detection identification
- Detection maturity scoring
- Pack-level reporting
- Behavioral analytics
- Executive dashboards

## Long-Term Vision

DetLab is evolving toward:

- community detection ecosystems
- reusable behavioral detection libraries
- enterprise detection governance
- portable detection engineering pipelines
- threat-informed analytics platforms

## License

MIT
