# DetLab

DetLab is an advanced detection engineering platform for validating, translating, scoring, packaging, distributing, and verifying behavioral detections across multiple security backends.

## Platform Capabilities

- Detection validation
- ATT&CK mapping and analytics
- Detection maturity scoring
- Behavioral sequence detections
- Multi-platform export pipelines
- HTML analytics dashboards
- Detection pack management
- Pack registry workflows
- Pack trust verification
- Docker deployment support
- GHCR publishing workflows
- Governance reporting
- CI/CD integration

## Docker Deployment

DetLab supports containerized execution using Docker.

## Build Local Image

```bash
docker build -t detlab .
```

## Run Validation

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  detlab validate detections
```

## Run Analytics

```bash
docker run --rm \
  -v "$PWD:/workspace" \
  detlab analytics detections
```

## GitHub Container Registry

Published images:

```text
ghcr.io/egrexsec/detlab:latest
```

## Automated Container Publishing

DetLab now supports:

- automated Docker builds
- GitHub Container Registry publishing
- tag-based releases
- reproducible CI/CD execution

## Detection Pack Trust Verification

DetLab supports integrity-oriented pack verification workflows.

### Verify Detection Pack

```bash
detlab pack verify registry/windows-core-1.0.0.tar.gz \
  --metadata registry/windows-core.json
```

Supports:
- SHA256 verification
- Registry metadata validation
- Pack integrity validation
- Trust-oriented governance workflows

## Detection Pack Registry

### Build Detection Pack

```bash
detlab pack build packs/windows-core
```

### Publish Detection Pack

```bash
detlab pack publish packs/windows-core
```

### Install Detection Pack

```bash
detlab pack install windows-core
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
- Pack integrity verification
- Reproducible container execution

## Long-Term Vision

DetLab is evolving toward:

- enterprise detection governance
- secure detection distribution ecosystems
- reusable behavioral detection libraries
- trusted security content pipelines
- portable detection engineering platforms
- container-native detection engineering

## License

MIT
