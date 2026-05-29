# DetLab

DetLab is an advanced detection engineering platform for validating, translating, scoring, packaging, distributing, verifying, serving, and visualizing behavioral detections across multiple security backends.

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
- FastAPI service layer
- Next.js dashboard foundation
- GHCR publishing workflows
- Governance reporting
- CI/CD integration

## Web Dashboard

DetLab now supports a Next.js-based dashboard foundation.

## Dashboard Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js |
| API | FastAPI |
| Runtime | Docker Compose |
| Deployment | Container-native |

## Frontend Setup

```bash
cd web
npm install
npm run dev
```

Frontend URL:

```text
http://localhost:3000
```

## API Server

```bash
uvicorn detlab.api:app --host 0.0.0.0 --port 8000
```

API URL:

```text
http://localhost:8000
```

## Docker Compose Stack

```bash
docker compose up --build
```

Supports:
- frontend dashboard
- FastAPI backend
- containerized local development
- platform orchestration

## Dashboard Features

Current dashboard foundation includes:

- API health monitoring
- platform capability overview
- frontend/API integration foundation
- governance dashboard groundwork

## Planned Dashboard Features

- ATT&CK heatmaps
- detection score visualizations
- maturity distributions
- pack browsing
- trust verification status
- governance analytics
- behavioral detection timelines

## Detection Pack Trust Verification

```bash
detlab pack verify registry/windows-core-1.0.0.tar.gz \
  --metadata registry/windows-core.json
```

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
- API-backed workflows
- Frontend platform foundations

## Long-Term Vision

DetLab is evolving toward:

- enterprise detection governance
- secure detection distribution ecosystems
- reusable behavioral detection libraries
- trusted security content pipelines
- portable detection engineering platforms
- container-native detection engineering
- API-driven detection operations
- full detection engineering platform ecosystems

## License

MIT
