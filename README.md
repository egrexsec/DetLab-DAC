# DetLab-DAC

> *Technical preview / portfolio project*

DetLab-DAC is a detection engineering workbench for validating detection-as-code content, scoring rule maturity, mapping coverage to MITRE ATT&CK, exporting detections to multiple backends, and exposing the results through a lightweight API and dashboard.

It is currently best understood as a **functional alpha**: the core CLI, API, Docker workflow, and dashboard foundation are working, but the project still needs stronger screenshots, attack-flow diagrams, and broader test coverage before it should be presented as a polished general-release platform.

## What it does

DetLab-DAC currently supports:
- Detection schema validation
- Detection maturity scoring
- ATT&CK tactic / technique coverage reporting
- Static dashboard generation from the CLI
- API-backed dashboard data for the web UI
- Multi-backend export workflows
- Detection pack build / publish / install / verify commands
- Docker-based local deployment

## Why this project matters

This repo is aimed at a real detection engineering problem:

- normalizing detection content into a consistent schema
- checking whether detections are operationally mature
- measuring ATT&CK coverage and weak spots
- translating the same content into downstream security backends
- making the state of a detection library visible through a dashboard

That makes it relevant to:
- detection engineering
- threat hunting support workflows
- content governance
- purple-team validation pipelines
- security automation portfolios

## Current release posture

**Safe claim:** DetLab-DAC is a working technical preview for detection validation, scoring, export, and dashboard-backed visibility.

**Avoid claiming:** production-ready platform, enterprise-ready detection pipeline, or fully complete content registry.

Known current boundaries:
- minimal automated test coverage is present
- dashboard visuals are functional but still early-stage
- screenshots and architecture diagrams are still needed for stronger portfolio presentation
- sample detections are included, but broader real-world content depth is still limited

## Architecture

```text
Detection YAML -> Validation / Scoring / ATT&CK Analytics -> API / CLI / Exports / Dashboard
```

Stack:
- CLI: Python + Typer
- API: FastAPI
- Web: Next.js
- Charts: Recharts
- Runtime: Docker Compose
- Schema / validation: Pydantic

[ARCHITECTURE DIAGRAM REQUIRED — DETECTION FLOW]

## Screenshots needed

The README is cleaned up, but visuals are still required for a proper flagship presentation.

- [SCREENSHOT REQUIRED — DASHBOARD OVERVIEW]
- [SCREENSHOT REQUIRED — ATT&CK HEATMAP]
- [SCREENSHOT REQUIRED — SPLUNK EXPORT / ANALYTICS VIEW]
- [ARCHITECTURE DIAGRAM REQUIRED — DETECTION VALIDATION + EXPORT FLOW]

## Quick start with Docker

This Docker flow assumes you are running from a full checkout of the repository root — not from a standalone copied Compose snippet.

Required files:
- `docker-compose.yml`
- `Dockerfile.api`
- `web/Dockerfile`

Expected layout:

```text
DetLab-DAC/
├── docker-compose.yml
├── Dockerfile.api
├── requirements-api.txt
├── pyproject.toml
├── detlab/
├── detections/
└── web/
    └── Dockerfile
```

### What runs
- `web`: public dashboard on port `3000`
- `api`: internal-only FastAPI service behind the web app proxy

### Docker Compose setup

```yaml
services:
  api:
    build:
      context: .
      dockerfile: Dockerfile.api
    volumes:
      - ./detections:/workspace/detections:ro

  web:
    build:
      context: ./web
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    depends_on:
      - api
```

This setup builds the FastAPI service from `Dockerfile.api`, builds the Next.js dashboard from `web/Dockerfile`, exposes the web UI on port `3000`, and mounts `./detections` read-only into the API container so the dashboard and API reflect the local detection content.

### Start

```bash
docker compose up -d --build
```

### Verify

```bash
docker compose ps
curl http://localhost:3000/api/health
curl http://localhost:3000/api/dashboard
```

Expected health response:

```json
{"status":"ok"}
```

### Access

Open:

```text
http://localhost:3000
http://localhost:3000/api/docs
```

### Logs

```bash
docker compose logs -f api
docker compose logs -f web
```

### Stop

```bash
docker compose down
```

### Docker notes
- The API container uses `Dockerfile.api`.
- The web container uses a committed `package-lock.json` and `npm ci` for deterministic installs.
- The API is not published directly to the host in the current Compose setup.
- Detection content is mounted into the API container from `./detections`.

## Local development

### API

```bash
pip install -r requirements-api.txt
uvicorn detlab.api:app --host 0.0.0.0 --port 8000
```

API endpoints during direct local development:

```text
http://localhost:8000/health
http://localhost:8000/docs
http://localhost:8000/dashboard
```

### Web

```bash
cd web
npm install
npm run dev
```

Web UI during local development:

```text
http://localhost:3000
```

## Example CLI workflows

### Validate detections

```bash
detlab validate detections
```

### Generate maturity report

```bash
detlab score detections --format markdown --output reports/maturity.md
```

### Generate ATT&CK analytics

```bash
detlab analytics detections --format markdown --output reports/analytics.md
```

### Generate static dashboard

```bash
detlab dashboard detections --output reports/dashboard.html
```

### Export to supported backends

```bash
detlab export-sigma detections --output exports/sigma
detlab export-splunk detections --output exports/splunk
detlab export-kql detections --output exports/kql
detlab export-eql detections --output exports/eql
```

### Import Sigma rules into the DetLab schema

```bash
detlab sigma-import sigma_rules --output detections/imported --start-id 1000
```

## Detection model

Detections are validated against a structured schema that currently includes:
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

### Example detection

```yaml
id: DET-0001
title: PowerShell WebClient Download
description: Detects PowerShell using .NET WebClient to retrieve remote content.
logsource:
  product: windows
  service: powershell
attack:
  technique: T1059.001
  tactic: execution
severity: high
status: stable
author: mell0wx
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Administrative PowerShell automation downloading approved internal content.
tests:
  - name: Atomic Red Team T1059.001 WebClient Download
    source: atomic-red-team
    test_id: 1
detection:
  selection:
    Image: powershell.exe
    CommandLine|contains:
      - New-Object Net.WebClient
      - DownloadString
  condition: selection
```

## Supported export targets

- Sigma
- Splunk SPL
- Microsoft Sentinel KQL
- Elastic EQL

## API endpoints

Primary endpoints currently exposed by the FastAPI service:
- `GET /health`
- `GET /validate`
- `GET /analytics`
- `GET /score`
- `GET /dashboard`

In the Docker setup, these are accessed through the web app proxy under `/api/*`.

## Current repo strengths

- Real Python CLI implementation, not just a concept README
- Working FastAPI layer
- Working Next.js dashboard shell
- Dockerized local stack
- Detection validation and scoring logic in code
- Cross-backend export direction aligned with detection engineering work

## Highest-value next improvements

1. Add real screenshots from the dashboard and exports
2. Add an architecture / attack-flow diagram
3. Expand automated tests beyond health checks
4. Add more realistic detection content and validation cases
5. Show a full threat-hunting / detection-engineering workflow in the README

## License

MIT
