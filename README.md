# DetLab

Detection Engineering Workbench

Build, validate, score, convert, test, and visualize detections from a single platform.

DetLab is built for detection engineers, threat hunters, SOC analysts, DFIR analysts, and security engineers who want a practical way to improve a detection library without standing up a heavy governance platform.

## Why DetLab

Most detection teams still piece together validation, ATT&CK mapping, backend conversion, scoring, and reporting with ad hoc scripts and spreadsheets.

That creates slow feedback loops:
- detections get written but not validated consistently
- ATT&CK coverage is hard to explain quickly
- backend conversion becomes repetitive manual work
- weak metadata and weak tests hide inside otherwise useful rules
- recruiters, hiring managers, and internal stakeholders cannot tell what the detection program actually does

DetLab focuses on the core workflow instead:
- **Is this detection valid?**
- **How good is this detection?**
- **What ATT&CK techniques does it cover?**
- **Can I convert it to another backend?**
- **What coverage gaps exist?**
- **How mature is my detection library?**

Think of it as **Terraform for detections**.

## Features

### 1. Detection Validation

Validate single files or full libraries for:
- syntax
- schema compliance
- ATT&CK metadata presence
- required detection metadata

```bash
detlab validate detections
```

### 2. Detection Conversion

Convert detections to backend-specific formats from one CLI.

Supported outputs:
- Sigma
- Splunk SPL
- Sentinel KQL
- Elastic EQL

```bash
detlab convert detections/windows/encoded_powershell.yml --target splunk
```

### 3. Detection Scoring

Score detections using practical engineering-oriented dimensions:
- Coverage Score
- Specificity Score
- Metadata Score
- Maintainability Score
- False Positive Risk
- Overall Score

```bash
detlab score detections --format markdown --output reports/scores.md
```

### 4. ATT&CK Coverage Analysis

Generate ATT&CK-oriented reports for:
- coverage by tactic
- coverage by technique
- coverage by platform
- missing coverage
- weak coverage
- high-risk gaps

```bash
detlab attack report detections --format markdown --output reports/attack-coverage.md
```

### 5. Detection Packs

Ship reusable sample packs for focused demo and adoption workflows.

Included examples:
- Windows Core
- PowerShell
- Credential Access
- Persistence
- CloudTrail
- Linux Core

```bash
detlab pack-report examples/packs/windows-core
```

## Screenshots

Captured from the verified Docker Compose stack in this repository.

### 1. Dashboard Overview

![Dashboard Overview](docs/images/dashboard-overview.png)

### 2. ATT&CK Heatmap

![ATT&CK Heatmap](docs/images/attack-heatmap.png)

### 3. Detection Score View

![Detection Score View](docs/images/detection-score-view.png)

### 4. Detection Pack View

![Detection Pack View](docs/images/detection-pack-view.png)

## Architecture

DetLab is designed as a detection engineering workbench with a fast local demo path and a workflow that maps cleanly to real SOC engineering tasks.

![DetLab Architecture Diagram](docs/images/architecture-diagram.png)

Architecture highlights:
- **Typer CLI** for validation, scoring, ATT&CK reporting, and backend export workflows
- **FastAPI** for health, validation, scoring, analytics, packs, and dashboard data APIs
- **Next.js dashboard** for overview, ATT&CK coverage, detection quality, packs, and reporting views
- **Scoring engine** for coverage, specificity, metadata, maintainability, and false-positive risk calculations
- **ATT&CK analytics** for tactic/technique coverage, weak coverage, and high-risk gaps
- **Export engine** for Splunk SPL, Sigma, Sentinel KQL, and Elastic EQL outputs
- **Detection packs** for reusable demo and engineering-focused content bundles
- **Docker Compose** for one-command local deployment

For the editable source diagram, see `docs/architecture-diagram.html`.

## Quick Start

### Requirements
- Docker Compose
- GNU Make

### One-command startup

```bash
git clone https://github.com/egrexsec/DetLab-DAC.git
cd DetLab-DAC
cp .env.example .env
make up
```

Open:
- `http://localhost:3000`

### What starts
- `web` → Next.js workbench UI on port `3000`
- `api` → FastAPI backend behind the `/api` proxy path

### Environment defaults

`.env.example` includes:
- `DETLAB_ROOT_PATH=/api`
- `NEXT_PUBLIC_API_BASE_URL=/api`
- `DETLAB_PACK_ROOT=/workspace/examples/packs`

The `/api` root path keeps FastAPI docs and OpenAPI working correctly when the UI proxies requests through the web container.

### Useful commands

```bash
make ps
make logs
make down
make test
```

## Example Workflow

1. Create or import a detection
2. Validate the detection
3. Score the detection quality
4. Generate an ATT&CK coverage report
5. Convert the detection for a target backend

```bash
detlab validate detections/windows/encoded_powershell.yml
detlab score detections --format markdown --output reports/scores.md
detlab attack report detections --format markdown --output reports/attack-coverage.md
detlab convert detections/windows/encoded_powershell.yml --target splunk --output exports/encoded_powershell.spl
```

## Sample Detection Packs

### Windows Core
Baseline Windows endpoint detections for execution, process creation, and admin tooling.

### PowerShell
Focused PowerShell pack for encoded commands, download activity, and script abuse.

### Credential Access
Starter pack metadata for credential theft and token abuse coverage expansion.

### Persistence
Pack centered on foothold-establishment and account abuse use cases.

### CloudTrail
Cloud detection starter pack for AWS control-plane monitoring and audit workflows.

### Linux Core
Baseline Linux starter pack for auth, process, and persistence telemetry.

## Roadmap

### Next 30 days
- improve pack-level analytics and pack comparison views
- add richer detection test result surfacing in the UI
- add single-detection drill-down pages for validation and score reasoning
- add export previews for Sigma, SPL, KQL, and EQL in the dashboard
- tighten scoring heuristics with better maintainability and FP-risk signals
- expand sample pack content for Linux, CloudTrail, and Credential Access

## Future Vision

The following ideas remain valid, but they are intentionally **not** the V1 story.

Future vision areas:
- detection marketplace
- registry ecosystem
- enterprise governance
- detection distribution networks
- trust ecosystems
- multi-tenant architecture
- enterprise workflow management
- detection supply chains

These belong after the workbench is easy to understand, easy to deploy, easy to demo, and easy to adopt.

## Recruiter Demo Test

A good DetLab demo should let someone understand the value in under 30 seconds:
- detections are validated
- detections are scored
- ATT&CK coverage is visible
- backend conversion exists
- packs make the project easy to demo and extend

A detection engineer should understand the core workflow in under 2 minutes.
A new user should be able to deploy the stack in under 5 minutes with Docker Compose and `make up`.
