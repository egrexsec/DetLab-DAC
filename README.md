# DetLab

DetLab is a website-first detection engineering and security knowledge platform.

It combines:
- a Next.js web app for browsing and authoring content
- a FastAPI backend for validation, scoring, conversion, sync, and workspace APIs
- repo-local Python tooling for validation, reporting, ATT&CK analytics, and export workflows

The repo is no longer positioned as a distributable Python package. The Python code exists to power the website and local workflows from this repository.

## What DetLab is for

DetLab is built for:
- detection engineering
- threat hunting
- cloud investigations
- incident response case studies
- learning paths and labs
- portfolio-ready security artifacts

Primary users:
- Detection Engineers
- Threat Hunters
- SOC Analysts
- Security Engineers
- DFIR Analysts

## Core capabilities

- Validate detections against the DetLab canonical schema
- Score detections for coverage, specificity, maintainability, metadata quality, and false-positive risk
- Convert canonical detections into Splunk SPL, Sigma, Microsoft Sentinel KQL, and Elastic EQL
- Generate ATT&CK coverage analytics and weak-signal summaries
- Browse a detection-first workspace with relationships, response actions, artifacts, and telemetry context
- Author detections, investigations, threat hunts, and learning artifacts through one workbench
- Sync a GitHub-backed content source into the active workspace for exploration

## Website workflow

1. Start the local stack.
2. Open `http://127.0.0.1:3000`.
3. Pivot between **Detections**, **Investigations**, **Threat Hunts**, and **Learning Paths**.
4. Open **Workbench**.
5. Load or paste content for the lane you want to author.
6. Set a repo path under `detections/` or `knowledge/`.
7. Click **Save to Repo** to persist the artifact into this repository.
8. Click **Inspect & Score** to validate and score it.
9. Preview backend conversions in-place.

## Screenshots

Captured on 2026-06-20 from the verified local FastAPI + Next.js workflow in this repository against the default GitHub-backed source (`egrexsec/cybersecurity-playbook` → `mde/advanced-hunting`).

### 1. Detection Workspace Overview

Top-level workspace view with the detection catalog, selected detection context, query, and investigation guidance.

![Detection Workspace Overview](docs/images/dashboard-overview.png)

### 2. ATT&CK Heat Map

Technique-context view showing direct coverage, partial coverage, related activity, and visible gaps for the selected detection.

![ATT&CK Heat Map](docs/images/attack-heatmap.png)

### 3. Score Review

Library-level scoring summary with distribution and per-detection quality breakdown.

![Score Review](docs/images/detection-score-view.png)

### 4. Repository Source

GitHub-backed source metadata and sync history for the active markdown detection library.

![Repository Source](docs/images/repository-source-view.png)

### 5. Validation & Conversion Workbench

In-browser authoring flow for validating detections, inspecting results, and previewing backend conversions.

![Validation & Conversion Workbench](docs/images/validation-workbench-view.png)

## Architecture

DetLab is evolving from a pure detection workbench into a detection-first investigation platform with a fast local demo path and a workflow that maps cleanly to real SOC engineering tasks.

![DetLab Architecture Diagram](docs/images/architecture-diagram.png)

Architecture highlights:
- **Next.js application** for the main catalog, workspace, content lanes, ATT&CK views, and authoring workflows
- **FastAPI backend** for health, validation, scoring, analytics, domain schema, source sync, catalog, and workspace APIs
- **Repo-local Python commands** for validation, reports, ATT&CK analytics, and backend export workflows
- **Detection domain schema** for investigation steps, artifacts, cloud telemetry, related detections, and response actions
- **Scoring engine** for coverage, specificity, metadata, maintainability, and false-positive risk calculations
- **ATT&CK analytics** for tactic/technique coverage, weak coverage, and high-risk gaps
- **Export engine** for Splunk SPL, Sigma, Sentinel KQL, and Elastic EQL outputs
- **GitHub-backed source sync** for pulling a repo directory into the active analysis workspace
- **Local run scripts** for one-command startup without containers

For the editable source diagram, see `docs/architecture-diagram.html`.

## Quick start

### Requirements
- `uv`
- Node.js + npm
- GNU Make

### One-command startup

```bash
git clone https://github.com/egrexsec/DetLab-DAC.git
cd DetLab-DAC
cp .env.example .env
make setup
make up
```

Open:
- `http://127.0.0.1:3000`

### What starts
- `api` → FastAPI backend on `127.0.0.1:8000`
- `web` → Next.js UI on `127.0.0.1:3000`

### Useful commands

```bash
make setup
make ps
make logs
make down
make test
make web-build
make check
```

### Manual startup

```bash
uv sync --all-extras
uv run uvicorn detlab.api:app --host 127.0.0.1 --port 8000

cd web
npm install
npm run dev -- --hostname 127.0.0.1 --port 3000
```

The web app defaults its internal `/api` proxy target to `http://127.0.0.1:8000` for local runs.

### Environment defaults

`.env.example` includes:
- `DETLAB_ROOT_PATH=/api`
- `NEXT_PUBLIC_API_BASE_URL=/api`
- `DETLAB_SOURCE_REPO=egrexsec/cybersecurity-playbook`
- `DETLAB_SOURCE_REF=main`
- `DETLAB_SOURCE_SUBDIR=mde/advanced-hunting`

The `/api` root path keeps FastAPI docs and OpenAPI working correctly when the web app proxies local requests.
The GitHub source settings tell the API which repo directory to sync into the active analysis workspace.
`make up` waits for both the API and web app to respond before returning.

## Local tooling examples

Use the repo-local CLI via `uv run python -m detlab.main`.

```bash
uv run python -m detlab.main validate detections/windows/encoded_powershell.yml
uv run python -m detlab.main score detections --format markdown --output reports/scores.md
uv run python -m detlab.main attack report detections --format markdown --output reports/attack-coverage.md
uv run python -m detlab.main convert detections/windows/encoded_powershell.yml --target splunk --output exports/encoded_powershell.spl
```

## API examples

- `GET /api/detections/catalog`
- `GET /api/detections/{detection_id}/workspace`
- `GET /api/schema/domain`
- `POST /api/detections/inspect`
- `POST /api/detections/convert`

## Content model

### Detection packs

Sample packs:
- `examples/packs/windows-core/`
- `examples/packs/powershell/`
- `examples/packs/credential-access/`
- `examples/packs/persistence/`
- `examples/packs/cloudtrail/`
- `examples/packs/linux-core/`

### Knowledge lanes

Repository content lanes:
- `knowledge/detection-engineering/`
- `knowledge/threat-hunts/`
- `knowledge/incident-response-case-studies/`
- `knowledge/learning-paths/`
- `knowledge/labs/`
- `knowledge/aws-security-learning/`
- `knowledge/flaws-cloud/`
- `knowledge/flaws2-cloud/`

## Documentation framework

DetLab treats documentation as a first-class deliverable.

Core workflow:
**Learn → Lab → Investigate → Detect → Hunt → Document → Publish**

Every substantial artifact should answer:
1. What happened?
2. Why does it matter?
3. How would an attacker use it?
4. How would a defender detect it?
5. How would a defender investigate it?
6. How would a defender respond?
7. How can the organization improve?

Before publishing a DetLab entry, aim to include:
- technical accuracy
- ATT&CK mappings when applicable
- reusable queries when applicable
- detection opportunities
- investigation guidance
- lessons learned
- references
- diagrams when they materially improve understanding

Use the in-app templates and `/detections/templates` API templates to keep structure aligned across the web workbench, API, and repo-authored markdown content.

## Contributing

Ways to contribute:
- add new detections
- improve validation logic
- improve scoring, analytics, or conversion logic
- improve the website workflow
- improve documentation
- add test coverage
- add or refine DetLab knowledge-base entries under `knowledge/`

Development setup:

```bash
uv sync --all-extras
cd web && npm install
```

Run checks:

```bash
uv run ruff check .
uv run pytest
uv run python -m detlab.main validate detections
cd web && npm run build
```

Pull request guidelines:
- create focused pull requests
- add or update tests for code changes
- keep detection metadata complete
- document new commands, APIs, schema fields, or authoring flows
- use clear commit messages

## Security

Do not report vulnerabilities through public GitHub issues.

Report them privately to: `mell0wx@proton.me`

Include:
- a description of the issue
- steps to reproduce
- potential impact
- suggested remediation, if known

At this stage, only the latest version on the `main` branch is supported for security fixes.

## Why this matters

DetLab is designed so that:
- detections are validated
- detections are scored
- ATT&CK coverage is visible
- backend conversion exists
- documentation becomes part of the deliverable, not an afterthought
- the website becomes the main path for authoring and exploration

A detection engineer should understand the core workflow in under 2 minutes.
A new user should be able to boot the local stack in under 5 minutes with `make up`.
