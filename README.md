# DetLab

DetLab is a website-only security documentation project.

The repo is now centered on a single Next.js website that presents:
- detections
- threat hunts
- investigations and DFIR notes
- learning paths and labs

The goal is clarity first: a visitor should understand the security work, documentation lanes, and intended audience quickly.

Longer term, the best patterns in this repo can be extracted into a self-hostable template that other practitioners or teams can spin up for their own security knowledge base.

## What the project is now

DetLab is no longer positioned as a hybrid app with a backend workbench.
It is a website-only repo.

That means:
- the product path is the website
- CI validates the website, not a backend runtime
- local development is just the Next.js app
- the repo narrative is about publishing security work, not operating an internal toolchain

## Website lanes

The site is organized around four lanes:

### 1. Detections
For publishing detection engineering content with ATT&CK context, telemetry assumptions, and follow-on investigation guidance.

Repository areas:
- `detections/`
- `knowledge/detection-engineering/`

### 2. Threat Hunts
For hypothesis-driven hunts, pivots, and downstream detection ideas.

Repository area:
- `knowledge/threat-hunts/`

### 3. Investigations and DFIR
For incident response case studies, cloud investigations, forensic summaries, and response lessons learned.

Repository areas:
- `knowledge/incident-response-case-studies/`
- `knowledge/flaws-cloud/`
- `knowledge/flaws2-cloud/`

### 4. Learning Paths and Labs
For structured learning tracks, lab notes, and portfolio-ready educational content.

Repository areas:
- `knowledge/learning-paths/`
- `knowledge/aws-security-learning/`
- `knowledge/labs/`

## Who it is for

Primary audiences:
- detection engineers
- threat hunters
- SOC analysts
- DFIR practitioners
- security engineers
- practitioners building a public portfolio of serious security work

## Local development

### Requirements
- Node.js
- npm

### Setup

```bash
git clone https://github.com/egrexsec/DetLab-DAC.git
cd DetLab-DAC/web
npm install
```

### Run locally

```bash
npm run dev
```

Then open:
- `http://127.0.0.1:3000`

### Production build

```bash
cd web
npm run build
npm run start
```

### Tests

```bash
cd web
npm test
```

## Repository structure

Key paths:
- `web/` — the Next.js website
- `detections/` — detection content and examples
- `knowledge/` — hunts, investigations, learning paths, and labs
- `docs/images/` — project screenshots and visual assets

## Contribution guidance

Good contributions include:
- improving the website copy, structure, and information architecture
- adding or refining security content in the existing lanes
- improving visual presentation and discoverability
- tightening the repo so it stays website-only and template-friendly

When contributing:
- keep changes aligned to the website-only direction
- avoid reintroducing backend/runtime coupling as part of the main product path
- prefer changes that make the repo easier to understand, fork, and extend

## Security and disclosure

Do not report vulnerabilities through public GitHub issues.

Report them privately to:
- `mell0wx@proton.me`

Include:
- a short description of the issue
- reproduction steps
- expected impact
- suggested remediation if known

## Future direction

DetLab has two clear phases:

### Current phase
A polished website for publishing security documentation across detections, hunts, investigations, and learning.

### Later phase
A reusable self-hostable template that others can fork and adapt for:
- personal security portfolios
- internal team knowledge bases
- blue-team documentation hubs
- public detection/hunt/investigation libraries

The current repo should optimize for the first phase without blocking the second.
