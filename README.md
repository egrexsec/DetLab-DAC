# DetLab-DAC

DetLab-DAC is a detection-engineering documentation repo.

It is now intentionally scoped to one job:
- document detections cleanly
- preserve the detection story around each rule
- capture implementations across multiple query and rule languages such as Sigma, SPL, KQL, EQL, and ES|QL
- keep the output easy to publish, review, and reuse

Everything outside that scope has been removed from the product framing.
No threat-hunt lane, no forensics lane, no DFIR lane, and no learning/lab lane.

## Assessment

Before this refactor, the repo was **not packaged tightly enough** for a pure detection-engineering use case because:
- the site and README split attention across detections, threat hunts, investigations, DFIR, labs, and learning paths
- the workbench supported multiple non-detection lanes instead of one strong detection workflow
- the default detection authoring path produced a single YAML artifact, but it did not document parallel implementations across SPL, KQL, EQL, Sigma, and related dialects
- repository structure and copy made the project feel like a generic security knowledge site instead of a focused detection catalog

After this refactor, the repo is packaged around a single detection-engineering publishing model.

## What the project is now

DetLab-DAC is a static Next.js site plus repo-backed detection content.

The repo is organized around three detection-specific layers:

1. **Canonical detections**
   - `detections/`
   - executable or near-executable rule content
   - platform-focused examples such as Windows and AWS detections

2. **Detection documentation**
   - `knowledge/detection-engineering/`
   - markdown briefs that explain detection intent, telemetry, ATT&CK mapping, triage guidance, validation notes, and multiple implementation dialects

3. **Curated detection packs**
   - `examples/packs/`
   - grouped examples for packaging detections by platform or theme

## Website focus

The website now presents a single lane:
- **Detection Engineering**

That lane is built to document detections across:
- Sigma
- Splunk SPL
- Microsoft Sentinel KQL
- Elastic EQL
- Elastic ES|QL
- other implementation-specific variants when needed

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

`npm run build` produces a static export in `web/out/`.
`npm run start` serves that exported site locally on port `3000` so you can review the exact deployable artifact.

### Tests

```bash
cd web
npm test
```

## Detection documentation standard

A strong DetLab detection entry should capture:
- what behavior is being detected
- why the behavior matters
- telemetry prerequisites and source assumptions
- ATT&CK tactic and technique context
- one canonical analytic model plus one or more implementation mappings
- field-level translation between canonical fields and platform-native fields
- false-positive expectations
- triage steps
- validation approach
- references or linked source material

Schema reference:
- `docs/schema/canonical-detection-schema.md`

## Workbench behavior

The website workbench is detection-only.
It builds a markdown detection brief in the browser and can save it to GitHub with a user-supplied token.

Default save target:
- `knowledge/detection-engineering/`

The generated artifact is meant for documentation-first detection engineering, not as a replacement for every runnable platform-native rule file under `detections/`.

## Repository structure

Key paths:
- `web/` — the Next.js website
- `detections/` — canonical detection files and examples
- `knowledge/detection-engineering/` — detection documentation briefs
- `examples/packs/` — grouped detection packs
- `docs/` — project and deployment docs

## Contribution guidance

Good contributions include:
- adding new detections
- tightening detection metadata and ATT&CK coverage
- improving query translations across Sigma, SPL, KQL, EQL, and ES|QL
- improving triage and validation guidance
- improving the packaging of detection packs and documentation

When contributing:
- keep the repo detection-engineering-only
- avoid reintroducing hunts, investigations, forensics, labs, or general knowledge-base sprawl
- prefer structures that help a detection engineer compare and publish logic across query languages

## Security and disclosure

Do not report vulnerabilities through public GitHub issues.

Report them privately to:
- `mell0wx@proton.me`

Include:
- a short description of the issue
- reproduction steps
- expected impact
- suggested remediation if known
