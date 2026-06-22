# DetLab Workbench Pivot

## Updated product positioning

**DetLab**

Detection Engineering Workbench

Build, validate, score, convert, test, and visualize detections from a single platform.

Primary audience:
- Detection Engineers
- Threat Hunters
- SOC Analysts
- Security Engineers
- DFIR Analysts

Non-primary V1 audience:
- Enterprise GRC teams
- Compliance teams
- Detection marketplaces
- Multi-tenant governance platforms

## Dashboard redesign recommendations

Top navigation:
- Dashboard
- Detections
- Coverage
- Scoring
- Packs
- Reports

Core dashboard pages and sections:
1. **Overview**
   - Total Detections
   - Coverage %
   - Average Detection Score
   - ATT&CK Techniques Covered
   - Packs Installed
   - Validation Failures
2. **ATT&CK Coverage**
   - flagship heatmap
   - coverage by tactic
   - coverage by technique
   - coverage gaps
   - high-risk gaps
3. **Detection Scoring**
   - sortable score table
   - coverage, specificity, documentation, false positive risk, overall score
4. **Detection Packs**
   - installed packs
   - pack health
   - pack coverage
   - pack metadata
   - pack validation status
5. **Reports**
   - validation health
   - score distribution
   - weak detections
   - platform coverage

## ATT&CK heatmap specification

Purpose:
- be the flagship visual for demos and recruiter reviews
- show detection coverage density by ATT&CK tactic

Inputs:
- ATT&CK tactic per detection
- ATT&CK technique per detection
- detection count per tactic

Visual behavior:
- 12-tactic grid
- gray = no coverage
- amber = weak coverage
- green = strong coverage

Supporting context:
- coverage percent across ATT&CK tactics
- weak coverage list
- high-risk gaps list
- platform breakdown

## Detection score engine specification

Per-detection fields:
- Coverage Score
- Specificity Score
- Metadata Score
- Maintainability Score
- False Positive Risk
- Overall Score

Current implementation direction:
- coverage rewards ATT&CK metadata and tests
- specificity rewards richer selection logic
- metadata rewards documentation completeness
- maintainability rewards status, references, and test evidence
- false positive risk penalizes broad or poorly documented detections

UI display:
- Detection Name
- Coverage
- Specificity
- Documentation
- False Positive Risk
- Overall Score

## Detection pack specification

Each pack should include:
- `pack.yml`
- descriptive metadata
- supported platforms
- focus areas
- example detections
- validation status
- pack report output

Current sample packs:
- Windows Core
- PowerShell
- Credential Access
- Persistence
- CloudTrail
- Linux Core

Pack goals:
- easier demos
- easier onboarding
- easier library segmentation
- quicker coverage storytelling

## Deployment simplification recommendations

Required V1 deployment shape:
- local FastAPI + Next.js startup scripts
- Makefile
- `.env.example`
- one-command startup

Current recommended path:
```bash
git clone https://github.com/egrexsec/DetLab-DAC.git
cd DetLab-DAC
cp .env.example .env
make up
```

Design rules:
- no container orchestrator requirement
- no enterprise bootstrap dependency
- local demo should work from repo root
- web should proxy API cleanly via `/api`

## Missing screenshot checklist

Required screenshots:
- [x] Dashboard Overview
- [x] ATT&CK Heatmap
- [x] Detection Score View
- [x] Detection Pack View

Nice-to-have follow-ons:
- [ ] export preview view
- [ ] single detection drill-down
- [ ] architecture diagram

## Next 30-day roadmap

### Week 1
- finish product-positioning cleanup across docs and UI copy
- harden pack metadata and pack coverage summaries
- add richer screenshot set for recruiting/demo use

### Week 2
- add detection-level detail page with score explanation and validation findings
- expose export previews for SPL, KQL, EQL, and Sigma

### Week 3
- expand example packs for Linux, Credential Access, and CloudTrail with real sample detections
- improve ATT&CK technique-level drill-downs

### Week 4
- add pack comparison and weak-detection triage workflow
- refine scoring heuristics and regression tests

## GitHub repository description

DetLab is a detection engineering workbench for validating, scoring, converting, testing, and visualizing detections with ATT&CK coverage and reusable detection packs.
