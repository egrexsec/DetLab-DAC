# In-Platform Detection Creation Workflow Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Let a user create a detection inside the DetLab web app, submit it to the backend, inspect validation results, view score/risk/recommendations, and optionally preview converted output for Sigma, Splunk, KQL, or EQL.

**Architecture:** Add a small request/response contract in the FastAPI layer for single-detection processing instead of relying only on filesystem scans. Keep the core business logic in reusable backend helpers that validate a detection payload into the existing `Detection` Pydantic model, then feed that validated object into the existing scoring and export functions. On the frontend, add a focused “Create & Inspect Detection” workflow to the current Next.js dashboard with a YAML editor, submit action, result panels, and optional conversion preview tabs.

**Tech Stack:** Python, FastAPI, Pydantic v2, pytest, Next.js App Router, React, TypeScript.

---

### Task 1: Add failing API contract tests for single-detection processing

**Objective:** Define the backend behavior before implementation.

**Files:**
- Modify: `tests/test_api.py`
- Reference: `detlab/api.py`

**Step 1: Write failing tests**

Add tests for:
- `POST /detections/inspect` with a valid detection payload returns:
  - `valid: true`
  - normalized detection payload
  - score block
  - recommendations list
  - empty `errors`
- `POST /detections/inspect` with an invalid detection payload returns:
  - status `422`
  - `valid: false`
  - validation error details
- `POST /detections/convert` with `target=splunk|kql|eql|sigma` returns converted text for a valid detection payload.
- `POST /detections/convert` with unsupported target returns `400`.

**Step 2: Run targeted tests to verify failure**

Run:
`cd /root/repo-audit/DetLab-DAC && . .venv/bin/activate && pytest tests/test_api.py -q`

Expected: FAIL because the endpoints and contract do not exist yet.

**Step 3: Implement minimal backend contract**

Files likely touched:
- `detlab/api.py`
- optionally new helper module: `detlab/processing.py`

Implement:
- request model for raw detection payload + optional conversion target
- helper that validates payload with `Detection.model_validate(...)`
- helper that returns score data via `score_detection(...)`
- helper that dispatches conversion via existing export functions

**Step 4: Re-run targeted tests to verify pass**

Run:
`cd /root/repo-audit/DetLab-DAC && . .venv/bin/activate && pytest tests/test_api.py -q`

Expected: PASS.

**Step 5: Commit**

```bash
cd /root/repo-audit/DetLab-DAC
git add tests/test_api.py detlab/api.py detlab/processing.py
git commit -m "feat: add single-detection processing api"
```

---

### Task 2: Add backend unit tests for validation/processing helpers

**Objective:** Keep the single-detection workflow logic reusable and testable outside the API route handlers.

**Files:**
- Create: `tests/test_processing.py`
- Create or modify: `detlab/processing.py`
- Reference: `detlab/models.py`, `detlab/scoring.py`, `detlab/splunk.py`, `detlab/kql.py`, `detlab/eql.py`, `detlab/sigma_export.py`

**Step 1: Write failing tests**

Add tests for helper functions such as:
- `inspect_detection_payload(payload)` returns a normalized detection dict and score block.
- invalid payload returns structured validation errors.
- `convert_detection_payload(payload, "splunk")` returns Splunk content containing the detection metadata.
- unsupported conversion target raises a predictable exception.

**Step 2: Run targeted tests to verify failure**

Run:
`cd /root/repo-audit/DetLab-DAC && . .venv/bin/activate && pytest tests/test_processing.py -q`

Expected: FAIL because helper module/functions do not yet exist or are incomplete.

**Step 3: Implement minimal helper logic**

Suggested API:
- `inspect_detection_payload(payload: dict) -> dict`
- `convert_detection_payload(payload: dict, target: str) -> dict`

Return shape should be stable and frontend-oriented, for example:
- `valid`
- `errors`
- `detection`
- `score`
- `conversion` (for convert path)

**Step 4: Re-run targeted tests to verify pass**

Run:
`cd /root/repo-audit/DetLab-DAC && . .venv/bin/activate && pytest tests/test_processing.py -q`

Expected: PASS.

**Step 5: Commit**

```bash
cd /root/repo-audit/DetLab-DAC
git add tests/test_processing.py detlab/processing.py
git commit -m "feat: add detection processing helpers"
```

---

### Task 3: Add failing frontend tests/build contract for the create-and-inspect workflow

**Objective:** Define the UI surface needed to drive the new backend behavior.

**Files:**
- Modify: `web/app/page.tsx`
- Optional create: `web/components/detection-workbench.tsx`
- Optional create: `web/components/conversion-preview.tsx`

**Step 1: Write the smallest failing contract first**

Because the repo currently does not show a frontend test harness, use a build/type contract as the first RED step:
- add the intended component usage/imports first in a way that fails until the new component or types exist.
- alternatively, add a small component file import to `page.tsx` before creating the file.

**Step 2: Run frontend build to verify failure**

Run:
`cd /root/repo-audit/DetLab-DAC/web && npm run build`

Expected: FAIL because the new UI contract is referenced but not implemented.

**Step 3: Implement minimal frontend workflow**

Add a new section with:
- YAML textarea preloaded with a sample detection
- `Inspect & Score` button → calls `POST /api/detections/inspect`
- result panels for:
  - validation state
  - parsed detection metadata
  - score breakdown
  - recommendations
- optional conversion selector/button for:
  - Sigma
  - Splunk
  - KQL
  - EQL
- conversion preview panel with copy-friendly text block
- clear error state for backend validation failures

**Step 4: Re-run frontend build to verify pass**

Run:
`cd /root/repo-audit/DetLab-DAC/web && npm run build`

Expected: PASS.

**Step 5: Commit**

```bash
cd /root/repo-audit/DetLab-DAC
git add web/app/page.tsx web/components/
git commit -m "feat: add in-platform detection inspection workflow"
```

---

### Task 4: Integrate the workflow into the running stack and verify live behavior

**Objective:** Prove the feature works end to end in the actual app, not just in unit tests.

**Files:**
- Verify runtime against the local FastAPI + Next.js app files.

**Step 1: Run backend and full test suite**

Run:
`cd /root/repo-audit/DetLab-DAC && . .venv/bin/activate && pytest -q`

Expected: PASS.

**Step 2: Rebuild frontend and services**

Run:
`cd /root/repo-audit/DetLab-DAC && ./scripts/start.sh`

Expected: services rebuild successfully.

**Step 3: Verify API contract live**

Run a live POST with sample payload to:
- `/api/detections/inspect`
- `/api/detections/convert`

Expected:
- inspect returns validation + score block
- convert returns converted text for the selected target

**Step 4: Verify browser workflow live**

Use browser tooling to confirm:
- YAML editor is visible
- Inspect action loads score/recommendation results
- conversion preview renders
- invalid YAML/path shows a clear error state

**Step 5: Commit**

```bash
cd /root/repo-audit/DetLab-DAC
git add -A
git commit -m "test: verify in-platform detection workflow end to end"
```

---

### Task 5: Tighten docs for the new workflow

**Objective:** Make the feature usable by a new visitor without reading code.

**Files:**
- Modify: `README.md`

**Step 1: Write failing documentation expectation**

Treat the missing README flow as the gap:
- the README currently explains CLI and dashboard, but not in-platform detection creation.

**Step 2: Add minimal docs**

Document:
- where to open the workflow in the UI
- what fields the sample YAML needs
- what inspect/score/convert do
- what export targets are supported

**Step 3: Verify docs match real behavior**

Run:
- `pytest -q`
- `cd web && npm run build`
- manual/live check against the running app

**Step 4: Commit**

```bash
cd /root/repo-audit/DetLab-DAC
git add README.md
git commit -m "docs: document in-platform detection workflow"
```

---

## Notes and constraints

- Keep the first version stateless: no database, no saved drafts, no auth.
- Reuse the existing `Detection` Pydantic model rather than inventing a second schema.
- Prefer one stable API response contract over frontend-specific ad hoc reshaping in React.
- Return structured validation errors the UI can render directly.
- Keep conversion preview text in-memory; do not require filesystem export for the first workflow.
- If frontend component sprawl grows, split `web/app/page.tsx` into focused components after the feature is green.

## Verification checklist

- [ ] `POST /detections/inspect` exists and is tested
- [ ] `POST /detections/convert` exists and is tested
- [ ] invalid detection payloads surface clear structured errors
- [ ] UI can submit a detection payload without page reload
- [ ] UI renders score, risk, recommendations, and conversion preview
- [ ] `pytest -q` passes
- [ ] `cd web && npm run build` passes
- [ ] live local browser verification succeeds
