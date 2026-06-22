# DetLab Knowledge Management & Documentation Framework

DetLab treats documentation as a first-class deliverable.

Nothing is complete until it has been documented.

Core workflow:

**Learn → Lab → Investigate → Detect → Hunt → Document → Publish**

## Purpose

This framework ensures that every DetLab activity becomes a reusable artifact for:

- learning notes
- operational runbooks
- detection references
- threat hunting guides
- incident response case studies
- portfolio-ready project evidence

The goal is consistency, repeatability, professionalism, and long-term knowledge retention.

## Required content lanes

Every learning module, AWS workshop, flaws.cloud challenge, flaws2.cloud investigation, threat hunt, detection, project, or research activity should be documented under one of these lanes:

- `knowledge/learning-paths/`
- `knowledge/labs/`
- `knowledge/incident-response-case-studies/`
- `knowledge/threat-hunts/`
- `knowledge/detection-engineering/`
- `knowledge/aws-security-learning/`
- `knowledge/flaws-cloud/`
- `knowledge/flaws2-cloud/`

## Documentation standards

Every document should answer:

1. What happened?
2. Why does it matter?
3. How would an attacker use it?
4. How would a defender detect it?
5. How would a defender investigate it?
6. How would a defender respond?
7. How can the organization improve?

If those questions are not answered, the document is incomplete.

## Portfolio readiness checklist

Before publishing a DetLab entry:

- verify technical accuracy
- include ATT&CK mappings when applicable
- include reusable queries when applicable
- include detection opportunities
- include investigation guidance
- include lessons learned
- include references
- include diagrams when they materially improve understanding

The finished artifact should be understandable by:

- SOC analysts
- incident responders
- threat hunters
- cloud security engineers
- hiring managers
- future versions of yourself

## Authoring workflow

1. Pick the content lane that best fits the activity.
2. Start from the matching DetLab template.
3. Fill in the required sections before calling the work complete.
4. Add evidence, queries, ATT&CK context, and lessons learned.
5. Convert the work into a publishable artifact once it is technically accurate.

## Template source of truth

DetLab ships reusable authoring templates through the `/detections/templates` API and the in-app workbench.

Available templates include:

- markdown detection
- learning path
- lab
- incident response case study
- threat hunt
- detection engineering
- AWS security learning
- flaws.cloud case study

Use those templates to keep structure aligned across the CLI, API, web workbench, and repo-authored markdown content.
