from pathlib import Path

from detlab.domain import build_detection_workspace, load_detections

SAMPLE_THREAT_HUNT = """---
id: DET-3201
name: Unapproved IAM User Creation Hunt
status: draft
severity: medium
author: mell0wx
attack:
  technique: T1136.003
  tactic: persistence
---

# Unapproved IAM User Creation Hunt

This hunt checks for IAM users created outside approved administrative workflows.

## Hunt Hypothesis
- An attacker may be creating IAM users outside approved administrative workflows.

## Data Sources
- CloudTrail
- IAM

## Queries
```sql
SELECT eventtime, useridentity.arn, requestparameters.userName
FROM cloudtrail_logs
WHERE eventname = 'CreateUser';
```

## Findings
- Record true positives, benign changes, and unanswered questions.

## False Positives
- Approved break-glass or automation workflows.

## Recommendations
- Require change correlation and stronger alert enrichment.

## Detection Opportunities
- Alert on CreateUser events from unusual principals.

## Follow-up Hunts
- Review CreateAccessKey and AttachUserPolicy activity for the same actors.
"""

SAMPLE_INCIDENT = """---
id: DET-3202
name: Suspicious IAM User Creation Incident
status: draft
severity: high
author: mell0wx
attack:
  technique: T1136.003
  tactic: persistence
---

# Suspicious IAM User Creation Incident

This incident case study documents the investigation of suspicious IAM account creation.

## Initial Indicators
- Alert from CloudTrail monitoring on CreateUser.

## Investigation Process
- Review CloudTrail actor, source IP, and follow-on IAM changes.

## Evidence Collected
- CreateUser event record
- Attached policy history

## Root Cause Analysis
- The actor used an overprivileged automation role.

## Containment Actions
- Disable the created user and revoke active sessions.

## Eradication Actions
- Remove unauthorized keys and policies.

## Recovery Actions
- Validate logging coverage and restore approved access patterns.

## Future Detection Opportunities
- Build correlation for CreateUser plus AttachUserPolicy.
"""


def test_markdown_framework_entries_infer_content_kind_and_queries(tmp_path: Path):
    hunt_dir = tmp_path / 'knowledge' / 'threat-hunts' / 'aws'
    hunt_dir.mkdir(parents=True)
    (hunt_dir / 'iam-user-creation.md').write_text(SAMPLE_THREAT_HUNT, encoding='utf-8')

    detections = load_detections(str(tmp_path / 'knowledge'))

    assert len(detections) == 1
    detection = detections[0]
    assert detection.detection.selection['ContentKind'] == 'hunt'
    assert detection.detection.selection['QueryLanguage'] == 'sql'
    assert 'CreateUser' in detection.detection.selection['QueryText']
    assert detection.logsource.product == 'aws'
    assert detection.logsource.service == 'cloudtrail'
    assert detection.response_actions[0].title == 'Require change correlation and stronger alert enrichment.'
    assert detection.hunt_suggestions[0].name == 'Review CreateAccessKey and AttachUserPolicy activity for the same actors.'


def test_incident_response_entries_map_response_and_investigation_sections(tmp_path: Path):
    incident_dir = tmp_path / 'knowledge' / 'incident-response-case-studies' / 'aws'
    incident_dir.mkdir(parents=True)
    (incident_dir / 'iam-user-creation-incident.md').write_text(SAMPLE_INCIDENT, encoding='utf-8')

    detections = load_detections(str(tmp_path / 'knowledge'))

    assert len(detections) == 1
    detection = detections[0]
    assert detection.detection.selection['ContentKind'] == 'incident_response'
    assert any(step.step == 'Review CloudTrail actor, source IP, and follow-on IAM changes.' for step in detection.investigation_steps)
    assert detection.artifacts[0].name == 'CreateUser event record'
    assert {action.title for action in detection.response_actions} == {
        'Disable the created user and revoke active sessions.',
        'Remove unauthorized keys and policies.',
        'Validate logging coverage and restore approved access patterns.',
    }

    workspace = build_detection_workspace(detection.id, str(tmp_path / 'knowledge'))

    assert workspace is not None
    assert workspace['overview']['detection_logic']['selection']['ContentKind'] == 'incident_response'
    assert {action['title'] for action in workspace['response_actions']} == {
        'Disable the created user and revoke active sessions.',
        'Remove unauthorized keys and policies.',
        'Validate logging coverage and restore approved access patterns.',
    }
