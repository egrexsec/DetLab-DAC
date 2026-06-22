from copy import deepcopy

import yaml

from detlab.contracts import CANONICAL_MODEL_VERSION
from detlab.eql import export_eql_detection
from detlab.kql import export_kql_detection
from detlab.models import Detection
from detlab.sigma_export import export_sigma_detection
from detlab.splunk import export_splunk_detection

_TEMPLATE_DETECTION_PAYLOAD = {
    "id": "DET-1000",
    "title": "Suspicious PowerShell Network Retrieval",
    "description": "Detects suspicious PowerShell retrieving remote content and launching follow-on execution.",
    "logsource": {
        "product": "windows",
        "service": "sysmon",
    },
    "attack": {
        "technique": "T1059.001",
        "tactic": "execution",
    },
    "severity": "high",
    "status": "experimental",
    "author": "DetLab",
    "domain": ["endpoint"],
    "platforms": ["windows"],
    "references": [
        "https://attack.mitre.org/techniques/T1059/001/",
    ],
    "falsepositives": [
        "Administrative automation that legitimately retrieves remote content.",
    ],
    "tests": [
        {
            "name": "Atomic validation",
            "source": "atomic-red-team",
            "test_id": "template-1",
        }
    ],
    "detection": {
        "selection": {
            "EventID": 1,
            "Image|endswith": "\\powershell.exe",
            "CommandLine|contains": [
                "Invoke-WebRequest",
                "DownloadString",
            ],
        },
        "condition": "selection",
    },
}

_MARKDOWN_TEMPLATE = """---
id: DET-1001
name: Markdown Suspicious PowerShell Hunt
author: DetLab
status: experimental
severity: medium
domain:
  - endpoint
platforms:
  - windows
logsource:
  product: mde
  service: advanced_hunting
attack:
  technique: T1059.001
  tactic: execution
tests:
  - name: Analyst validation
    source: markdown-curation
    test_id: template-markdown-1
---

# Markdown Suspicious PowerShell Hunt

Detects suspicious PowerShell retrieving remote content and launching follow-on execution.

## Query
```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "DownloadString")
```
"""

_LEARNING_PATH_TEMPLATE = """---
id: DET-2001
content_kind: learning_path
name: IAM Foundations Learning Path
author: DetLab
status: draft
severity: low
domain:
  - cloud
platforms:
  - aws
logsource:
  product: aws
  service: cloudtrail
attack:
  technique: T1078.004
  tactic: persistence
data_sources:
  - name: AWS IAM documentation
    kind: cloud
    provider: aws
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction.html
---

# IAM Foundations Learning Path

A structured learning-path entry that turns study notes into reusable cloud-defense knowledge.

**Learn → Lab → Investigate → Detect → Hunt → Document → Publish**

## Overview
- Topic: IAM policy evaluation and administrative boundaries
- Objective: Explain how IAM decisions are made and where abuse opportunities appear
- Skills Developed: IAM analysis, permission scoping, cloud investigations
- Difficulty: Intermediate
- Prerequisites: Basic AWS identity concepts

## Key Concepts
- Explicit deny overrides allow
- Resource-based and identity-based policies combine during evaluation
- Least privilege reduces privilege-escalation blast radius

## Lessons Learned
- Policy simulation should be part of change review
- Overly broad wildcard permissions create long-tail risk
- Good learning notes should capture mistakes and defender takeaways

## Real-World Application
- Defenders use this to investigate unusual privilege changes and scoping mistakes
- Attackers abuse weak policy boundaries to escalate or persist
- Business impact includes unauthorized access to sensitive resources

## Detection Opportunities
- Monitor CreatePolicyVersion, PutUserPolicy, and AttachUserPolicy for drift from approved workflows

## References
- AWS IAM User Guide
- AWS policy evaluation logic
- Internal study notes or practice labs
"""

_LAB_TEMPLATE = """---
id: DET-2002
content_kind: lab
name: CloudTrail Tampering Validation Lab
author: DetLab
status: draft
severity: medium
domain:
  - cloud
platforms:
  - aws
logsource:
  product: aws
  service: cloudtrail
attack:
  technique: T1562.008
  tactic: defense-evasion
data_sources:
  - name: CloudTrail
    kind: cloud
    provider: aws
  - name: IAM
    kind: cloud
    provider: aws
references:
  - https://attack.mitre.org/techniques/T1562/008/
---

# CloudTrail Tampering Validation Lab

A hands-on lab entry for documenting technical experimentation and turning it into reusable defensive knowledge.

## Lab Summary
- Lab Name: CloudTrail tampering validation
- Platform: AWS
- Date Completed: YYYY-MM-DD
- Estimated Difficulty: Intermediate

## Objective
- Validate how logging changes appear in control-plane telemetry and what evidence defenders should capture

## Environment
- AWS Services: CloudTrail, IAM, S3, CloudWatch
- Tools Used: AWS CLI, Athena, DetLab
- Accounts: sandbox account identifiers
- Infrastructure: short-lived test trail and log bucket

## Walkthrough
- Document the setup, execution steps, teardown, and observed behavior in order

## Evidence
- Screenshots
- Commands
- Logs
- Findings

## Lessons Learned
- Capture what worked, what failed, and what you would do differently next time

## Detection Opportunities
- Create EventBridge or SIEM detections for StopLogging, DeleteTrail, and PutEventSelectors

## Threat Hunting Opportunities
- Hunt for correlated IAM changes and gaps in expected log-delivery patterns

## Defensive Recommendations
- Restrict trail administration and centralize immutable log storage
"""

_INCIDENT_RESPONSE_TEMPLATE = """---
id: DET-2003
content_kind: incident_response
name: Suspicious IAM User Creation Incident
author: DetLab
status: draft
severity: high
domain:
  - cloud
platforms:
  - aws
logsource:
  product: aws
  service: cloudtrail
attack:
  technique: T1136.003
  tactic: persistence
data_sources:
  - name: CloudTrail
    kind: cloud
    provider: aws
  - name: GuardDuty
    kind: cloud
    provider: aws
references:
  - https://attack.mitre.org/techniques/T1136/003/
---

# Suspicious IAM User Creation Incident

An incident-response case study template for documenting investigations as if they were real security incidents.

## Executive Summary
- Summarize what happened, why it mattered, and the responder conclusion

## Incident Overview
- Define the affected account, scope, and alert source

## Initial Indicators
- Capture the first alert, anomaly, or report that started the case

## Timeline of Events
- Record the key timestamps in order

## Investigation Process
- Document the query path, pivots, and evidence review steps

## Evidence Collected
- CloudTrail records, IAM artifacts, screenshots, or supporting logs

## Root Cause Analysis
- Explain the control failure or abuse path that enabled the activity

## Impact Assessment
- State what access, systems, or data were affected or at risk

## Containment Actions
- Immediate steps taken to limit ongoing exposure

## Eradication Actions
- Credentials, persistence, or configurations removed

## Recovery Actions
- Validation and restoration steps required to return to normal operations

## Lessons Learned
- What the incident improved in detections, response, or architecture

## Future Detection Opportunities
- Detections, hunts, or automations that should be added after the case
"""

_THREAT_HUNT_TEMPLATE = """---
id: DET-2004
content_kind: hunt
name: Unapproved IAM User Creation Hunt
author: DetLab
status: draft
severity: medium
domain:
  - cloud
platforms:
  - aws
logsource:
  product: aws
  service: cloudtrail
attack:
  technique: T1136.003
  tactic: persistence
data_sources:
  - name: CloudTrail
    kind: cloud
    provider: aws
  - name: GuardDuty
    kind: cloud
    provider: aws
references:
  - https://attack.mitre.org/techniques/T1136/003/
---

# Unapproved IAM User Creation Hunt

A proactive threat-hunt template for documenting hypotheses, queries, findings, and detection follow-up.

## Hunt Title
- Unapproved IAM user creation outside approved workflows

## Hunt Hypothesis
- An attacker may be creating IAM users outside approved administrative workflows

## ATT&CK Mapping
- T1136.003 Create Account: Cloud Account

## Data Sources
- CloudTrail
- GuardDuty
- Security Hub
- SIEM data

## Hunt Methodology
- State the scoping logic, filters, pivots, and prioritization rules

## Queries
```sql
SELECT eventtime, useridentity.arn, requestparameters.userName
FROM cloudtrail_logs
WHERE eventname = 'CreateUser';
```

## Findings
- Record true positives, benign admin activity, and unanswered questions

## False Positives
- Approved automation or break-glass workflows may generate expected events

## Recommendations
- Improve workflow tagging, approvals, and alert enrichment for IAM changes

## Detection Opportunities
- Build detections for CreateUser outside change windows or from unusual principals

## Follow-up Hunts
- Expand into access key creation, policy attachment, and role chaining behavior
"""

_DETECTION_ENGINEERING_TEMPLATE = """---
id: DET-2005
content_kind: detection
name: Detect Unauthorized IAM Access Key Creation
author: DetLab
status: draft
severity: high
domain:
  - cloud
platforms:
  - aws
logsource:
  product: aws
  service: cloudtrail
attack:
  technique: T1098
  tactic: persistence
data_sources:
  - name: CloudTrail
    kind: cloud
    provider: aws
references:
  - https://attack.mitre.org/techniques/T1098/
---

# Detect Unauthorized IAM Access Key Creation

A reusable detection-engineering template for storing logic, tuning notes, and validation guidance.

## Detection Name
- Detect unauthorized IAM access key creation

## Objective
- Identify persistence or privilege abuse through newly created IAM access keys

## Threat Scenario
- An attacker creates new access keys after compromising a principal with IAM write permissions

## ATT&CK Mapping
- T1098 Account Manipulation

## Data Sources
- CloudTrail
- IAM configuration metadata

## Detection Logic
```sigma
title: AWS IAM Access Key Creation
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: CreateAccessKey
  condition: selection
```

## Expected Results
- Capture successful CreateAccessKey events with actor, target user, and source IP context

## Tuning Guidance
- Exclude known automation roles only when they are tightly bounded and documented

## False Positives
- Approved key-rotation workflows or controlled break-glass operations

## Validation Process
- Replay a known-good event and verify alert routing, enrichment, and analyst context

## References
- MITRE ATT&CK
- AWS IAM and CloudTrail documentation
"""

_AWS_SECURITY_LEARNING_TEMPLATE = """---
id: DET-2006
content_kind: learning_path
name: AWS CloudTrail Security Study Note
author: DetLab
status: draft
severity: low
domain:
  - cloud
platforms:
  - aws
logsource:
  product: aws
  service: cloudtrail
attack:
  technique: T1562.008
  tactic: defense-evasion
data_sources:
  - name: CloudTrail
    kind: cloud
    provider: aws
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
---

# AWS CloudTrail Security Study Note

A study template for AWS Security Specialty preparation that keeps the material defender-focused and portfolio-usable.

## Service Overview
- Describe what the AWS service does and why it matters operationally

## Security Relevance
- Explain how defenders rely on the service during prevention, detection, and investigations

## Common Misconfigurations
- Document the mistakes most likely to create exposure or blind spots

## Threat Scenarios
- List realistic abuse cases or attacker objectives involving the service

## Detection Opportunities
- Capture what should be alerted on and what context is needed

## Investigation Workflow
- Describe how to pivot through the service during triage and scoping

## Response Workflow
- Note what containment or remediation actions are realistic for the service

## Key Exam Concepts
- Record what matters for certification and why it matters in practice

## Real-World Usage
- Tie the service back to production cloud operations and incident response
"""

_FLAWS_CLOUD_TEMPLATE = """---
id: DET-2007
content_kind: investigation
name: flaws.cloud Case Study Placeholder
author: DetLab
status: draft
severity: medium
domain:
  - cloud
platforms:
  - aws
logsource:
  product: aws
  service: cloudtrail
attack:
  technique: T1078.004
  tactic: initial-access
data_sources:
  - name: CloudTrail
    kind: cloud
    provider: aws
  - name: IAM
    kind: cloud
    provider: aws
  - name: S3
    kind: cloud
    provider: aws
references:
  - https://flaws.cloud/
---

# flaws.cloud Case Study Placeholder

A challenge-to-case-study template for turning flaws.cloud or flaws2.cloud work into professional cloud investigation content.

## Challenge Summary
- Summarize the scenario, objective, and why it matters beyond the challenge itself

## Objective
- State what the challenge required and what success looked like

## Attack Path
- Document the abuse chain from initial discovery through objective completion

## Discovery Process
- Show how the weakness was identified and validated

## Exploited Weakness
- Explain the misconfiguration, trust mistake, or design flaw that enabled the path

## Cloud Evidence
- Record the artifacts that prove the path or support the reconstruction

## CloudTrail Analysis
- Show which events matter and how they were queried

## IAM Analysis
- Capture principals, permissions, trust relationships, and escalation logic

## S3 Analysis
- Note relevant bucket policy, object exposure, or data-access evidence where applicable

## ATT&CK Mapping
- Map the activity to relevant techniques and tactics

## Detection Engineering Opportunities
- Describe alerts, detections, or enrichment that would surface the behavior earlier

## Threat Hunting Opportunities
- Describe follow-on hunts that would identify adjacent or repeated abuse

## Defensive Improvements
- State what to change to prevent or limit recurrence

## Lessons Learned
- Capture the defender value, not just the challenge flag or completion path
"""


def _template_detection() -> Detection:
    return Detection.model_validate(deepcopy(_TEMPLATE_DETECTION_PAYLOAD))


def build_detection_templates() -> dict[str, object]:
    detection = _template_detection()
    yaml_template = yaml.safe_dump(deepcopy(_TEMPLATE_DETECTION_PAYLOAD), sort_keys=False)
    return {
        "canonical_model_version": CANONICAL_MODEL_VERSION,
        "default_format": "yaml",
        "templates": {
            "yaml": {
                "label": "Canonical YAML",
                "description": "Primary DetLab authoring template for canonical detections.",
                "content": yaml_template,
            },
            "markdown": {
                "label": "Markdown detection",
                "description": "Markdown-authored detection or hunt template with frontmatter and query block.",
                "content": _MARKDOWN_TEMPLATE,
            },
            "learning_path": {
                "label": "Learning path",
                "description": "Template for turning study progress into reusable security knowledge.",
                "content": _LEARNING_PATH_TEMPLATE,
            },
            "lab": {
                "label": "Lab",
                "description": "Template for documenting hands-on exercises with evidence and follow-up opportunities.",
                "content": _LAB_TEMPLATE,
            },
            "incident_response": {
                "label": "Incident response case study",
                "description": "Template for documenting investigations like real security incidents.",
                "content": _INCIDENT_RESPONSE_TEMPLATE,
            },
            "threat_hunt": {
                "label": "Threat hunt",
                "description": "Template for proactive hunt hypotheses, queries, findings, and follow-up actions.",
                "content": _THREAT_HUNT_TEMPLATE,
            },
            "detection_engineering": {
                "label": "Detection engineering",
                "description": "Template for storing reusable detection logic, tuning, and validation guidance.",
                "content": _DETECTION_ENGINEERING_TEMPLATE,
            },
            "aws_security_learning": {
                "label": "AWS security learning",
                "description": "Template for AWS Security Specialty study notes with defender relevance.",
                "content": _AWS_SECURITY_LEARNING_TEMPLATE,
            },
            "flaws_cloud": {
                "label": "flaws.cloud case study",
                "description": "Template for converting flaws.cloud and flaws2.cloud work into professional case studies.",
                "content": _FLAWS_CLOUD_TEMPLATE,
            },
            "sigma": {
                "label": "Sigma",
                "description": "Rendered Sigma template that round-trips through DetLab normalization.",
                "content": export_sigma_detection(detection),
            },
            "splunk": {
                "label": "Splunk",
                "description": "Rendered Splunk SPL template that round-trips through DetLab normalization.",
                "content": export_splunk_detection(detection),
            },
            "kql": {
                "label": "KQL",
                "description": "Rendered KQL template that round-trips through DetLab normalization.",
                "content": export_kql_detection(detection),
            },
            "eql": {
                "label": "EQL",
                "description": "Rendered EQL template that round-trips through DetLab normalization.",
                "content": export_eql_detection(detection),
            },
        },
    }
