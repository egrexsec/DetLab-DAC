# Canonical detection schema

DetLab detection files now use a stronger canonical schema for cross-platform mappings.

## Goals

The schema is designed to keep one detection anchored around:
- a single canonical behavior statement
- normalized ATT&CK context
- explicit telemetry requirements
- one or more platform/query-language mappings
- operational guidance for triage, validation, and response

## Top-level model

```yaml
schema_version: 2.0.0
kind: detection
id: DET-XXXX
title: Example detection
description: Short detection summary
status: draft
severity: medium
author: mell0wx
domain:
  - endpoint
platforms:
  - windows
canonical_detection:
  intent: Detect the behavior in plain language
  attack:
    primary:
      technique: T1059.001
      tactic: execution
    related: []
  logsource:
    product: windows
    service: sysmon
  analytics:
    logic:
      selection: {}
      condition: selection
    selectors:
      - canonical_field: process.command_line
        platform_field: CommandLine
        operator: contains_any
        values:
          - -enc
    condition: selection
telemetry_requirements:
  primary_logsource:
    product: windows
    service: sysmon
  data_sources: []
  cloud_telemetry: []
mappings:
  - mapping_id: sigma-core
    platform: sigma
    language: sigma
    status: available
    purpose: canonical
    query:
      logsource:
        product: windows
        service: sysmon
      detection:
        selection: {}
        condition: selection
    field_mappings:
      - canonical_field: process.command_line
        platform_field: CommandLine
        operator: contains_any
    notes: Sigma-style source mapping
workflow_guidance:
  triage_steps: []
  investigation_steps: []
  escalation_guidance: []
  hunt_suggestions: []
supporting_artifacts:
  artifacts: []
  velociraptor_artifacts: []
related_detections: []
response_actions: []
validation:
  tests: []
  falsepositives: []
references: []
```

## Why this is stronger

Compared with the old flat shape, this schema separates:
- **canonical_detection**: the platform-agnostic intent and analytic model
- **telemetry_requirements**: what data is needed to make the detection work
- **mappings**: concrete implementations across Sigma, SPL, KQL, EQL, ES|QL, and future dialects
- **workflow_guidance / validation**: how to operate and trust the detection

That gives you one home for the detection concept and many homes for execution-specific translations.

## Mapping rules

Each `mappings[]` entry should carry:
- `mapping_id`: stable repo identifier
- `platform`: product or ecosystem (`splunk`, `microsoft-sentinel`, `elastic`, `sigma`)
- `language`: actual detection/query language (`spl`, `kql`, `eql`, `esql`, `sigma`)
- `status`: readiness (`draft`, `available`, `validated`, etc.)
- `query`: the implementation itself
- `field_mappings`: how the platform fields map back to canonical fields
- `notes`: translation caveats, parser assumptions, or known gaps

## Canonical fields

Use stable normalized fields when possible, for example:
- `process.name`
- `process.parent.name`
- `process.command_line`
- `event.code`
- `event.action`
- `file.path`
- `user.name`
- `source.ip`
- `cloud.service`

Platform-specific fields stay inside `mappings[]`, while canonical fields describe the underlying behavioral requirement.

## Repo usage

Current detection files under `detections/` now follow this schema.

Representative cross-platform examples include:
- `detections/windows/suspicious_encoded_powershell.yaml`
- `detections/windows/office_spawned_powershell.yaml`
- `detections/aws/create_access_key.yml`

These examples show how one canonical detection can carry multiple implementation mappings without losing operational context.
