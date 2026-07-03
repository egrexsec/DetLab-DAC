import test from 'node:test'
import assert from 'node:assert/strict'

import {
  buildLaneArtifact,
  buildRepoFilePath,
  getWorkbenchConfig,
  slugify,
  supportedWorkbenchLanes,
} from '../data/workbench-config.mjs'

test('workbench supports only the detection lane', () => {
  assert.deepEqual(supportedWorkbenchLanes, ['detections'])
  assert.equal(getWorkbenchConfig('threat-hunts'), null)
})

test('slugify creates stable GitHub-safe path segments', () => {
  assert.equal(slugify(' Encoded PowerShell / Follow-On '), 'encoded-powershell-follow-on')
})

test('detection artifacts render canonical schema frontmatter and multi-language sections', () => {
  const artifact = buildLaneArtifact({
    laneSlug: 'detections',
    title: 'Encoded PowerShell Follow-On',
    summary: 'Detect suspicious PowerShell encoded invocations.',
    tags: 'windows, powershell',
    author: 'mell0wx',
    technique: 'T1059.001',
    tactic: 'execution',
    severity: 'high',
    status: 'draft',
    platform: 'windows, endpoint',
    telemetry: 'Sysmon Event ID 1 with command-line logging enabled.',
    sigma: 'title: Encoded PowerShell',
    spl: 'index=win powershell',
    kql: 'DeviceProcessEvents | where FileName =~ "powershell.exe"',
    eql: 'process where process.name == "powershell.exe"',
    esql: 'from logs-* | where process.name == "powershell.exe"',
    otherLanguage: 'XQL',
    otherQuery: 'dataset = xdr_data | filter event_type = PROCESS',
    triage: 'Review parent process\nReview user context',
    validation: 'Run Atomic Red Team test',
    falsePositives: 'Administrative automation',
    references: 'https://attack.mitre.org/techniques/T1059/001/',
  })

  assert.equal(artifact.filename, 'encoded-powershell-follow-on.md')
  assert.equal(artifact.commitMessage.includes('Add detection brief:'), true)
  assert.equal(artifact.content.includes('schema_version: 2.0.0'), true)
  assert.equal(artifact.content.includes('canonical_schema: detlab/cross-platform-detection'), true)
  assert.equal(artifact.content.includes('mapping_catalog:'), true)
  assert.equal(artifact.content.includes("mapping_id: sigma-core"), true)
  assert.equal(artifact.content.includes("mapping_id: xql-custom"), true)
  assert.equal(artifact.content.includes('## Canonical detection'), true)
  assert.equal(artifact.content.includes('## Telemetry requirements'), true)
  assert.equal(artifact.content.includes('## Sigma'), true)
  assert.equal(artifact.content.includes('## Splunk SPL'), true)
  assert.equal(artifact.content.includes('## Microsoft Sentinel KQL'), true)
  assert.equal(artifact.content.includes('## Elastic EQL'), true)
  assert.equal(artifact.content.includes('## Elastic ES|QL'), true)
  assert.equal(artifact.content.includes('## XQL'), true)
  assert.equal(artifact.content.includes('Sysmon Event ID 1'), true)
})

test('repo file path builder keeps nested directories stable', () => {
  assert.equal(buildRepoFilePath('knowledge/detection-engineering', 'encoded-powershell-follow-on.md'), 'knowledge/detection-engineering/encoded-powershell-follow-on.md')
})
