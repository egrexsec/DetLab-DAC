import test from 'node:test'
import assert from 'node:assert/strict'

import {
  buildLaneArtifact,
  buildRepoFilePath,
  getWorkbenchConfig,
  slugify,
  supportedWorkbenchLanes,
} from '../data/workbench-config.mjs'

test('workbench supports detections, threat hunts, and investigations', () => {
  assert.deepEqual(supportedWorkbenchLanes, ['detections', 'threat-hunts', 'investigations'])
  assert.equal(getWorkbenchConfig('learning-paths'), null)
})

test('slugify creates stable GitHub-safe path segments', () => {
  assert.equal(slugify(' Encoded PowerShell / Follow-On '), 'encoded-powershell-follow-on')
})

test('detection artifacts render YAML defaults and filenames', () => {
  const artifact = buildLaneArtifact({
    laneSlug: 'detections',
    title: 'Encoded PowerShell Follow-On',
    summary: 'Detect suspicious PowerShell encoded invocations.',
    body: '',
    tags: 'windows, powershell',
    author: 'mell0wx',
    technique: 'T1059.001',
    tactic: 'execution',
    severity: 'high',
    status: 'draft',
    platform: 'windows',
    hypothesis: '',
    scope: '',
  })

  assert.equal(artifact.filename, 'encoded-powershell-follow-on.yml')
  assert.equal(artifact.commitMessage.includes('Add detection:'), true)
  assert.equal(artifact.content.includes('technique: T1059.001'), true)
  assert.equal(artifact.content.includes('severity: high'), true)
})

test('markdown artifacts include lane-specific frontmatter', () => {
  const huntArtifact = buildLaneArtifact({
    laneSlug: 'threat-hunts',
    title: 'Rare IAM Role Assumption Hunt',
    summary: 'Track suspicious role assumption behavior.',
    body: '## Hunt steps\n1. Pivot on AssumeRole.',
    tags: 'aws, identity',
    author: 'mell0wx',
    technique: '',
    tactic: '',
    severity: '',
    status: '',
    platform: '',
    hypothesis: 'Rare role assumption may indicate credential misuse.',
    scope: '',
  })

  const investigationArtifact = buildLaneArtifact({
    laneSlug: 'investigations',
    title: 'Cloud Privilege Escalation Review',
    summary: 'Document cloud privilege escalation findings.',
    body: '## Executive summary\nThe actor escalated via IAM.',
    tags: 'cloud, ir',
    author: 'mell0wx',
    technique: '',
    tactic: '',
    severity: '',
    status: '',
    platform: '',
    hypothesis: '',
    scope: 'Production AWS account',
  })

  assert.equal(huntArtifact.content.includes('lane: threat-hunt'), true)
  assert.equal(huntArtifact.content.includes('hypothesis: Rare role assumption may indicate credential misuse.'), true)
  assert.equal(investigationArtifact.content.includes('lane: investigation'), true)
  assert.equal(investigationArtifact.content.includes('scope: Production AWS account'), true)
})

test('repo file path builder keeps nested directories stable', () => {
  assert.equal(buildRepoFilePath('knowledge/threat-hunts', 'rare-iam-role-assumption.md'), 'knowledge/threat-hunts/rare-iam-role-assumption.md')
})
