import test from 'node:test'
import assert from 'node:assert/strict'

import { capabilityPillars, contentLanes, getLaneBySlug, roadmap } from '../data/site-content.mjs'

test('content lanes expose only the detection-engineering route', () => {
  assert.deepEqual(
    contentLanes.map((lane) => lane.slug),
    ['detections'],
  )
})

test('detection lane carries focused packaging copy', () => {
  const lane = contentLanes[0]

  assert.equal(lane.title, 'Detection Engineering')
  assert.equal(lane.repositoryArea.includes('detections/'), true)
  assert.equal(lane.repositoryArea.includes('knowledge/detection-engineering/'), true)
  assert.equal(lane.futureTemplateNote.toLowerCase().includes('detection'), true)
  assert.ok(lane.entries.length >= 3)
})

test('lane lookup resolves detections and rejects unknown lanes', () => {
  assert.equal(getLaneBySlug('detections')?.shortTitle, 'Detections')
  assert.equal(getLaneBySlug('missing-lane'), null)
})

test('homepage support data reflects a detection-only, multi-language direction', () => {
  assert.equal(capabilityPillars.length, 4)
  assert.equal(capabilityPillars.some((item) => item.description.toLowerCase().includes('sigma')), true)
  assert.equal(roadmap.some((item) => item.toLowerCase().includes('detection workbench')), true)
  assert.equal(roadmap.some((item) => item.toLowerCase().includes('spl')), true)
})
