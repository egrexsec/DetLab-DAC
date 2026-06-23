import test from 'node:test'
import assert from 'node:assert/strict'

import { capabilityPillars, contentLanes, getLaneBySlug, roadmap } from '../data/site-content.mjs'

test('content lanes expose the website sections expected by routing', () => {
  assert.deepEqual(
    contentLanes.map((lane) => lane.slug),
    ['detections', 'threat-hunts', 'investigations', 'learning-paths'],
  )
})

test('every lane carries template-direction copy for the future self-hosted starter goal', () => {
  for (const lane of contentLanes) {
    assert.equal(lane.futureTemplateNote.toLowerCase().includes('template') || lane.futureTemplateNote.toLowerCase().includes('starter'), true)
    assert.equal(typeof lane.repositoryArea, 'string')
    assert.ok(lane.entries.length >= 2)
  }
})

test('lane lookup resolves valid slugs and rejects unknown ones', () => {
  assert.equal(getLaneBySlug('threat-hunts')?.shortTitle, 'Threat Hunts')
  assert.equal(getLaneBySlug('missing-lane'), null)
})

test('homepage support data reflects a website-only direction', () => {
  assert.equal(capabilityPillars.length, 4)
  assert.equal(roadmap.some((item) => item.toLowerCase().includes('website-only')), true)
  assert.equal(roadmap.some((item) => item.toLowerCase().includes('template')), true)
})
