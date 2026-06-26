import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const testDir = path.dirname(fileURLToPath(import.meta.url))
const pagePath = path.resolve(testDir, '../app/page.tsx')
const contentRoutePath = path.resolve(testDir, '../app/content/[slug]/page.tsx')

test('homepage copy positions DetLab as a GitHub-backed authoring site', () => {
  const page = fs.readFileSync(pagePath, 'utf8')

  assert.equal(page.includes('GitHub'), true)
  assert.equal(page.toLowerCase().includes('self-hostable template'), true)
  assert.equal(page.includes('client-side workbench'), true)
})

test('content route embeds the lane workbench for supported operational lanes', () => {
  const contentRoute = fs.readFileSync(contentRoutePath, 'utf8')

  assert.equal(contentRoute.includes('LaneWorkbench'), true)
  assert.equal(contentRoute.includes('GitHub save enabled'), true)
  assert.equal(contentRoute.includes("lane.slug === 'detections' || lane.slug === 'threat-hunts' || lane.slug === 'investigations'"), true)
})
