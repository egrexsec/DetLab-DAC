import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const testDir = path.dirname(fileURLToPath(import.meta.url))
const pagePath = path.resolve(testDir, '../app/page.tsx')
const contentRoutePath = path.resolve(testDir, '../app/content/[slug]/page.tsx')

test('homepage copy positions DetLab as a detection-engineering site', () => {
  const page = fs.readFileSync(pagePath, 'utf8')

  assert.equal(page.includes('Detection engineering documentation, without the extra lanes.'), true)
  assert.equal(page.includes('Splunk SPL'), true)
  assert.equal(page.toLowerCase().includes('no hunt lane'), true)
})

test('content route embeds the detection workbench directly', () => {
  const contentRoute = fs.readFileSync(contentRoutePath, 'utf8')

  assert.equal(contentRoute.includes('LaneWorkbench'), true)
  assert.equal(contentRoute.includes('GitHub save enabled'), true)
  assert.equal(contentRoute.includes('Packaging standard'), true)
})
