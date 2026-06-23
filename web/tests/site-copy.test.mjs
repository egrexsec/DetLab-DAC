import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const testDir = path.dirname(fileURLToPath(import.meta.url))
const pagePath = path.resolve(testDir, '../app/page.tsx')
const contentRoutePath = path.resolve(testDir, '../app/content/[slug]/page.tsx')

test('homepage copy positions DetLab as website-only with future template potential', () => {
  const page = fs.readFileSync(pagePath, 'utf8')

  assert.equal(page.includes('website-only'), true)
  assert.equal(page.toLowerCase().includes('self-hostable template'), true)
  assert.equal(page.includes('FastAPI'), false)
  assert.equal(page.includes('Inspect & Score'), false)
})

test('content route is static and no longer depends on API config or workbench components', () => {
  const contentRoute = fs.readFileSync(contentRoutePath, 'utf8')

  assert.equal(contentRoute.includes('fetch('), false)
  assert.equal(contentRoute.includes('/api'), false)
  assert.equal(contentRoute.includes('ContentIndexPage'), false)
})
