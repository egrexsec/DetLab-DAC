import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const source = await readFile(new URL('../app/content/[slug]/page.tsx', import.meta.url), 'utf8')

test('Next 16 dynamic content route awaits params before resolving the lane', () => {
  assert.match(source, /export default async function ContentLanePage/)
  assert.match(source, /params:\s*Promise<\{ slug: string \}>/)
  assert.match(source, /const \{ slug \} = await params/)
  assert.match(source, /getLaneBySlug\(slug\)/)
})
