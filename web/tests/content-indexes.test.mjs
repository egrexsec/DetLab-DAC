import test from 'node:test'
import assert from 'node:assert/strict'

import {
  CONTENT_INDEX_DEFINITIONS,
  buildContentIndexCards,
  buildWorkbenchCreateHref,
  buildWorkbenchEditHref,
  getContentIndexNavigation,
} from '../config/content-indexes.mjs'

const samplePayload = {
  indexes: {
    hunts: {
      title: 'Threat Hunts',
      count: 1,
      items: [{ id: 'DET-4101', name: 'Rare IAM User Hunt', path: 'threat-hunts/aws/rare-iam-user-hunt.md', content_kind: 'hunt' }],
    },
    investigations: {
      title: 'Investigations',
      count: 1,
      items: [{ id: 'DET-4201', name: 'IAM PrivEsc Investigation', path: 'flaws-cloud/iam-privesc.md', content_kind: 'investigation' }],
    },
    forensics: {
      title: 'Forensic Writeups',
      count: 0,
      items: [],
    },
    learning_paths: {
      title: 'Learning Paths',
      count: 1,
      items: [{ id: 'DET-4301', name: 'IAM Foundations Learning Path', path: 'learning-paths/aws/iam-foundations.md', content_kind: 'learning_path' }],
    },
  },
}

test('content index definitions include all requested route slugs', () => {
  assert.deepEqual(
    CONTENT_INDEX_DEFINITIONS.map((entry) => entry.slug),
    ['threat-hunts', 'investigations', 'forensic-writeups', 'learning-paths'],
  )
})

test('getContentIndexNavigation returns hrefs for all content index pages', () => {
  const nav = getContentIndexNavigation()
  assert.equal(nav[0].href, '/content/threat-hunts')
  assert.equal(nav[1].href, '/content/investigations')
  assert.equal(nav[2].href, '/content/forensic-writeups')
  assert.equal(nav[3].href, '/content/learning-paths')
})

test('buildContentIndexCards maps API payload into route cards', () => {
  const cards = buildContentIndexCards(samplePayload)
  assert.equal(cards[0].slug, 'threat-hunts')
  assert.equal(cards[0].count, 1)
  assert.equal(cards[1].items[0].content_kind, 'investigation')
  assert.equal(cards[2].emptyState.includes('No forensic'), true)
  assert.equal(cards[3].items[0].path, 'learning-paths/aws/iam-foundations.md')
})

test('buildWorkbenchEditHref deep-links indexed content into the workbench editor', () => {
  assert.equal(
    buildWorkbenchEditHref({ path: 'threat-hunts/aws/rare-iam-user-hunt.md', content_kind: 'hunt' }),
    '/?edit=knowledge%2Fthreat-hunts%2Faws%2Frare-iam-user-hunt.md&tab=hunt#workbench',
  )
  assert.equal(
    buildWorkbenchEditHref({ path: 'learning-paths/aws/iam-foundations.md', content_kind: 'learning_path' }),
    '/?edit=knowledge%2Flearning-paths%2Faws%2Fiam-foundations.md&tab=learning#workbench',
  )
})

test('buildWorkbenchCreateHref deep-links each index into the correct new-artifact tab', () => {
  assert.equal(buildWorkbenchCreateHref('threat-hunts'), '/?tab=hunt#workbench')
  assert.equal(buildWorkbenchCreateHref('investigations'), '/?tab=investigation#workbench')
  assert.equal(buildWorkbenchCreateHref('forensic-writeups'), '/?tab=investigation#workbench')
  assert.equal(buildWorkbenchCreateHref('learning-paths'), '/?tab=learning#workbench')
})
