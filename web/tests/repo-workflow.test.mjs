import test from 'node:test'
import assert from 'node:assert/strict'

import { getRepoActionDefinitions, summarizeRepoStatus } from '../config/repo-workflow.mjs'

test('repo workflow exposes save diff and commit actions in UI order', () => {
  const actions = getRepoActionDefinitions()
  assert.deepEqual(actions.map((action) => action.id), ['save', 'diff', 'commit-message', 'commit'])
})

test('summarizeRepoStatus reports clean and dirty states for workbench messaging', () => {
  assert.equal(summarizeRepoStatus({ branch: 'main', clean: true, changed_files: [] }), 'main is clean — no uncommitted repo changes.')
  assert.equal(
    summarizeRepoStatus({ branch: 'main', clean: false, changed_files: [{ path: 'knowledge/threat-hunts/new-hunt.md', status: 'M' }] }),
    'main has 1 uncommitted change: knowledge/threat-hunts/new-hunt.md',
  )
})
