export function getRepoActionDefinitions() {
  return [
    { id: 'save', label: 'Save to Repo', description: 'Write the current artifact into detections/ or knowledge/.' },
    { id: 'diff', label: 'Diff Preview', description: 'Preview the current uncommitted repo diff before committing.' },
    { id: 'commit-message', label: 'Commit Message', description: 'Capture the exact Git commit message for the current repo changes.' },
    { id: 'commit', label: 'Commit from UI', description: 'Stage and commit the current repo changes from the workbench.' },
  ]
}

export function summarizeRepoStatus(status) {
  const branch = status?.branch || 'unknown'
  const changed = status?.changed_files || []
  if (status?.clean || changed.length === 0) {
    return `${branch} is clean — no uncommitted repo changes.`
  }
  const noun = changed.length === 1 ? 'change' : 'changes'
  const preview = changed.slice(0, 3).map((item) => item.path).join(', ')
  return `${branch} has ${changed.length} uncommitted ${noun}: ${preview}`
}
