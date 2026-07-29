const generatedQueryFields = new Set(['spl', 'kql', 'eql', 'esql'])

function requireGeneratedQueryField(field) {
  if (!generatedQueryFields.has(field)) {
    throw new Error(`Unsupported generated query field: ${field}`)
  }
}

export function recordGeneratedQuerySource(sources, field, source) {
  requireGeneratedQueryField(field)
  return { ...sources, [field]: source }
}

export function forgetGeneratedQuerySource(sources, field) {
  requireGeneratedQueryField(field)
  const next = { ...sources }
  delete next[field]
  return next
}

export function staleGeneratedQueryFields(sources, currentSource, queries) {
  return Object.entries(sources)
    .filter(([field, source]) => (
      generatedQueryFields.has(field)
      && source !== currentSource
      && typeof queries[field] === 'string'
      && queries[field].trim()
    ))
    .map(([field]) => field)
    .sort()
}
