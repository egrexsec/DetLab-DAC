const targetFields = {
  splunk: 'spl',
  'elastic-eql': 'eql',
  'elastic-esql': 'esql',
  'microsoft-kusto': 'kql',
}

export function conversionFieldForTarget(target) {
  return targetFields[target] ?? null
}

export function normalizeConversionApiBaseUrl(value) {
  let parsed
  try {
    parsed = new URL(String(value).trim())
  } catch {
    throw new Error('Conversion API URL must be an absolute HTTP(S) URL.')
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Conversion API URL must be an absolute HTTP(S) URL.')
  }
  if (parsed.username || parsed.password) {
    throw new Error('Conversion API URL must not contain embedded credentials.')
  }
  if (parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error('Conversion API URL must contain only an origin, without a path, query, or fragment.')
  }
  return parsed.origin
}

export async function requestSigmaConversion({ baseUrl, source, target, fetchImpl = fetch }) {
  const origin = normalizeConversionApiBaseUrl(baseUrl)
  const response = await fetchImpl(`${origin}/v1/convert`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source, target }),
  })
  const payload = await response.json().catch(() => ({}))
  if (!response.ok) {
    const message = payload?.detail?.message || `Conversion API returned HTTP ${response.status}.`
    throw new Error(message)
  }
  if (!Array.isArray(payload.outputs) || !payload.outputs.length || !payload.provenance) {
    throw new Error('Conversion API returned an incomplete response.')
  }
  return payload
}
