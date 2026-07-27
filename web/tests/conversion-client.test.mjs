import test from 'node:test'
import { readFile } from 'node:fs/promises'
import assert from 'node:assert/strict'

import {
  conversionFieldForTarget,
  normalizeConversionApiBaseUrl,
  requestSigmaConversion,
} from '../data/conversion-client.mjs'

const workbenchSource = await readFile(new URL('../components/lane-workbench.tsx', import.meta.url), 'utf8')

test('workbench rejects a conversion response when Sigma changes in flight', () => {
  assert.match(workbenchSource, /useRef/)
  assert.match(workbenchSource, /submittedSource/)
  assert.match(workbenchSource, /latestSigmaRef\.current\s*!==\s*submittedSource/)
  assert.match(workbenchSource, /requestGeneration/)
  assert.match(workbenchSource, /conversion response is stale/i)
})

test('conversion API base URL accepts absolute HTTP(S) without credentials', () => {
  assert.equal(normalizeConversionApiBaseUrl('https://convert.example.test/'), 'https://convert.example.test')
  assert.equal(normalizeConversionApiBaseUrl('http://localhost:8000'), 'http://localhost:8000')
  assert.throws(() => normalizeConversionApiBaseUrl('/api'), /absolute HTTP/)
  assert.throws(() => normalizeConversionApiBaseUrl('https://user:pass@example.test'), /credentials/)
})

test('conversion targets map only to supported workbench fields', () => {
  assert.equal(conversionFieldForTarget('splunk'), 'spl')
  assert.equal(conversionFieldForTarget('elastic-eql'), 'eql')
  assert.equal(conversionFieldForTarget('elastic-esql'), 'esql')
  assert.equal(conversionFieldForTarget('microsoft-kusto'), 'kql')
  assert.equal(conversionFieldForTarget('unknown'), null)
})

test('conversion client sends Sigma and returns provenance', async () => {
  const calls = []
  const fakeFetch = async (url, options) => {
    calls.push({ url, options })
    return {
      ok: true,
      json: async () => ({
        target: 'splunk',
        language: 'spl',
        outputs: ['index=main powershell'],
        source_sha256: 'a'.repeat(64),
        provenance: {
          spec_version: '1.0.0',
          source_sha256: 'a'.repeat(64),
          converter: { name: 'pysigma-backend-splunk', version: '2.1.0' },
        },
      }),
    }
  }

  const result = await requestSigmaConversion({
    baseUrl: 'https://convert.example.test/',
    source: 'title: example',
    target: 'splunk',
    fetchImpl: fakeFetch,
  })

  assert.equal(calls[0].url, 'https://convert.example.test/v1/convert')
  assert.deepEqual(JSON.parse(calls[0].options.body), { source: 'title: example', target: 'splunk' })
  assert.equal(result.outputs[0], 'index=main powershell')
  assert.equal(result.provenance.converter.version, '2.1.0')
})

test('conversion client surfaces structured API errors', async () => {
  const fakeFetch = async () => ({
    ok: false,
    status: 422,
    json: async () => ({ detail: { code: 'invalid_sigma', message: 'Sigma source is invalid' } }),
  })
  await assert.rejects(
    requestSigmaConversion({ baseUrl: 'http://localhost:8000', source: 'bad', target: 'splunk', fetchImpl: fakeFetch }),
    /Sigma source is invalid/,
  )
})
