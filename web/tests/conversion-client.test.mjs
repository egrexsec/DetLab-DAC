import test from 'node:test'
import assert from 'node:assert/strict'

import {
  conversionFieldForTarget,
  normalizeConversionApiBaseUrl,
  requestSigmaConversion,
} from '../data/conversion-client.mjs'
import { runConversionRequest } from '../data/conversion-request.mjs'
import {
  forgetGeneratedQuerySource,
  recordGeneratedQuerySource,
  staleGeneratedQueryFields,
} from '../data/conversion-provenance.mjs'

function deferred() {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function conversionHarness() {
  let generation = 0
  let state = { status: 'idle', result: null, message: '' }

  return {
    start(source, request) {
      const requestGeneration = ++generation
      state = { status: 'converting', result: null, message: `converting ${source}` }
      return runConversionRequest({
        source,
        generation: requestGeneration,
        request,
        isCurrent: (candidateGeneration) => candidateGeneration === generation,
        publishSuccess: (result) => {
          state = { status: 'converted', result, message: `converted ${source}` }
        },
        publishError: (error) => {
          state = { status: 'error', result: null, message: error.message }
        },
      })
    },
    snapshot() {
      return state
    },
  }
}

test('old success after a new request starts cannot mutate shared conversion state', async () => {
  const oldResponse = deferred()
  const newResponse = deferred()
  const harness = conversionHarness()
  const oldRequest = harness.start('old sigma', () => oldResponse.promise)
  harness.start('new sigma', () => newResponse.promise)
  const stateAfterNewStart = harness.snapshot()

  oldResponse.resolve({ target: 'splunk', outputs: ['old output'] })
  await oldRequest

  assert.deepEqual(harness.snapshot(), stateAfterNewStart)
  newResponse.resolve({ target: 'splunk', outputs: ['new output'] })
})

test('old error after a newer request succeeds cannot mutate shared conversion state', async () => {
  const oldResponse = deferred()
  const newResponse = deferred()
  const harness = conversionHarness()
  const oldRequest = harness.start('old sigma', () => oldResponse.promise)
  const newRequest = harness.start('new sigma', () => newResponse.promise)

  newResponse.resolve({ target: 'splunk', outputs: ['new output'] })
  await newRequest
  const stateAfterNewSuccess = harness.snapshot()
  oldResponse.reject(new Error('old request failed'))
  await oldRequest

  assert.deepEqual(harness.snapshot(), stateAfterNewSuccess)
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

test('regenerating one target cannot make other generated targets current', () => {
  let sources = {}
  sources = recordGeneratedQuerySource(sources, 'spl', 'old sigma')
  sources = recordGeneratedQuerySource(sources, 'kql', 'old sigma')

  sources = recordGeneratedQuerySource(sources, 'spl', 'new sigma')

  assert.deepEqual(
    staleGeneratedQueryFields(sources, 'new sigma', { spl: 'new spl', kql: 'old kql' }),
    ['kql'],
  )
})

test('failed retry leaves every generated output from the edited source stale', () => {
  let sources = {}
  sources = recordGeneratedQuerySource(sources, 'spl', 'old sigma')
  sources = recordGeneratedQuerySource(sources, 'kql', 'old sigma')

  assert.deepEqual(
    staleGeneratedQueryFields(sources, 'new sigma', { spl: 'old spl', kql: 'old kql' }),
    ['kql', 'spl'],
  )
})

test('manual query edits remove generated provenance for that field', () => {
  let sources = recordGeneratedQuerySource({}, 'spl', 'old sigma')
  sources = forgetGeneratedQuerySource(sources, 'spl')

  assert.deepEqual(staleGeneratedQueryFields(sources, 'new sigma', { spl: 'manual spl' }), [])
})
