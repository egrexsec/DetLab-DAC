import test from 'node:test'
import assert from 'node:assert/strict'

import { getInternalApiOrigin, getProxyDestination } from '../config/api-origin.mjs'

test('getInternalApiOrigin defaults to localhost for local test runs', () => {
  assert.equal(getInternalApiOrigin({}), 'http://127.0.0.1:8000')
})

test('getInternalApiOrigin honors explicit override for container networking', () => {
  assert.equal(getInternalApiOrigin({ DETLAB_INTERNAL_API_ORIGIN: 'http://api:8000' }), 'http://api:8000')
})

test('getProxyDestination keeps the forwarded path placeholder', () => {
  assert.equal(getProxyDestination({ DETLAB_INTERNAL_API_ORIGIN: 'http://api:8000' }), 'http://api:8000/:path*')
})
