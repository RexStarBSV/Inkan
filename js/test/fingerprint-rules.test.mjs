// Tamper-fingerprint inputs (SPEC §7, E21, E22): accepted adopter names and versions give exactly the
// pinned fingerprint; rejected ones are refused before hashing.
// Vectors: ../test-vectors/fingerprint-vectors.json.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { fingerprintHex } from '../src/fingerprint.js'

// Errata whose vectors this port does not satisfy yet. Their vectors are reported as SKIPPED, by
// name, never counted as passes; remove an erratum here in the commit that implements it.
const PENDING_ERRATA = new Set([])

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, '..', '..', 'test-vectors', 'fingerprint-vectors.json'), 'utf8'))
const text = (points) => String.fromCodePoint(...points.map((h) => parseInt(h, 16)))
const fp = (v) => fingerprintHex(new TextEncoder().encode(v.payload_utf8), text(v.adopter), v.version)

test('accepted names and versions give exactly the pinned fingerprint', () => {
  for (const v of doc.accept) assert.equal(fp(v), v.fingerprint_hex, v.name)
})

test('rejected names and versions are refused', (t) => {
  for (const v of doc.reject.filter((v) => !PENDING_ERRATA.has(v.rule))) assert.throws(() => fp(v), v.name)
  const pending = doc.reject.filter((v) => PENDING_ERRATA.has(v.rule))
  if (pending.length) {
    t.skip(`${[...new Set(pending.map((v) => v.rule))].sort().join('/')} not implemented in this port yet; ` +
      `${pending.length} vectors pending: ${pending.map((v) => v.name).join(', ')}`)
  }
})

test('versions: positive integers only, a BigInt beyond 10^21', async () => {
  const { checkVersion } = await import('../src/fingerprint.js')
  for (const ok of [1, 2, 10, 2 ** 53, 1e20]) assert.equal(checkVersion(ok), String(ok))
  assert.equal(checkVersion(10n ** 30n), '1' + '0'.repeat(30))
  for (const bad of [0, -1, 1.5, NaN, Infinity, 1e21, true, '1', null, undefined, 0n, -1n, [1]]) {
    assert.throws(() => checkVersion(bad), /E22/, String(bad))
  }
})
