// Canary records (SPEC §8, E23): each signed record, parsed from its wire text, gets exactly the
// pinned verdict. Vectors: ../test-vectors/canary-vectors.json.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { status, MalformedCanaryInput } from '../src/canary.js'

// Errata whose vectors this port does not satisfy yet. Their cases are reported as SKIPPED, by name,
// never counted as passes; remove an erratum here in the commit that implements it.
const PENDING_ERRATA = new Set([])

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, '..', '..', 'test-vectors', 'canary-vectors.json'), 'utf8'))
const now = Date.parse(doc.now)

// The verdict for a case read from its wire text, as the vectors define it; or, with `parsed`, for
// the object JSON.parse makes of it (the canonical-bytes rule then has no bytes to check).
function verdict (c, parsed = false) {
  try {
    return status(parsed ? JSON.parse(c.record_json) : c.record_json, c.signature_der_hex,
      c.pubkey_hex || doc.pubkey_hex, now, doc.max_age_days)
  } catch (e) {
    return e instanceof MalformedCanaryInput ? 'MALFORMED' : 'UNSUPPORTED'
  }
}

test('cases every verifier already meets', () => {
  const due = doc.cases.filter((c) => !PENDING_ERRATA.has(c.rule))
  assert.ok(due.length > 0)
  for (const c of due) assert.equal(verdict(c), c.expect, c.name)
})

test('cases decided by the input rules', (t) => {
  const cases = doc.cases.filter((c) => c.rule !== null)
  const pending = cases.filter((c) => PENDING_ERRATA.has(c.rule))
  if (pending.length) {
    t.skip(`E23 not implemented in this port yet; ${pending.length} cases pending: ${pending.map((c) => c.name).join(', ')}`)
    return
  }
  for (const c of cases) assert.equal(verdict(c), c.expect, c.name)
})

test('a parsed record gets the same verdict, and the wire form may be bytes', () => {
  const utf8 = new TextEncoder()
  for (const c of doc.cases) {
    const want = c.name === 'record-not-canonical' ? 'OK' : c.expect
    assert.equal(verdict(c, true), want, c.name + ' (parsed)')
    let got
    try {
      got = status(utf8.encode(c.record_json), c.signature_der_hex, c.pubkey_hex || doc.pubkey_hex, now, doc.max_age_days)
    } catch (e) { got = e instanceof MalformedCanaryInput ? 'MALFORMED' : 'UNSUPPORTED' }
    assert.equal(got, c.expect, c.name + ' (bytes)')
  }
  const tv7 = doc.cases.find((c) => c.name === 'tv7')
  const bom = new Uint8Array([0xEF, 0xBB, 0xBF, ...utf8.encode(tv7.record_json)])
  assert.equal(status(bom, tv7.signature_der_hex, doc.pubkey_hex, now, doc.max_age_days), 'MALFORMED')
  assert.equal(status(new Uint8Array([0x7B, 0xFF, 0x7D]), tv7.signature_der_hex, doc.pubkey_hex, now), 'MALFORMED')
})

test('a key or signature that is not text reads MALFORMED (SPEC §8 E23)', () => {
  const tv7 = doc.cases.find((c) => c.name === 'tv7')
  const sig = tv7.signature_der_hex, pub = doc.pubkey_hex, utf8 = new TextEncoder()
  for (const [s, p] of [[utf8.encode(sig), pub], [sig, utf8.encode(pub)], [null, pub], [sig, undefined], [3006020101020101, pub]]) {
    assert.equal(status(tv7.record_json, s, p, now, doc.max_age_days), 'MALFORMED', String(s).slice(0, 12))
  }
})
