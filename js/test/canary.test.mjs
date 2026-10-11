// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Test suite, not part of the Apache-2.0 verification path -- NOTICE covers the library only,
// mirroring python/tests/.
//
// REGRESSION + COVERAGE (2026-08-04). `npm test` ran parity, seal-parity and normalization and
// nothing else: `grep -c canary js/test/*.mjs` was 0,0,0. An adopter installing the npm package and
// running the package's own gate got ZERO canary and ZERO secp256k1 coverage. That coverage existed
// only in js/tools/check_web_verifier.mjs, which is not part of the published surface -- so the
// entire attack surface of the MALFORMED-vs-INVALID defect (SPEC §8 E11) was untested here.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { status, verify, MalformedCanaryInput } from '../src/canary.js'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'test-vectors', 'vectors.json'), 'utf8'))

function find (o, key) {
  if (o && typeof o === 'object') {
    if (key in o) return o
    for (const v of Object.values(o)) { const r = find(v, key); if (r) return r }
  }
  return null
}
const fx = find(vectors, 'signature_der_hex')
const AT = Date.parse('2026-08-01T00:00:00Z')

test('pinned canary vector verifies OK', () => {
  assert.ok(fx, 'the pinned canary vector must exist for this suite to mean anything')
  assert.equal(status(fx.record, fx.signature_der_hex, fx.pubkey_hex, AT), 'OK')
})

test('a real key with a wrong-but-parseable signature is INVALID, not MALFORMED', () => {
  const altered = { ...fx.record, seq: fx.record.seq + 1 }
  assert.equal(status(altered, fx.signature_der_hex, fx.pubkey_hex, AT), 'INVALID')
})

test('unparseable input is MALFORMED, never INVALID (SPEC §8 E11)', () => {
  for (const [label, sig, pub] of [
    ['non-hex signature', 'zzzz', fx.pubkey_hex],
    ['truncated DER', fx.signature_der_hex.slice(0, 20), fx.pubkey_hex],
    ['empty signature', '', fx.pubkey_hex],
    ['non-hex pubkey', fx.signature_der_hex, 'nothex']
  ]) {
    assert.equal(status(fx.record, sig, pub, AT), 'MALFORMED', label)
  }
})

test('verify throws a typed error a caller can branch on', () => {
  assert.throws(() => verify(fx.record, 'zzzz', fx.pubkey_hex), MalformedCanaryInput)
})

test('an unknown record version propagates, so a caller can say UNSUPPORTED (E2)', () => {
  assert.throws(() => verify({ ...fx.record, v: 2 }, fx.signature_der_hex, fx.pubkey_hex),
    /unsupported canary record version/)
})

test('staleness is separate from validity', () => {
  const late = Date.parse('2027-01-01T00:00:00Z')
  assert.equal(status(fx.record, fx.signature_der_hex, fx.pubkey_hex, late), 'STALE')
})

test('a record of the wrong shape is MALFORMED (SPEC §8 E13)', () => {
  const cases = [
    ['extra field', { ...fx.record, note: 'x' }],
    ['missing field', Object.fromEntries(Object.entries(fx.record).filter(([k]) => k !== 'block_hash'))],
    ['wrong type', { ...fx.record, seq: '1' }],
    ['not an object', []]
  ]
  for (const [label, rec] of cases) {
    assert.equal(status(rec, fx.signature_der_hex, fx.pubkey_hex, AT), 'MALFORMED', label)
  }
})

test('python and js agree on every status this suite exercises', () => {
  // the parity that matters: both ports must classify identically, or an adopter switching
  // languages silently changes what their users are told
  assert.equal(status(fx.record, fx.signature_der_hex, fx.pubkey_hex, AT), 'OK')
  assert.equal(status({ ...fx.record, seq: fx.record.seq + 1 }, fx.signature_der_hex, fx.pubkey_hex, AT), 'INVALID')
  assert.equal(status(fx.record, 'zzzz', fx.pubkey_hex, AT), 'MALFORMED')
})

// --- SPEC §4 E4: unencodable kinds -----------------------------------------------------------
import { inkanSeed } from '../src/seed.js'

test('an unencodable kind is REJECTED, not substituted (SPEC §4 E4)', () => {
  const hi = '\ud800'
  const lo = '\udfff'
  for (const bad of [hi, lo, 'id' + hi, hi + 'id']) {
    assert.throws(() => inkanSeed(new TextEncoder().encode('x'), bad), /E4/,
      'substitution would collapse every malformed kind onto one anchor')
  }
  // a well-formed surrogate pair is ordinary text
  assert.ok(inkanSeed(new TextEncoder().encode('x'), '\ud83d\ude00'))
  // and unencodable DATA is rejected on the same principle
  assert.throws(() => inkanSeed(hi, 'identity'), /E4/)
})
