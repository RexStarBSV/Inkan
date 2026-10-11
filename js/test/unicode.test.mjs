// Text inputs and the Unicode database (SPEC §1, E14): reject a text input containing a code point
// this runtime's Unicode database leaves unassigned, or return exactly the pinned result; never
// anything else. Vectors: ../test-vectors/unicode-vectors.json.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { sha256, bytesToHex } from '../src/sha256.js'
import { inkanSeed, unicodeVersion } from '../src/seed.js'
import { resolveKind } from '../src/seal.js'
import { fingerprintHex } from '../src/fingerprint.js'

// Errata whose vectors this port does not satisfy yet. Their vectors are reported as SKIPPED, by
// name, never counted as passes; remove an erratum here in the commit that implements it.
const PENDING_ERRATA = new Set([])

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, '..', '..', 'test-vectors', 'unicode-vectors.json'), 'utf8'))
const text = (points = []) => String.fromCodePoint(...points.map((h) => parseInt(h, 16)))
const inputs = (v) => text(v.data) + text(v.kind) + text(v.adopter)
// E14's test with the database this runtime's normaliser uses: Cn, except the noncharacters.
const unassignedHere = (s) => [...s].some((c) => /\p{Cn}/u.test(c) && !/\p{Noncharacter_Code_Point}/u.test(c))

function result (v) {
  if (v.adopter) {
    return { fingerprint_hex: fingerprintHex(new TextEncoder().encode(v.payload_utf8), text(v.adopter), v.fingerprint_version) }
  }
  const kind = text(v.kind)
  return { code: 'ik1' + bytesToHex(sha256(inkanSeed(text(v.data), kind))), resolve: resolveKind(kind) }
}
const pinned = (v) => Object.fromEntries(['code', 'resolve', 'fingerprint_hex']
  .filter((k) => k in v.result_if_accepted).map((k) => [k, v.result_if_accepted[k]]))

test('accept vectors give exactly the pinned result', () => {
  for (const v of doc.accept) assert.deepEqual(result(v), pinned(v), v.name)
})

// A Unicode version, '16.0' or '16.0.0', as three numbers; compare(a, b) < 0 when a is older.
const version = (s) => [...s.split('.').map(Number), 0, 0].slice(0, 3)
const compare = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2]

test('either/or vectors this runtime\'s Unicode database can answer', (t) => {
  const seen = unicodeVersion()           // null: older than every sentinel the port knows
  assert.ok(doc.either_or.length > 0, 'unicode-vectors.json has no either/or vectors')
  let answered = 0
  for (const v of doc.either_or) {
    // A database at least as new as the vector's newest code point knows every code point in it.
    const tooOld = seen === null || compare(version(seen), version(v.newest_code_point_assigned_in)) < 0
    assert.equal(unassignedHere(inputs(v)), tooOld, v.name)
    if (tooOld) continue                  // the reject branch: see the test below
    const got = result(v)
    assert.deepEqual(got, pinned(v), v.name)
    assert.ok(!(v.never || []).includes(got.code ?? got.fingerprint_hex), v.name + ' gave a known-wrong result')
    answered++
  }
  // A database older than Unicode 16.0 lacks a code point in every either/or vector. Reported as
  // SKIPPED, with the reason, never counted as a pass.
  if (answered === 0) {
    t.skip(`this runtime's Unicode database (${seen ?? 'older than 3.0'}) lacks a code point in every ` +
      'either/or vector; all of them are in the reject branch')
  }
})

test('inputs with unassigned code points are rejected', (t) => {
  const due = [...doc.either_or, ...doc.reject_unless_assigned].filter((v) => unassignedHere(inputs(v)))
  assert.ok(due.length > 0)
  if (PENDING_ERRATA.has(doc.rule)) {
    t.skip(`${doc.rule} not implemented in this port yet; ${due.length} vectors pending: ${due.map((v) => v.name).join(', ')}`)
    return
  }
  for (const v of due) assert.throws(() => result(v), v.name)
})

test('the kind derivation rejects the same kinds', () => {
  // SPEC §4.2: a kind the anchor rejects is rejected by the seal derivation too. Checked on its own,
  // because result() computes the anchor first and would throw before reaching resolveKind.
  const kinds = [...doc.either_or, ...doc.reject_unless_assigned]
    .filter((v) => v.kind && v.kind.length && unassignedHere(text(v.kind))).map((v) => text(v.kind))
  assert.ok(kinds.length > 0)
  for (const k of kinds) assert.throws(() => resolveKind(k), /E14/, JSON.stringify(k))
  assert.deepEqual(resolveKind('nc:\uFDD0@t3'), [24, 4, 23])
  assert.deepEqual(resolveKind('caf\u00e9@t2'), [48, 3, 1])
})

test('the Unicode version the check uses is the runtime\'s', () => {
  const v = unicodeVersion()
  console.log('# Unicode database (E14 check and NFC): ' + v)
  assert.match(v, /^\d+\.\d+$/)
  // Node reports ICU's Unicode version; the probe reads the regular-expression tables. They agree.
  if (process.versions.unicode) assert.equal(v, process.versions.unicode.split('.').slice(0, 2).join('.'))
})
