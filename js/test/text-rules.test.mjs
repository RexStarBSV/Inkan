// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Test suite, not part of the Apache-2.0 verification path.
//
// SPEC §4.2 and §7, E4: text that is not well-formed (an unpaired surrogate) is refused everywhere a
// string becomes bytes, never replaced. TextEncoder writes U+FFFD (EF BF BD) for an unpaired
// surrogate, so before this the kind derivation and the fingerprint mapped every malformed kind or
// adopter name onto the result of one well-formed string, while the anchor (fixed earlier) refused.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { resolveKind } from '../src/seal.js'
import { fingerprintHex } from '../src/fingerprint.js'

const bytes = new TextEncoder().encode('build-bytes-v1')

test('the kind derivation refuses an unpaired surrogate (E4)', () => {
  for (const bad of ['bad\uD800', 'bad\uDC00', '\uD800@t3', 'x:\uDFFF@t1']) {
    assert.throws(() => resolveKind(bad), /E4/, JSON.stringify(bad))
  }
  // the replacement character itself is ordinary text, and a well-formed pair is one code point
  assert.deepEqual(resolveKind('\u{1F600}'), [48, 1, 9])
  assert.deepEqual(resolveKind('x:\u{1F600}@t1'), [72, 2, 27])
  assert.doesNotThrow(() => resolveKind('bad\uFFFD'))
})

test('the fingerprint refuses an unpaired surrogate in the adopter name or a text payload (E4)', () => {
  assert.throws(() => fingerprintHex(bytes, 'acme\uD800'), /E4/)
  assert.throws(() => fingerprintHex(bytes, '\uDC00acme'), /E4/)
  assert.throws(() => fingerprintHex('payload\uD800', 'acme'), /E4/)
  // a well-formed astral name is fine, and differs from the U+FFFD spelling a substitution produced
  assert.notEqual(fingerprintHex(bytes, 'acme\u{1F600}'), fingerprintHex(bytes, 'acme\uFFFD'))
  assert.equal(fingerprintHex(bytes, 'acme'), 'd88657e80e283d5a44bd29b83cf8a93ec60729ec635e642b5454b8829bd3e3c6')
})
