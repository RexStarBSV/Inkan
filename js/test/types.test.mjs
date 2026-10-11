// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Test suite, not part of the Apache-2.0 verification path.
//
// Argument types. JavaScript converts silently where Python raises: an array [256, 257] given as
// bytes became [0, 1], a 32-character string passed as a 32-byte digest, an ArrayBuffer became no
// bytes at all, and a fractional scale produced an image of fractional size. Each was a confident
// wrong answer. Every one of them now throws a TypeError or RangeError, and the right types still work.
import assert from 'node:assert/strict'
import { test } from 'node:test'

import { sha256, bytesToHex } from '../src/sha256.js'
import { inkanSeed } from '../src/seed.js'
import { sealFields, sealRgb, sealRgbFromFields, sealPng, resolveKind, golay24, cellsFromWords, scaleNearest } from '../src/seal.js'
import { fingerprintHex } from '../src/fingerprint.js'
import { inkanGlyph } from '../src/index.js'

const digest = sha256(new TextEncoder().encode('x'))

test('bytes are a Uint8Array, nothing that merely looks like one', () => {
  for (const bad of [[256, 257], 'abc', new ArrayBuffer(4), new Uint16Array([256]), null, undefined, 7]) {
    assert.throws(() => sha256(bad), TypeError, String(bad))
    assert.throws(() => bytesToHex(bad), TypeError, String(bad))
  }
  assert.equal(bytesToHex(sha256(Buffer.from('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
})

test('a digest is exactly 32 bytes of Uint8Array', () => {
  const asArray = Array.from(digest).map((b) => b + 256)              // would wrap to the same bytes
  const asString = 'a'.repeat(32)
  for (const bad of [asArray, Array.from(digest), asString]) {
    assert.throws(() => sealFields(bad), TypeError)
    assert.throws(() => sealRgb(bad, 'address'), TypeError)
    assert.throws(() => sealPng(bad), TypeError)
  }
  assert.throws(() => sealFields(digest.subarray(0, 31)), RangeError)
  assert.deepEqual(sealFields(Buffer.from(digest)), sealFields(digest))
})

test('data is a string or a Uint8Array, and a kind is a string', () => {
  for (const bad of [[104, 105], new ArrayBuffer(2), 5, null, { length: 2 }]) {
    assert.throws(() => inkanSeed(bad, ''), TypeError, String(bad))
    assert.throws(() => inkanGlyph(bad, ''), TypeError, String(bad))
  }
  for (const bad of [5, null, ['address'], new String('address')]) {
    assert.throws(() => inkanSeed('x', bad), TypeError, String(bad))
    assert.throws(() => resolveKind(bad), TypeError, String(bad))
    assert.throws(() => sealFields(digest, bad), TypeError, String(bad))
  }
  assert.deepEqual(inkanSeed(Buffer.from('hi'), 'code'), inkanSeed(new TextEncoder().encode('hi'), 'code'))
})

test('fields, codes and scales are integers in range', () => {
  const f = sealFields(digest, 'address')
  assert.throws(() => sealRgbFromFields(f.words.slice(1), f.paletteIx, f.corePattern, 'address'), TypeError)
  assert.throws(() => sealRgbFromFields(f.words.map(String), f.paletteIx, f.corePattern, 'address'), TypeError)
  for (const bad of [-1, 32, 1.5, '3']) {
    assert.throws(() => sealRgbFromFields(f.words, bad, f.corePattern, 'address'), RangeError, String(bad))
  }
  assert.throws(() => sealRgbFromFields(f.words, f.paletteIx, 2.5, 'address'), TypeError)
  assert.throws(() => golay24(1.5), TypeError)
  assert.throws(() => cellsFromWords(f.words, 1.5), TypeError)
  for (const bad of [0, -1, 1.5, '2', NaN]) assert.throws(() => scaleNearest(sealRgb(digest), bad), RangeError, String(bad))
  assert.equal(scaleNearest(sealRgb(digest), 2).width, 448)
  assert.deepEqual(sealRgbFromFields(f.words, f.paletteIx, f.corePattern, 'address'), sealRgb(digest, 'address'))
})

test('a fingerprint payload is a string or a Uint8Array', () => {
  for (const bad of [[1, 2], new ArrayBuffer(2), 5, null]) {
    assert.throws(() => fingerprintHex(bad, 'acme'), TypeError, String(bad))
  }
  assert.equal(fingerprintHex(Buffer.from('build-bytes-v1'), 'acme'), fingerprintHex('build-bytes-v1', 'acme'))
})
