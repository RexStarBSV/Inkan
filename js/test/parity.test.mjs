/**
 * Parity tests: the JS port must reproduce the Python reference byte-for-byte
 * against ../test-vectors/vectors.json.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { sha256, bytesToHex } from '../src/sha256.js'
import { sealRgb, scaleNearest } from '../src/seal.js'
import { inkanSeed } from '../src/seed.js'
import { fingerprintHex } from '../src/fingerprint.js'
import { inkanGlyph } from '../src/index.js'

const vectors = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'test-vectors', 'vectors.json'), 'utf8'),
)

test('sha256 matches FIPS 180-4 vectors', () => {
  const utf8 = (s) => new TextEncoder().encode(s)
  assert.equal(bytesToHex(sha256(utf8(''))),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  assert.equal(bytesToHex(sha256(utf8('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  assert.equal(bytesToHex(sha256(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
  // > 55 bytes exercises the two-block padding path
  assert.equal(bytesToHex(sha256(utf8('a'.repeat(1000)))),
    '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3')
})

test('fingerprint vectors', () => {
  for (const v of vectors.fingerprint) {
    assert.equal(fingerprintHex(v.payload_utf8, v.adopter, v.version), v.digest_hex,
      `fingerprint(${JSON.stringify(v.payload_utf8)}, ${v.adopter})`)
  }
})

test('inkan_seed matches reference seeds', () => {
  for (const v of vectors.inkan.vectors) {
    assert.equal(bytesToHex(inkanSeed(v.data_utf8, v.kind)), v.seed_hex,
      `seed(${JSON.stringify(v.data_utf8)}, ${JSON.stringify(v.kind)})`)
  }
})

test('Inkan Seal v2 raster matches reference RGB888 byte-for-byte', () => {
  assert.equal(vectors.inkan.seal_version, 3)
  for (const v of vectors.inkan.vectors) {
    const img = sealRgb(sha256(inkanSeed(v.data_utf8, v.kind)), v.kind)
    assert.equal(img.width, v.width)
    assert.equal(img.height, v.height)
    assert.equal(img.pixels.length, v.width * v.height * 3)
    assert.equal(bytesToHex(sha256(img.pixels)), v.rgb888_sha256,
      `seal(${JSON.stringify(v.data_utf8)}, ${JSON.stringify(v.kind)})`)
  }
})

test('scaleNearest is exact integer nearest-neighbour', () => {
  const img = { width: 2, height: 2, pixels: Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) }
  const s = scaleNearest(img, 2)
  assert.equal(s.width, 4)
  assert.equal(s.height, 4)
  assert.deepEqual(Array.from(s.pixels.slice(0, 12)), [1, 2, 3, 1, 2, 3, 4, 5, 6, 4, 5, 6])
  assert.deepEqual(Array.from(s.pixels.slice(36)), [7, 8, 9, 7, 8, 9, 10, 11, 12, 10, 11, 12])
})

test('inkanGlyph equals an explicit scaled Seal v2 render', () => {
  const v = vectors.inkan.vectors[0]
  const g = inkanGlyph(v.data_utf8, v.kind, 3)
  const direct = scaleNearest(sealRgb(sha256(inkanSeed(v.data_utf8, v.kind)), v.kind), 3)
  assert.equal(bytesToHex(sha256(g.pixels)), bytesToHex(sha256(direct.pixels)))
  assert.equal(g.width, v.width * 3)
})
