/**
 * Seal v3 parity gate: the JS port must reproduce the Python reference byte-for-byte.
 * Parity is asserted on RGB pixel bytes rather than PNG, so neither port depends on a
 * specific zlib's compressed output.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { CANVAS, KINDS } from '../src/seal_tables.js'
import { SEAL_VERSION, cellsFromWords, golay24, resolveKind, sealFields, sealRgbFromFields } from '../src/seal.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, '..', '..', 'test-vectors', 'seal-v3-vectors.json')))
const sha256hex = (u8) => createHash('sha256').update(Buffer.from(u8)).digest('hex')
const fromHex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)))

test('vector file matches this engine generation', () => {
  assert.equal(doc.seal_version, SEAL_VERSION)
  assert.equal(doc.canvas, CANVAS)
  for (const [kind, v] of Object.entries(doc.kinds)) {
    assert.deepEqual(resolveKind(kind), [v.cells, v.k, v.motif], `kind ${kind}`)
  }
})

test('Golay [24,12,8]: injective, min weight 8, signed-XOR guard', () => {
  const seen = new Set()
  let minw = 24
  for (let i = 0; i < 4096; i++) {
    const c = golay24(i)
    seen.add(c)
    if (i) {
      let w = 0
      for (let x = c; x; x >>>= 1) w += x & 1
      if (w < minw) minw = w
    }
  }
  assert.equal(seen.size, 4096)
  assert.equal(minw, 8, 'the entire structural guarantee rests on this')
  // JS ^ returns signed int32; the engine must coerce. Linearity is the witness:
  assert.equal((golay24(0x123) ^ golay24(0xabc)) >>> 0, golay24(0x123 ^ 0xabc))
})


test('sampled vectors: fields and RGB parity', () => {
  for (const v of doc.sampled) {
    const f = sealFields(fromHex(v.digest_hex), v.kind)
    assert.deepEqual(f.words, v.words, `words ${v.kind}/${v.digest_hex.slice(0, 8)}`)
    assert.equal(f.paletteIx, v.palette_ix, `palette ${v.kind}/${v.digest_hex.slice(0, 8)}`)
    assert.equal(f.corePattern, v.core_pattern, `core ${v.kind}/${v.digest_hex.slice(0, 8)}`)
    const rgb = sealRgbFromFields(f.words, f.paletteIx, f.corePattern, v.kind)
    assert.equal(sha256hex(rgb.pixels), v.rgb_sha256, `rgb ${v.kind}/${v.digest_hex.slice(0, 8)}`)
  }
})

test('constructed worst case: exactly 8 cells differ, both renders match', () => {
  for (const v of doc.constructed_worst_case) {
    const f = sealFields(fromHex(v.digest_hex), v.kind)
    const words2 = [f.words[0] ^ v.min_weight_error_word, ...f.words.slice(1)]
    const c1 = cellsFromWords(f.words, v.cells)
    const c2 = cellsFromWords(words2, v.cells)
    let diff = 0
    for (let i = 0; i < c1.length; i++) if (c1[i] !== c2[i]) diff++
    assert.equal(diff, v.cells_differing, 'floor')
    assert.equal(diff, 8)
    assert.equal(sha256hex(sealRgbFromFields(f.words, f.paletteIx, f.corePattern, v.kind).pixels), v.rgb_sha256_a)
    assert.equal(sha256hex(sealRgbFromFields(words2, f.paletteIx, f.corePattern, v.kind).pixels), v.rgb_sha256_b)
  }
})
