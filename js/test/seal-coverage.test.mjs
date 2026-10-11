// Seal v3 tables and coverage (SPEC §3.0): this port's tables must encode to the published,
// SHA-256-pinned file test-vectors/seal-v3-tables.json, and the engine must reproduce
// test-vectors/seal-v3-coverage-vectors.json, which reaches every region map, every open-kind
// frame motif, every palette class, every core pattern and the second block of the field stream.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import * as T from '../src/seal_tables.js'
import { SEAL_VERSION, resolveKind, sealFields, sealRgbFromFields } from '../src/seal.js'

const here = dirname(fileURLToPath(import.meta.url))
const vec = (name) => readFileSync(join(here, '..', '..', 'test-vectors', name))
const sha256hex = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex')
const fromHex = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)))

// The canonical encoding of SPEC §3.0: members sorted by key, no whitespace, plain integers,
// ASCII strings without escapes, one trailing line feed.
function canon (v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']'
  if (v !== null && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
  }
  if (typeof v === 'number') { assert.ok(Number.isSafeInteger(v)); return String(v) }
  return JSON.stringify(v)
}

test('this port\'s tables encode to the published tables file', () => {
  const bytes = vec('seal-v3-tables.json')
  const file = JSON.parse(bytes.toString('ascii'))
  const doc = {
    // The domains and the Golay generator are internal to seal.js; the vectors check its use of them.
    FORMAT: file.FORMAT,
    STREAM_DOMAIN_HEX: file.STREAM_DOMAIN_HEX,
    KIND_DOMAIN_HEX: file.KIND_DOMAIN_HEX,
    GOLAY_G: file.GOLAY_G,
    SEAL_VERSION,
    CANVAS: T.CANVAS,
    TIER_CELLS: T.TIER_CELLS,
    KMAX: T.KMAX,
    ORBIT_REPS: T.ORBIT_REPS,
    KINDS: T.KINDS,
    PALETTE: T.PALETTE,
    SELECT_WEIGHTS: T.SELECT_WEIGHTS,
    CORE_PATTERNS: T.CORE_PATTERNS,
    REGION_RLE: T.REGION_RLE,
  }
  assert.equal(sha256hex(Buffer.from(canon(doc) + '\n', 'ascii')), sha256hex(bytes))
})

test('coverage vectors: every map, motif, palette class and core pattern, and the second block', () => {
  const doc = JSON.parse(vec('seal-v3-coverage-vectors.json').toString('utf8'))
  assert.equal(doc.seal_version, SEAL_VERSION)
  assert.equal(doc.tables_sha256, sha256hex(vec('seal-v3-tables.json')))
  for (const v of [...doc.coverage, ...doc.second_block]) {
    const what = `${v.kind}/${v.digest_hex.slice(0, 8)}`
    assert.deepEqual(resolveKind(v.kind), v.resolve, `resolve ${what}`)
    const f = sealFields(fromHex(v.digest_hex), v.kind)
    assert.deepEqual(f.words, v.words, `words ${what}`)
    assert.equal(f.paletteIx, v.palette_ix, `palette ${what}`)
    assert.equal(f.corePattern, v.core_pattern, `core ${what}`)
    const rgb = sealRgbFromFields(f.words, f.paletteIx, f.corePattern, v.kind)
    assert.equal(sha256hex(rgb.pixels), v.rgb_sha256, `rgb ${what}`)
  }
})
