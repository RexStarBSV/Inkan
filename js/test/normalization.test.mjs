// Normalization vectors (additive, 2026-07-31): pin the FROZEN v3 behaviour — the anchor
// NFC-normalizes the kind, the seal derivation hashes the kind AS PROVIDED. An implementation
// that inserts NFC into derivation FAILS these. See ../test-vectors/normalization-vectors.json.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { inkanSeed } from '../src/seed.js'
import { resolveKind, sealFields, sealRgbFromFields } from '../src/seal.js'

const here = dirname(fileURLToPath(import.meta.url))
const doc = JSON.parse(readFileSync(join(here, '..', '..', 'test-vectors', 'normalization-vectors.json'), 'utf8'))
const sha256hex = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex')
const sha256buf = (b) => createHash('sha256').update(Buffer.from(b)).digest()

test('normalization: anchors agree across NFC/NFD, derivation stays raw', () => {
  const a = doc.anchor_layer
  const nfd = a.kind_nfd_codepoints.map((h) => String.fromCodePoint(parseInt(h, 16))).join('')
  const dNfc = sha256buf(inkanSeed(a.data_utf8, a.kind_nfc))
  const dNfd = sha256buf(inkanSeed(a.data_utf8, nfd))
  assert.deepEqual(dNfc, dNfd, 'anchor layer must normalize: NFC and NFD kinds share one anchor')
  for (const layer of doc.derivation_layer) {
    const kind = Buffer.from(layer.kind_utf8_hex, 'hex').toString('utf8')
    assert.deepEqual(resolveKind(kind), layer.resolve, `derivation is raw-bytes for ${layer.kind_form}`)
    const digest = layer.kind_form === 'NFC' ? dNfc : dNfd
    const f = sealFields(digest, kind)
    assert.equal(sha256hex(sealRgbFromFields(f.words, f.paletteIx, f.corePattern, kind).pixels),
                 layer.rgb_sha256, `rgb pin ${layer.kind_form}`)
  }
})
