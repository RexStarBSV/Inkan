// Release provenance (SPEC §7.1): the anchor of a released file is the Inkan of the lower-case hex
// of SHA-256(file bytes) under kind "code", its tagged Seal v3 PNG is the inscription, and the §7
// fingerprint is published beside it. The JS port must reproduce the worked example in
// ../test-vectors/vectors.json (`inkan_image_example`) exactly.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { sha256, bytesToHex } from '../src/sha256.js'
import { inkanSeed } from '../src/seed.js'
import { resolveKind, sealRgb, sealPng } from '../src/seal.js'
import { fingerprintHex } from '../src/fingerprint.js'

const here = dirname(fileURLToPath(import.meta.url))
const v = JSON.parse(readFileSync(join(here, '..', '..', 'test-vectors', 'vectors.json'), 'utf8')).inkan_image_example

test('release provenance: file hash, anchor, code, geometry and pixels match the reference', () => {
  const file = new TextEncoder().encode(v.payload_utf8)
  const fileHex = bytesToHex(sha256(file))
  assert.equal(fileHex, v.file_sha256_hex)
  const seed = inkanSeed(fileHex, v.kind)
  assert.equal(bytesToHex(seed), v.seed_hex)
  const anchor = sha256(seed)
  assert.equal('ik1' + bytesToHex(anchor), v.code)
  assert.deepEqual(resolveKind(v.kind), v.resolve)
  assert.equal(bytesToHex(sha256(sealRgb(anchor, v.kind).pixels)), v.rgb_sha256)
  assert.equal(fingerprintHex(file, v.adopter, v.fingerprint_version), v.fingerprint_hex)
})

test('release provenance: the tagged PNG carries the code and the kind', () => {
  const anchor = sha256(inkanSeed(v.file_sha256_hex, v.kind))
  const png = sealPng(anchor, v.kind, { tag: true })
  const text = Buffer.from(png).toString('latin1')
  assert.ok(text.includes('inkan-code\0\0\0\0\0' + v.tag['inkan-code']), 'inkan-code tag')
  assert.ok(text.includes('inkan-kind\0\0\0\0\0' + v.tag['inkan-kind']), 'inkan-kind tag')
})
