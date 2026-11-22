// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Test suite, not part of the Apache-2.0 verification path.
//
// The built web verifier must compare a block HASH the reader pastes with the record's block_hash,
// not only a height. No pasted hash is "not done", never a pass; a mismatch is a loud failure.
// The function under test is extracted from the generated page itself, the artifact that ships.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const page = fs.readFileSync(path.join(HERE, '..', '..', 'web', 'inkan-verify.html'), 'utf8')

const a = page.indexOf('function blockAnchorCheck(')
assert.ok(a >= 0, 'web/inkan-verify.html has no blockAnchorCheck: the page does not compare a block hash')
const b = page.indexOf('// ---- canary layer', a)
const blockAnchorCheck = new Function(page.slice(a, b) + '\nreturn blockAnchorCheck;')()

const H1 = 'ab'.repeat(32)
const H2 = 'cd'.repeat(32)
const rec = { block_height: 870000, block_hash: H1 }

test('no pasted hash: the hash check is not done, never ok', () => {
  const r = blockAnchorCheck(rec, '870010', '')
  assert.equal(r.hash.state, 'notdone')
  assert.equal(r.hashMismatch, false)
  assert.match(r.hash.text, /not a pass/i)
})

test('a height alone never marks the hash check as passed', () => {
  assert.notEqual(blockAnchorCheck(rec, '999999', '').hash.state, 'ok')
})

test('matching hash passes, case and 0x prefix tolerated', () => {
  assert.equal(blockAnchorCheck(rec, '', H1).hash.state, 'ok')
  assert.equal(blockAnchorCheck(rec, '', '0x' + H1.toUpperCase()).hash.state, 'ok')
})

test('mismatching hash is a loud failure', () => {
  const r = blockAnchorCheck(rec, '', H2)
  assert.equal(r.hash.state, 'bad')
  assert.equal(r.hashMismatch, true)
  assert.match(r.hash.text, /MISMATCH/)
})

test('a pasted value that is not a 64 hex hash is a failure, not a skip', () => {
  const r = blockAnchorCheck(rec, '', 'not a hash')
  assert.equal(r.hash.state, 'bad')
  assert.equal(r.hashMismatch, true)
})

test('a record with no block_hash cannot pass a pasted hash', () => {
  const r = blockAnchorCheck({ block_height: 5 }, '', H1)
  assert.equal(r.hash.state, 'bad')
  assert.equal(r.hashMismatch, true)
})

test('height ahead of the supplied height is still impossible', () => {
  assert.equal(blockAnchorCheck(rec, '100', '').impossible, true)
})

test('the footer no longer calls the chain the anchor', () => {
  assert.doesNotMatch(page, /so the chain is the anchor/)
  assert.match(page, /planned and has not been made yet/)
})
