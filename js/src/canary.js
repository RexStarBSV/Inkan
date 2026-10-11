// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
/**
 * inkan canary — warrant / compromise canary verification. JS mirror of the Python reference
 * (`python/inkan_standard/canary.py`), verification half only.
 *
 * A canary is a signed, freshness-proofed statement that the operator is uncompromised and
 * un-coerced. **Absence, staleness, or a failed signature is the warning** — which is precisely why
 * this belongs in a page an ordinary reader can open, not only in a terminal. A canary nobody can
 * check is a canary that has already failed quietly.
 *
 * Record — canonical JSON, sorted keys, no whitespace:
 *   {"v":1,"domain":str,"seq":int,"date":ISO8601 Z,"block_height":int,"block_hash":hex,
 *    "statement":str}
 * `block_height`/`block_hash` are a recent chain tip. They ENABLE an anti-backdate check, but
 * performing it requires the chain and THIS MODULE DOES NOT PERFORM IT -- `block_hash` is read by no
 * verification branch here. A verifier with chain access SHOULD resolve the hash at that height and
 * reject a mismatch; until it does, these are a commitment the signer made, not a checked proof.
 */
import { sha256 } from './sha256.js'
import { verifyDerHash } from './secp256k1.js'

const enc = new TextEncoder()

/**
 * Deterministic serialisation that is signed and verified: sorted keys, no whitespace, UTF-8.
 * Matches Python's json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False) for every
 * record that meets the input rules (SPEC §8 E23). The record is flat by construction, so a
 * single-level sort is the whole rule.
 */
function canonicalText (record) {
  const keys = Object.keys(record).sort()
  return '{' + keys.map(k => JSON.stringify(k) + ':' + JSON.stringify(record[k])).join(',') + '}'
}

export function canonicalBytes (record) {
  return enc.encode(canonicalText(record))
}

export const messageHash = record => sha256(canonicalBytes(record))

/**
 * True iff `signatureHex` is a valid signature over the record by `pubkeyHex`.
 * An unknown record version THROWS rather than returning false (SPEC §8 E2): a future v2 record fed
 * to a v1 verifier must read UNSUPPORTED, never a false INVALID. Anything else that goes wrong is a
 * check that ran and failed.
 */
export class MalformedCanaryInput extends Error {}

/** The record names a version this verifier does not implement (SPEC §8 E2): UNSUPPORTED, never
 *  INVALID or OK. */
export class UnsupportedCanaryVersion extends Error {}

/**
 * SPEC §8 E23: a public key or signature is hexadecimal text, an even number of ASCII hex digits in
 * either case, with no prefix and nothing between the digits. Only these characters are ignored
 * around it, the set the Python and JavaScript verifiers both ignored before E23 (`trim()` also
 * drops U+FEFF, and Python's `strip()` also drops U+001C-U+001F and U+0085).
 */
const HEX = /^[\t-\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*((?:[0-9A-Fa-f]{2})+)[\t-\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/

function hexBytes (text, what) {
  const m = typeof text === 'string' ? HEX.exec(text) : null
  if (!m) {
    throw new MalformedCanaryInput('the ' + what + ' is not hexadecimal text: it must be an even number of ' +
      'the digits 0-9 and a-f (either case), with no 0x prefix and nothing between the digits (SPEC s.8 E23)')
  }
  return Uint8Array.from(m[1].match(/../g), b => parseInt(b, 16))
}

/** SPEC §8 E23 rule 1: `seq` and `block_height` are integers from 0 to 2^53 - 1. */
const isRecordInteger = x => Number.isSafeInteger(x) && x >= 0

const DATE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/

/**
 * The time (ms since 1970) a record's `date` names, or null unless it is exactly YYYY-MM-DDTHH:MM:SSZ
 * in ASCII digits and a real UTC time (SPEC §8 E23 rule 2): year 0001-9999, month 01-12, a day that
 * exists in that month of that year (Gregorian), hour 00-23, minute 00-59, second 00-59.
 */
function realUtcTime (date) {
  const m = typeof date === 'string' ? DATE.exec(date) : null
  if (!m) return null
  const [y, mo, d, h, mi, sec] = m.slice(1).map(Number)
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
  if (y < 1 || !days || d < 1 || d > days || h > 23 || mi > 59 || sec > 59) return null
  const t = new Date(0)
  t.setUTCFullYear(y, mo - 1, d)            // Date.UTC would read years 0-99 as 1900-1999
  t.setUTCHours(h, mi, sec, 0)
  return t.getTime()
}

/** True unless the string holds an unpaired surrogate (SPEC §8 E23 rule 3). */
function wellFormed (s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xD800 && c <= 0xDBFF) {
      const n = s.charCodeAt(i + 1)
      if (!(n >= 0xDC00 && n <= 0xDFFF)) return false
      i++
    } else if (c >= 0xDC00 && c <= 0xDFFF) return false
  }
  return true
}

//: SPEC s.8 (E1) fixes the record at exactly these seven fields.
const FIELDS = { v: 'number', domain: 'string', seq: 'number', date: 'string',
                 block_height: 'number', block_hash: 'string', statement: 'string' }

/** The signature covers whatever fields are present, so a wrong shape cannot be FORGED -- but a
 *  publisher can emit one by mistake and every verifier would still say OK. Nothing validated this
 *  in any port, on either side of the wire. Fail closed. */
function checkShape (record) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new MalformedCanaryInput('canary record must be an object')
  }
  const want = Object.keys(FIELDS).sort()
  const got = Object.keys(record).sort()
  const missing = want.filter(k => !got.includes(k))
  const extra = got.filter(k => !want.includes(k))
  if (missing.length || extra.length) {
    throw new MalformedCanaryInput('canary record must carry exactly the seven fields SPEC s.8 fixes' +
      (missing.length ? ' (missing ' + missing.join(', ') + ')' : '') +
      (extra.length ? ' (unexpected ' + extra.join(', ') + ')' : ''))
  }
  for (const [k, ty] of Object.entries(FIELDS)) {
    if (typeof record[k] !== ty) {
      throw new MalformedCanaryInput('canary field ' + k + ' must be ' + ty)
    }
  }
}

/** SPEC §8 E23 rules 1-3, on a record of the right shape. Before E23 the Python and JavaScript
 *  verifiers gave different verdicts for records that broke them; each is MALFORMED now. */
function checkRules (record) {
  for (const k of ['seq', 'block_height']) {
    if (!isRecordInteger(record[k])) {
      throw new MalformedCanaryInput('canary field ' + k + ' must be an integer from 0 to 2^53 - 1, got ' +
        String(record[k]) + ' (SPEC s.8 E23)')
    }
  }
  if (realUtcTime(record.date) === null) {
    throw new MalformedCanaryInput('canary date must be exactly YYYY-MM-DDTHH:MM:SSZ in ASCII digits and ' +
      'name a real UTC time, got ' + JSON.stringify(record.date) + ' (SPEC s.8 E23)')
  }
  for (const k of ['domain', 'date', 'block_hash', 'statement']) {
    if (!wellFormed(record[k])) {
      throw new MalformedCanaryInput('canary field ' + k + ' is not well-formed Unicode text: it holds an ' +
        'unpaired surrogate (SPEC s.8 E23)')
    }
  }
}

/**
 * Read a record from its wire form, a string or a Uint8Array of UTF-8, and return [record, text].
 * Strict: the bytes must be UTF-8 (a byte-order mark is kept, so it fails as JSON), and the text must
 * be JSON. Throws MalformedCanaryInput. Whether the text is the record's canonical form (E23 rule 4)
 * is checked after the version check.
 */
export function parseRecord (wire) {
  let text = wire
  if (typeof wire !== 'string') {
    if (!(wire instanceof Uint8Array)) throw new MalformedCanaryInput('a wire record is a string or a Uint8Array')
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(wire)
    } catch (e) {
      throw new MalformedCanaryInput('record bytes are not UTF-8')
    }
  }
  try {
    return [JSON.parse(text), text]
  } catch (e) {
    throw new MalformedCanaryInput('record is not JSON: ' + e.message)
  }
}

const recordOf = record =>
  (typeof record === 'string' || record instanceof Uint8Array) ? parseRecord(record) : [record, null]

/**
 * Every check SPEC §8 makes before the signature, in its order: an object; the version is 1, else
 * UnsupportedCanaryVersion (E2); exactly the seven fields with their types (E13); the input rules
 * (E23 rules 1-3); and, for a record read from its wire form, that form is exactly its canonical
 * bytes (rule 4). Throws MalformedCanaryInput.
 */
export function checkRecord (record, wireText = null) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new MalformedCanaryInput('canary record must be an object')
  }
  if (record.v !== 1) {
    throw new UnsupportedCanaryVersion('unsupported canary record version ' + JSON.stringify(record.v) +
                    ' (this verifier implements v1)')
  }
  checkShape(record)          // v1 shape, checked only once we know it claims to BE v1
  checkRules(record)
  if (wireText !== null && canonicalText(record) !== wireText) {
    throw new MalformedCanaryInput("the record's bytes are not its canonical bytes (SPEC s.8 E23 rule 4): " +
      'it must be written on one line, members in key order, with no spaces and no escapes other ' +
      'than the canonical ones')
  }
}

/**
 * `record` is an object, or its wire form (a string or a Uint8Array), which must then be exactly the
 * record's canonical bytes (SPEC §8 E23).
 */
export function verify (record, signatureHex, pubkeyHex) {
  const [rec, wire] = recordOf(record)
  checkRecord(rec, wire)
  record = rec
  // A malformed key or signature is NOT a failed check -- it is a check that never ran. Collapsing
  // the two fires the maximum-severity alarm for what is usually a truncated paste. Same principle
  // as the unknown-version rule above (SPEC s.8 E2, E11).
  const pub = hexBytes(pubkeyHex, 'public key')
  const sig = hexBytes(signatureHex, 'signature')
  try {
    return verifyDerHash(pub, sig, messageHash(record))
  } catch (e) {
    // secp256k1.js throws only for a malformed point or malformed DER; a signature that merely
    // fails to verify returns false.
    throw new MalformedCanaryInput(e.message)
  }
}

/** Within the staleness window, and not implausibly future-dated. A date that is not exactly the
 *  SPEC §8 form naming a real time is never fresh. */
export function isFresh (record, nowMs = Date.now(), maxAgeDays = 35) {
  const t = realUtcTime(record && record.date)
  if (t === null) return false
  const ageSec = (nowMs - t) / 1000
  return ageSec >= -86400 && ageSec <= maxAgeDays * 86400
}

/**
 * 'OK' | 'STALE' | 'INVALID' | 'MALFORMED' — the single value a client surfaces.
 *
 * MALFORMED means the check could not RUN (key or signature did not parse), as distinct from
 * INVALID, which means a check ran and the signature was wrong. Both are fail-closed; neither is
 * ever OK. An unsupported version still propagates as a throw, so a caller can say UNSUPPORTED.
 */
export function status (record, signatureHex, pubkeyHex, nowMs = Date.now(), maxAgeDays = 35) {
  let ok, rec
  try {
    rec = recordOf(record)[0]
    ok = verify(record, signatureHex, pubkeyHex)
  } catch (e) {
    if (e instanceof MalformedCanaryInput) return 'MALFORMED'
    throw e                                   // unknown version still propagates as UNSUPPORTED
  }
  if (!ok) return 'INVALID'
  if (!isFresh(rec, nowMs, maxAgeDays)) return 'STALE'
  return 'OK'
}
