// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
/**
 * Inkan glyph-seed domain separation — JS mirror of the Python reference
 * `inkan_standard/seed.py`. Byte-identical seeds so a JS-rendered seal matches every port.
 *
 * NOTE: this is the STANDARD's GLYPH domain ("inkan/v1"). The tamper-fingerprint
 * domain ("<adopter>/inkan/v1", see fingerprint.js) is namespaced per adopter.
 */

import { requireBytes } from './sha256.js'

const encoder = new TextEncoder()

/** Fixed, published domain prefix for the Inkan standard — bump only if the scheme changes. */
export const INKAN_DOMAIN = Uint8Array.from([
  ...encoder.encode('inkan/v1'), 0x00,
])

/**
 * UTF-8 encode, REJECTING unencodable text rather than substituting (SPEC §4 E4).
 *
 * TextEncoder turns an unpaired surrogate into U+FFFD (EF BF BD) without complaint, so every
 * distinct malformed kind collapsed onto ONE anchor while the caller believed it had succeeded.
 * Python raised and Kotlin substituted differently again: three ports, three answers, no failure.
 */
export function encodeUtf8 (text, what) {
  const s = String(text)
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xD800 && c <= 0xDBFF) {
      const n = s.charCodeAt(i + 1)
      if (!(n >= 0xDC00 && n <= 0xDFFF)) {
        throw new RangeError(what + ' is not encodable as UTF-8 and MUST be rejected, not ' +
          'substituted (SPEC §4 E4): unpaired high surrogate at position ' + i)
      }
      i++
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      throw new RangeError(what + ' is not encodable as UTF-8 and MUST be rejected, not ' +
        'substituted (SPEC §4 E4): unpaired low surrogate at position ' + i)
    }
  }
  return encoder.encode(s)
}

/**
 * For each Unicode version, the first code point it assigned, newest first. `unicodeVersion()` reads
 * the runtime's character database through the same `\p{…}` tables `rejectUnassigned` uses, so the
 * version it reports is the one the E14 check actually applies.
 */
const UNICODE_SENTINELS = [
  ['17.0', 0x088F], ['16.0', 0x0897], ['15.1', 0x2FFC], ['15.0', 0x0CF3], ['14.0', 0x061D],
  ['13.0', 0x08BE], ['12.1', 0x32FF], ['12.0', 0x0C77], ['11.0', 0x0560], ['10.0', 0x0860],
  ['9.0', 0x08B6], ['8.0', 0x08B3], ['7.0', 0x037F], ['6.3', 0x061C], ['6.2', 0x20BA],
  ['6.1', 0x058F], ['6.0', 0x0526], ['5.2', 0x0524], ['5.1', 0x0370], ['5.0', 0x0242],
  ['4.1', 0x0237], ['4.0', 0x0221], ['3.2', 0x0220], ['3.1', 0x03F4], ['3.0', 0x01F6],
]

let unicodeVersionSeen

/**
 * The Unicode version of this runtime's character database: the newest version in the table above
 * whose first new code point the database assigns. A runtime newer than the table reports the
 * table's newest entry. Returns null if the database predates Unicode 3.0.
 */
export function unicodeVersion () {
  if (unicodeVersionSeen === undefined) {
    unicodeVersionSeen = null
    for (const [v, cp] of UNICODE_SENTINELS) {
      if (!/^\p{Cn}$/u.test(String.fromCodePoint(cp))) { unicodeVersionSeen = v; break }
    }
  }
  return unicodeVersionSeen
}

// General_Category Cn, except the 66 noncharacters (U+FDD0..U+FDEF and U+nFFFE, U+nFFFF), which are
// permanently unassigned and normalise to themselves in every Unicode version.
const UNASSIGNED = /(?!\p{Noncharacter_Code_Point})\p{Cn}/u

/**
 * Refuse text that holds a code point this runtime's Unicode database leaves unassigned (SPEC §1
 * E14). NFC treats a code point it does not know as an unassigned starter, while a newer database
 * may know it as a combining mark or a composable letter, so guessing would give a different anchor
 * from an implementation that knew. Two databases that both assign every code point of a string
 * normalise it identically, now and later, so refusing never disagrees with another conforming
 * implementation. The check uses the runtime's own `\p{Cn}` tables, which in a JavaScript engine
 * come from the same Unicode data as `String.prototype.normalize`.
 */
export function rejectUnassigned (text, what) {
  const s = String(text)
  const m = UNASSIGNED.exec(s)
  if (m) {
    const cp = m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')
    throw new RangeError(what + ' contains U+' + cp + ' at position ' + m.index + ', which is ' +
      'unassigned in the Unicode ' + (unicodeVersion() || 'unknown') + ' database this runtime ' +
      'normalises with. Such text MUST be rejected, never normalised or hashed (SPEC §1 E14)')
  }
}

/**
 * The glyph seed: `INKAN_DOMAIN + u8(len(kind)) + kind + data`. The kind is length-prefixed, so the
 * kind/data boundary is unambiguous for every pair; len(kind_utf8) must be <= 255. Any string is a
 * kind; 14 are reserved (KINDS in seal_tables.js).
 *
 * @param {string|Uint8Array} data text (NFC-normalised, SPEC §1) or bytes (used as they are)
 * @param {string} [kind]
 * @returns {Uint8Array} `<inkan prefix><u8 len><kind><data>`
 */
export function inkanSeed(data, kind = '') {
  // data is text (a string) or bytes (a Uint8Array), nothing else; the kind is a string.
  if (typeof data !== 'string') requireBytes(data, 'data (when not a string)')
  if (typeof kind !== 'string') throw new TypeError('kind must be a string, got ' + (kind === null ? 'null' : typeof kind))
  // NFC-normalise text inputs so visually-identical strings make the same Inkan. Raw bytes verbatim.
  // Text with a code point this runtime's Unicode database does not assign is refused first (E14).
  if (typeof data === 'string') rejectUnassigned(data, 'data')
  rejectUnassigned(kind, 'kind')
  const dataBytes = typeof data === 'string' ? encodeUtf8(data.normalize('NFC'), 'data') : data
  const kindBytes = encodeUtf8(kind.normalize('NFC'), 'kind')
  if (kindBytes.length > 255) throw new Error('kind must be at most 255 UTF-8 bytes')
  const out = new Uint8Array(INKAN_DOMAIN.length + 1 + kindBytes.length + dataBytes.length)
  out.set(INKAN_DOMAIN, 0)
  out[INKAN_DOMAIN.length] = kindBytes.length
  out.set(kindBytes, INKAN_DOMAIN.length + 1)
  out.set(dataBytes, INKAN_DOMAIN.length + 1 + kindBytes.length)
  return out
}

