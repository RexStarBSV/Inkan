// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
/**
 * inkan fingerprint — tamper-evidence digests, JS mirror of the Python
 * reference (`python/inkan_standard/fingerprint.py`).
 *
 *     digest = SHA256( domain_prefix || payload )
 *     domain_prefix = "<adopter>/inkan/v<version>" + 0x00
 *
 * Parity proven against `test-vectors/vectors.json` "fingerprint" entries.
 */
import { sha256, bytesToHex, requireBytes } from './sha256.js'
import { encodeUtf8, rejectUnassigned } from './seed.js'

const encoder = new TextEncoder()

/**
 * A fingerprint version is a positive integer: 1, 2, 3, ... (SPEC §7, E22). Anything else is refused:
 * zero, a negative number, a fraction, a string, a boolean. A number must also be below 10^21, where
 * JavaScript starts writing numbers in exponent form and so could not write dec(n); pass a BigInt
 * for a larger version. Before E22 any value was accepted, and 1.5 was written out here while Python
 * truncated it to 1, so one input had two digests.
 * @returns {string} dec(version)
 */
export function checkVersion (version) {
  if (typeof version === 'bigint' && version >= 1n) return version.toString()
  if (typeof version === 'number' && Number.isInteger(version) && version >= 1 && version < 1e21) {
    return String(version)
  }
  throw new RangeError('fingerprint version must be a positive integer (1, 2, 3, ...), got ' +
    (typeof version === 'string' ? JSON.stringify(version) : String(version)) + ' (SPEC §7 E22)')
}

/**
 * Refuse an adopter name the profile does not allow, before anything is hashed (SPEC §7, E6, E21),
 * and return its NFC form. The profile is fixed by code-point ranges, so it does not move as Unicode
 * assigns characters: well-formed (E4), no code point this runtime's database leaves unassigned
 * (E14), no control character (U+0000-U+001F, U+007F-U+009F; NUL included), and after NFC no leading
 * "nkan/". That last rule closes the one cross-context parse: for a name of length 0x69 the length
 * byte is ASCII "i", the preimage opens with the glyph domain "inkan/v1\0", and one digest would be
 * both a fingerprint and an anchor.
 */
export function checkAdopter (adopter) {
  if (typeof adopter !== 'string') {
    throw new TypeError('adopter name must be a string, got ' + (adopter === null ? 'null' : typeof adopter))
  }
  rejectUnassigned(adopter, 'adopter name')
  const c = /[\u0000-\u001F\u007F-\u009F]/.exec(adopter)
  if (c) {
    throw new RangeError('adopter name contains the control character U+' +
      c[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + ' at position ' + c.index +
      '; an adopter name MUST be printable (SPEC §7 E21)')
  }
  const nfc = adopter.normalize('NFC')
  // Strict UTF-8 (E4): an unpaired surrogate is refused, never replaced by U+FFFD, which would give
  // every malformed name the fingerprint of one well-formed name.
  encodeUtf8(nfc, 'adopter name')
  if (nfc.startsWith('nkan/')) {
    throw new RangeError("an adopter name MUST NOT begin with 'nkan/' (after NFC): with the length " +
      "byte it could spell the glyph domain 'inkan/v1\\0', making one digest both a fingerprint and " +
      'an anchor (SPEC §7 E6, E21)')
  }
  return nfc
}

/**
 * Per-adopter fingerprint domain: u8(len(adopter)) + adopter + "/inkan/v<version>" + 0x00, the
 * adopter NFC-normalised and length-prefixed so the adopter/payload boundary is unambiguous. The name
 * and the version are both checked first (checkAdopter, checkVersion).
 * @returns {Uint8Array}
 */
export function domainPrefix (adopter, version = 1) {
  const dec = checkVersion(version)
  const a = encodeUtf8(checkAdopter(adopter), 'adopter name')
  if (a.length > 255) throw new Error('adopter must be at most 255 UTF-8 bytes')
  const suffix = encoder.encode('/inkan/v' + dec)
  const out = new Uint8Array(1 + a.length + suffix.length + 1)
  out[0] = a.length; out.set(a, 1); out.set(suffix, 1 + a.length); out[out.length - 1] = 0x00
  return out
}

/**
 * @param {Uint8Array|string} payload
 * @param {string} adopter
 * @param {number} [version]
 * @returns {Uint8Array} 32-byte tamper fingerprint
 */
export function fingerprintDigest(payload, adopter, version = 1) {
  const payloadBytes = typeof payload === 'string' ? encodeUtf8(payload, 'payload')
    : requireBytes(payload, 'payload (when not a string)')
  const prefix = domainPrefix(adopter, version)
  const msg = new Uint8Array(prefix.length + payloadBytes.length)
  msg.set(prefix, 0)
  msg.set(payloadBytes, prefix.length)
  return sha256(msg)
}

export function fingerprintHex(payload, adopter, version = 1) {
  return bytesToHex(fingerprintDigest(payload, adopter, version))
}
