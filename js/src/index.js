// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
/**
 * inkan (npm) — Inkan trust-signaling core (JS).
 *
 * Dependency-free, synchronous, browser + node. Parity with the Python reference is
 * proven by `npm test`: the digest + canary against ../test-vectors/vectors.json, and
 * the Seal v3 renderer against ../test-vectors/seal-v3-vectors.json.
 *
 * The seal engine (Seal v3) is original work. The legacy v1 glyph was LifeHash
 * (© 2019-2022 Blockchain Commons, BSD-2-Clause-Patent); it was deleted on 2026-07-09,
 * since no seals had ever been published and nothing needed preserving.
 *
 * Warrant-canary verify IS ported and dependency-free: `./canary` and `./secp256k1` are a
 * self-contained secp256k1 verifier, parity-checked against BRC-145 TV7. The note that once stood
 * here ("not yet ported — planned via @noble/secp256k1") outlived the work by several months.
 */
export { sha256, bytesToHex } from './sha256.js'
export { inkanSeed, INKAN_DOMAIN, rejectUnassigned, unicodeVersion } from './seed.js'
export { domainPrefix, fingerprintDigest, fingerprintHex, checkAdopter, checkVersion } from './fingerprint.js'
// Canary verification, namespaced: `verify` and `status` are generic words and would collide
// with the seal vocabulary above. The unprefixed API is reachable at 'inkan-standard/canary'.
export { verify as canaryVerify, status as canaryStatus, isFresh as canaryIsFresh,
         canonicalBytes as canaryCanonicalBytes, messageHash as canaryMessageHash,
         parseRecord as canaryParseRecord, checkRecord as canaryCheckRecord,
         MalformedCanaryInput, UnsupportedCanaryVersion } from './canary.js'

// Seal v3 — the current engine. Original work, no third-party lineage.
export { sealRgb, sealRgbFromFields, sealPng, sealFields, resolveKind, golay24, cellsFromWords, scaleNearest, KINDS, SEAL_VERSION } from './seal.js'

import { sha256 } from './sha256.js'
import { sealRgb, scaleNearest } from './seal.js'
import { inkanSeed } from './seed.js'

/**
 * One-call Inkan seal: seed → SHA-256 → Seal v3 → optional integer nearest-neighbour
 * upscale. Byte-identical to `python/inkan_standard/seal.py`.
 *
 * `kind` does double duty by design: it domain-separates the seed AND selects the frame
 * motif, so a signer seal can never be confused with an address seal.
 *
 * @param {string|Uint8Array} data e.g. an address, npub, or identity key
 * @param {string} [kind] stable stamp class ("address", "identity", …)
 * @param {number} [scale] integer upscale factor (1 = native 224×224)
 * @returns {{width: number, height: number, pixels: Uint8Array}} RGB888, at most 5 colours
 */
export function inkanGlyph(data, kind = '', scale = 1) {
  return scaleNearest(sealRgb(sha256(inkanSeed(data, kind)), kind), scale)
}
