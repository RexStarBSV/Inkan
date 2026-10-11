// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
/**
 * secp256k1 ECDSA **verification only** — JS mirror of the Python reference
 * (`python/inkan_standard/_secp256k1.py`), which is itself the dependency-free fallback proven against
 * bitcoinx across 1270 differential cases with zero divergences.
 *
 * VERIFY ONLY, deliberately. There is no signing here and there must never be: an Inkan
 * verification surface holds no key material and can spend nothing, which is what makes it safe to
 * inscribe on chain and to run from a stranger's machine. Adding a signer would destroy that
 * property permanently for every copy already published.
 *
 * Public inputs only, so no constant-time requirement: everything here is a signature, a public key
 * and a message that an attacker already has.
 */
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const G = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
]

const mod = (a, m) => ((a % m) + m) % m

function powMod (base, exp, m) {
  let r = 1n
  base = mod(base, m)
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % m
    base = (base * base) % m
    exp >>= 1n
  }
  return r
}

// P and N are prime, so Fermat gives the inverse without an extended-Euclid implementation.
const inv = (a, m) => powMod(a, m - 2n, m)

// ── affine point arithmetic (null = point at infinity) ─────────────────────────────────
function add (a, b) {
  if (a === null) return b
  if (b === null) return a
  const [x1, y1] = a
  const [x2, y2] = b
  let m
  if (x1 === x2) {
    if (mod(y1 + y2, P) === 0n) return null // Q + (-Q)
    m = mod(3n * x1 * x1 * inv(2n * y1, P), P) // tangent (a = 0 curve)
  } else {
    m = mod((y2 - y1) * inv(x2 - x1, P), P)
  }
  const x3 = mod(m * m - x1 - x2, P)
  return [x3, mod(m * (x1 - x3) - y1, P)]
}

function mul (point, k) {
  let acc = null
  while (k > 0n) {
    if (k & 1n) acc = add(acc, point)
    point = add(point, point)
    k >>= 1n
  }
  return acc
}

const beInt = bytes => { let v = 0n; for (const b of bytes) v = (v << 8n) | BigInt(b); return v }

// ── SEC point decoding ─────────────────────────────────────────────────────────────────
function decodePoint (pub) {
  if (pub.length === 33 && (pub[0] === 2 || pub[0] === 3)) {
    const x = beInt(pub.subarray(1))
    if (x >= P) throw new Error('pubkey x out of field range')
    const y2 = mod(powMod(x, 3n, P) + 7n, P)
    let y = powMod(y2, (P + 1n) / 4n, P) // sqrt: valid because P % 4 == 3
    if (mod(y * y, P) !== y2) throw new Error('pubkey x is not on the curve')
    if (Number(y & 1n) !== (pub[0] & 1)) y = P - y // match the encoded parity
    return [x, y]
  }
  if (pub.length === 65 && (pub[0] === 4 || pub[0] === 6 || pub[0] === 7)) {
    const x = beInt(pub.subarray(1, 33))
    const y = beInt(pub.subarray(33))
    if (x >= P || y >= P || mod(y * y - powMod(x, 3n, P) - 7n, P) !== 0n) {
      throw new Error('pubkey point is not on the curve')
    }
    // hybrid 06/07: libsecp requires the parity byte to match y
    if (pub[0] !== 4 && Number(y & 1n) !== (pub[0] & 1)) throw new Error('hybrid pubkey parity mismatch')
    return [x, y]
  }
  throw new Error('pubkey must be 33-byte compressed or 65-byte uncompressed/hybrid SEC')
}

// ── strict DER parsing, mirroring libsecp256k1 ecdsa_signature_parse_der ───────────────
// Structural violations throw; a negative or overflowing INTEGER parses to 0 (libsecp's
// "overflow" rule), so verification returns false rather than throwing.
function readLen (buf, i) {
  if (i >= buf.length) throw new Error('DER: truncated length')
  const b = buf[i++]
  if (b < 0x80) return [b, i]
  const n = b & 0x7f
  if (n === 0 || n > 4 || i + n > buf.length) throw new Error('DER: bad long-form length')
  if (buf[i] === 0) throw new Error('DER: non-minimal long-form length')
  let len = 0
  for (let j = 0; j < n; j++) len = (len << 8) | buf[i + j]
  if (len < 0x80) throw new Error('DER: long form used where short form fits')
  return [len, i + n]
}

function readInt (buf, i) {
  if (i >= buf.length || buf[i] !== 0x02) throw new Error('DER: expected INTEGER')
  const [len, j] = readLen(buf, i + 1)
  if (len === 0 || j + len > buf.length) throw new Error('DER: bad INTEGER length')
  const body = buf.subarray(j, j + len)
  if (len > 1 && body[0] === 0x00 && !(body[1] & 0x80)) throw new Error('DER: excess 0x00 padding')
  if (len > 1 && body[0] === 0xff && (body[1] & 0x80)) throw new Error('DER: excess 0xFF padding')
  if (body[0] & 0x80) return [0n, j + len] // negative -> overflow -> scalar 0
  const v = beInt(body)
  return [v >= N ? 0n : v, j + len]
}

function parseDer (sig) {
  if (!sig.length || sig[0] !== 0x30) throw new Error('DER: expected SEQUENCE')
  const [len, i0] = readLen(sig, 1)
  if (len !== sig.length - i0) throw new Error('DER: length mismatch / trailing garbage')
  const [r, i1] = readInt(sig, i0)
  const [s, i2] = readInt(sig, i1)
  if (i2 !== sig.length) throw new Error('DER: trailing garbage inside SEQUENCE')
  return [r, s]
}

/**
 * True iff `derSig` is a valid secp256k1 ECDSA signature over sha256(message) by `pubkey`.
 * Throws exactly where the reference throws (malformed DER / malformed point); otherwise returns
 * false, meaning a check RAN and failed.
 * @param {Uint8Array} pubkey 33-byte compressed, or 65-byte uncompressed/hybrid SEC
 * @param {Uint8Array} derSig
 * @param {Uint8Array} messageHash32 sha256 of the signed message
 */
export function verifyDerHash (pubkey, derSig, messageHash32) {
  const q = decodePoint(pubkey)
  const [r, s] = parseDer(derSig)
  if (!(r >= 1n && r < N && s >= 1n && s < N)) return false // zero / overflowed scalar
  if (s > N / 2n) return false // high-S rejected, as libsecp256k1 does
  const z = mod(beInt(messageHash32), N)
  const w = inv(s, N)
  const rp = add(mul(G, mod(z * w, N)), mul(q, mod(r * w, N)))
  if (rp === null) return false
  return mod(rp[0], N) === r
}
