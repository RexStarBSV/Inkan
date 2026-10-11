# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 RexStarBSV
# Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
"""
inkan_standard._secp256k1 — pure-stdlib secp256k1 ECDSA *verification* fallback.

Verify-only: no signing, no key generation, no secret material — every input is public,
so constant-time discipline is deliberately out of scope. Semantics are calibrated by
EXPERIMENT against bitcoinx (libsecp256k1) on the pinned vectors in
test-vectors/vectors.json (see tests/test_secp_fallback.py):

  * The message is hashed ONCE with SHA-256 — bitcoinx `verify_der_signature`'s default
    hasher is single sha256 (the pinned canary sig verifies against sha256(canonical_bytes)
    and FAILS against double-sha256).
  * Malformed DER (trailing garbage, truncation, non-minimal lengths, excess padding) and
    malformed points RAISE ValueError — bitcoinx raises there too (InvalidSignature /
    ValueError); returning False would misreport "checked and bad" for "never parsed".
  * Out-of-range r/s (0 or >= n), BER-negative integers, and high-S return False — that is
    libsecp256k1's behaviour (negative/overflow parse to scalar 0; low-S is enforced).
"""
import hashlib

# secp256k1 domain parameters (SEC 2 v2, §2.4.1)
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


# ── affine point arithmetic (None = point at infinity) ───────────────────────────────

def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2:
        if (y1 + y2) % _P == 0:              # P + (-P)
            return None
        m = 3 * x1 * x1 * pow(2 * y1, -1, _P) % _P      # tangent (a=0 curve)
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    return x3, (m * (x1 - x3) - y1) % _P


def _mul(point, k):
    """Double-and-add. Public inputs only — no constant-time requirement."""
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, point)
        point = _add(point, point)
        k >>= 1
    return acc


# ── SEC point decoding (raises ValueError, as bitcoinx PublicKey.from_bytes does) ────

def _decode_point(pub):
    if len(pub) == 33 and pub[0] in (2, 3):
        x = int.from_bytes(pub[1:], "big")
        if x >= _P:
            raise ValueError("pubkey x out of field range")
        y2 = (pow(x, 3, _P) + 7) % _P
        y = pow(y2, (_P + 1) // 4, _P)       # sqrt: valid because P % 4 == 3
        if y * y % _P != y2:
            raise ValueError("pubkey x is not on the curve")
        if (y ^ pub[0]) & 1:                 # match the encoded parity
            y = _P - y
        return x, y
    if len(pub) == 65 and pub[0] in (4, 6, 7):
        x = int.from_bytes(pub[1:33], "big")
        y = int.from_bytes(pub[33:], "big")
        if x >= _P or y >= _P or (y * y - pow(x, 3, _P) - 7) % _P:
            raise ValueError("pubkey point is not on the curve")
        if pub[0] != 4 and (y ^ pub[0]) & 1:  # hybrid 06/07: parity byte must match y (libsecp)
            raise ValueError("hybrid pubkey parity mismatch")
        return x, y
    raise ValueError("pubkey must be 33-byte compressed or 65-byte uncompressed/hybrid SEC")


# ── strict DER parsing, mirroring libsecp256k1 ecdsa_signature_parse_der ─────────────
# Structural violations raise (bitcoinx raises InvalidSignature); a *negative* or
# *overflowing* INTEGER parses to 0 — libsecp's "overflow" rule — so verify returns False.

def _read_len(buf, i):
    if i >= len(buf):
        raise ValueError("DER: truncated length")
    b = buf[i]
    i += 1
    if b < 0x80:
        return b, i
    nbytes = b & 0x7F
    if nbytes == 0 or nbytes > 4 or i + nbytes > len(buf):
        raise ValueError("DER: bad long-form length")
    if buf[i] == 0:
        raise ValueError("DER: non-minimal long-form length")
    length = int.from_bytes(buf[i:i + nbytes], "big")
    if length < 0x80:
        raise ValueError("DER: long form used where short form fits")
    return length, i + nbytes


def _read_int(buf, i):
    if i >= len(buf) or buf[i] != 0x02:
        raise ValueError("DER: expected INTEGER")
    length, i = _read_len(buf, i + 1)
    if length == 0 or i + length > len(buf):
        raise ValueError("DER: bad INTEGER length")
    body = buf[i:i + length]
    if length > 1 and body[0] == 0x00 and not body[1] & 0x80:
        raise ValueError("DER: excess 0x00 padding")
    if length > 1 and body[0] == 0xFF and body[1] & 0x80:
        raise ValueError("DER: excess 0xFF padding")
    if body[0] & 0x80:                       # negative → overflow → scalar 0 (libsecp)
        return 0, i + length
    v = int.from_bytes(body, "big")
    return (0 if v >= _N else v), i + length


def _parse_der(sig):
    if not sig or sig[0] != 0x30:
        raise ValueError("DER: expected SEQUENCE")
    length, i = _read_len(sig, 1)
    if length != len(sig) - i:
        raise ValueError("DER: length mismatch / trailing garbage")
    r, i = _read_int(sig, i)
    s, i = _read_int(sig, i)
    if i != len(sig):
        raise ValueError("DER: trailing garbage inside SEQUENCE")
    return r, s


# ── public API ────────────────────────────────────────────────────────────────────────

def verify_der(pubkey_bytes: bytes, der_sig: bytes, message: bytes) -> bool:
    """True iff `der_sig` is a valid secp256k1 ECDSA signature over sha256(message) by
    `pubkey_bytes` (33-byte compressed, or 65-byte uncompressed/hybrid SEC — libsecp256k1
    accepts hybrid 0x06/0x07 when the parity byte matches y, so we do too). Single sha256 matches
    bitcoinx PublicKey.verify_der_signature's default hasher — proven on the pinned vector.
    Raises ValueError exactly where bitcoinx errors (malformed DER / malformed point);
    otherwise returns False, meaning a check RAN and failed."""
    q = _decode_point(bytes(pubkey_bytes))
    r, s = _parse_der(bytes(der_sig))
    if not (1 <= r < _N and 1 <= s < _N):
        return False                          # zero / overflowed scalar: bitcoinx → False
    if s > _N // 2:
        return False                          # high-S rejected, as libsecp256k1 does
    z = int.from_bytes(hashlib.sha256(message).digest(), "big") % _N
    w = pow(s, -1, _N)
    rp = _add(_mul(_G, z * w % _N), _mul(q, r * w % _N))
    if rp is None:
        return False
    return rp[0] % _N == r
