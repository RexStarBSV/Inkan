import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from inkan_standard import _secp256k1 as secp

P = Fl = 0

# How many checks this file is expected to execute. Pinned because the tally assertion at the
# bottom only proves that nothing FAILED -- it cannot tell "all checks passed" from "the checks
# never ran". A skipped check is the silent pass this repo's doctrine names first. Update this
# number only when checks are added or removed deliberately.
EXPECTED_CHECKS = 42
def check(n, c):
    global P, Fl
    if c: P += 1; print("  PASS", n)
    else: Fl += 1; print("  ** FAIL", n)

def raises_valueerror(fn):
    try:
        fn(); return False
    except ValueError:
        return True

def der(r, s):
    """Minimal DER encoder for crafting negative-test signatures."""
    def i2(v):
        b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = i2(r) + i2(s)
    return b"\x30" + bytes([len(body)]) + body

def comp(pt):
    x, y = pt
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")

vec_path = os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors", "vectors.json")
with open(vec_path) as fh:
    cv = json.load(fh)["canary"]
canon = cv["canonical_bytes_utf8"].encode("utf-8")
sig = bytes.fromhex(cv["signature_der_hex"])
pub = bytes.fromhex(cv["pubkey_hex"])
N = secp._N

print("== pinned vector (calibrated against bitcoinx: single sha256 of the message) ==")
check("pinned canary vector verifies", secp.verify_der(pub, sig, canon))
check("tampered record → False",
      not secp.verify_der(pub, sig, canon.replace(b"acme", b"evil")))
# single-vs-double sha256 is the calibration finding: pre-hashing must NOT verify
check("pre-hashed (double-sha256) message → False (bitcoinx hashes ONCE)",
      not secp.verify_der(pub, sig, hashlib.sha256(canon).digest()))

print("== wrong key (derived via own point math) ==")
other = comp(secp._mul(secp._G, int.from_bytes(b"\x02" * 32, "big")))
check("wrong key → False", not secp.verify_der(other, sig, canon))

print("== uncompressed key round-trip (privkey 01*32, own point math) ==")
pt = secp._mul(secp._G, int.from_bytes(b"\x01" * 32, "big"))
check("own math → compressed encoding matches pinned pubkey", comp(pt) == pub)
unc = b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
check("uncompressed key verifies pinned sig", secp.verify_der(unc, sig, canon))
# hybrid SEC (0x06 even / 0x07 odd): libsecp256k1 ACCEPTS these when the parity byte
# matches y — proven differentially vs bitcoinx; wrong parity is a parse error there.
hyb = bytes([6 + (pt[1] & 1)]) + unc[1:]
check("hybrid key (correct parity) verifies pinned sig", secp.verify_der(hyb, sig, canon))
hyb_bad = bytes([6 + ((pt[1] & 1) ^ 1)]) + unc[1:]
check("hybrid key with wrong parity raises",
      raises_valueerror(lambda: secp.verify_der(hyb_bad, sig, canon)))

print("== malformed DER RAISES (bitcoinx raises InvalidSignature on these) ==")
r0, s0 = secp._parse_der(sig)
check("truncated DER raises", raises_valueerror(lambda: secp.verify_der(pub, sig[:-1], canon)))
check("trailing garbage raises", raises_valueerror(lambda: secp.verify_der(pub, sig + b"\x00", canon)))
check("empty sig raises", raises_valueerror(lambda: secp.verify_der(pub, b"", canon)))
check("garbage sig raises", raises_valueerror(lambda: secp.verify_der(pub, b"\x01\x02\x03", canon)))
def i2(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b
rb = r0.to_bytes(34, "big")  # top-bit-set r needs 33 bytes; a 34-byte form is EXCESS 0x00 padding
body = b"\x02" + bytes([len(rb)]) + rb + i2(s0)
check("non-minimal INTEGER (excess 0x00 pad) raises",
      raises_valueerror(lambda: secp.verify_der(pub, b"\x30" + bytes([len(body)]) + body, canon)))
body = i2(r0) + i2(s0)
check("non-minimal long-form SEQUENCE length raises",
      raises_valueerror(lambda: secp.verify_der(pub, b"\x30\x81" + bytes([len(body)]) + body, canon)))
check("malformed point (x not on curve) raises",
      raises_valueerror(lambda: secp.verify_der(b"\x02" + b"\x00" * 32, sig, canon)))
check("bad pubkey length raises", raises_valueerror(lambda: secp.verify_der(pub[:32], sig, canon)))

print("== out-of-range r/s return False (bitcoinx returns False, does not raise) ==")
check("r = 0 → False", not secp.verify_der(pub, der(0, s0), canon))
check("s = 0 → False", not secp.verify_der(pub, der(r0, 0), canon))
check("r = n → False", not secp.verify_der(pub, der(N, s0), canon))
check("s = n → False", not secp.verify_der(pub, der(r0, N), canon))
check("high-S (n - s) → False (bitcoinx enforces low-S)",
      not secp.verify_der(pub, der(r0, N - s0), canon))
# BER-negative integer: libsecp parses it as overflow→0, so False — NOT a raise
neg = b"\x02\x20" + r0.to_bytes(32, "big")  # r0 has its top bit set: negative without pad
body = neg + i2(s0)
try:
    res = secp.verify_der(pub, b"\x30" + bytes([len(body)]) + body, canon)
    check("BER-negative INTEGER → False, no raise (matches bitcoinx)", res is False)
except ValueError:
    check("BER-negative INTEGER → False, no raise (matches bitcoinx)", False)

print("== randomized cross-check: sign with bitcoinx, verify with fallback ==")
try:
    from bitcoinx import PrivateKey
    HAVE_BX = True
except ImportError:
    HAVE_BX = False
if not HAVE_BX:
    print("  ** SKIP: bitcoinx not installed — 20 sign-there/verify-here cross-checks NOT run")
    print("  **       pinned-vector and negative cases above still exercise the fallback")
else:
    for i in range(20):
        kb = hashlib.sha256(b"inkan-test-" + str(i).encode()).digest()   # deterministic keys
        msg = b"inkan fallback cross-check message #" + str(i).encode()
        pk = PrivateKey(kb)
        s = pk.sign(msg)                       # bitcoinx default: single sha256 of msg
        pb = pk.public_key.to_bytes(compressed=(i % 2 == 0))  # alternate SEC encodings
        ok = secp.verify_der(pb, s, msg) and not secp.verify_der(pb, s, msg + b"!")
        check("cross-check #%d (key sha256('inkan-test-%d'), %scompressed)"
              % (i, i, "" if i % 2 == 0 else "un"), ok)

print(f"\nRESULT: {P} passed, {Fl} failed")
# Guarded so a test runner can IMPORT this file. An unguarded module-level sys.exit aborts pytest
# collection with INTERNALERROR and takes the other suites in this directory down with it, so
# `pytest tests/` reported "no tests ran" for all four. Running this file directly is unchanged:
# it still exits non-zero when a check failed.
if __name__ == "__main__":
    sys.exit(1 if Fl else 0)


def test_every_check_in_this_file_passed():
    """Surfaces this file's own tally to the test runner.

    The checks above execute at import time and only PRINTED their result. A runner that imported
    this module therefore ran every check and then reported success no matter how many had failed.
    This repo's doctrine names that failure mode first -- see the note above `unittest.main()` in
    tests/test_verify.py: a suite that passes by not running, or by not looking at, its tests.
    """
    assert Fl == 0, "%d of %d checks failed; run this file directly to see which" % (Fl, P + Fl)
    assert P + Fl == EXPECTED_CHECKS, (
        "expected %d checks, %d ran -- a check was SKIPPED rather than failed, so a green result "
        "here would mean nothing. Update EXPECTED_CHECKS only for a deliberate change."
        % (EXPECTED_CHECKS, P + Fl))
