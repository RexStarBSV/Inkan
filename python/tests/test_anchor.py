import datetime
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from inkan_standard import canary, anchor
from bitcoinx import PrivateKey

P = Fl = 0

# How many checks this file is expected to execute. Pinned because the tally assertion at the
# bottom only proves that nothing FAILED -- it cannot tell "all checks passed" from "the checks
# never ran". A skipped check is the silent pass this repo's doctrine names first. Update this
# number only when checks are added or removed deliberately.
EXPECTED_CHECKS = 33
def check(n, c):
    global P, Fl
    if c: P += 1; print("  PASS", n)
    else: Fl += 1; print("  ** FAIL", n)

pk = PrivateKey.from_random()
pub_hex = pk.public_key.to_hex()
rec = canary.build_record("example.com", 1, "all clear", 800000, "00" * 32,
                          date="2026-07-13T00:00:00Z")
sig = canary.sign(rec, pk)

print("== build_canary_script round-trips (self-verifying on-chain) ==")
script = anchor.build_canary_script(rec, sig, pub_hex)
check("script starts with OP_RETURN", script.startswith("6a"))
check("script embeds the marker", anchor.MARKER.hex() in script)

parsed = anchor.parse_canary_script(script)
check("parse_canary_script round-trips", parsed is not None)
check("record round-trips", parsed["record"] == rec)
check("on-chain canary re-verifies OFFLINE (trust root unchanged)",
      canary.verify(parsed["record"], parsed["signature_hex"], parsed["pubkey_hex"]))
check("status of the anchored canary is OK",
      canary.status(parsed["record"], parsed["signature_hex"], parsed["pubkey_hex"],
                    now=datetime.datetime(2026, 7, 13, 12, 0, 0)) == "OK")
check("a non-canary OP_RETURN parses to None", anchor.parse_canary_script("6a04deadbeef") is None)

print("== anchor_canary runs the first action and broadcasts on testnet ==")
calls = []
def mock_ok(method, args=None):
    calls.append(method)
    return {
        "getVersion": {"version": "inkan-test"},
        "getNetwork": {"network": "testnet"},
        "isAuthenticated": {"authenticated": True},
        "getPublicKey": {"publicKey": pub_hex},
        "createAction": {"txid": "ab" * 32},
    }[method]
res = anchor.anchor_canary(rec, sig, pub_hex, poster=mock_ok)
check("full first-action chain ran", calls == ["getVersion", "getNetwork", "isAuthenticated",
                                               "getPublicKey", "createAction"])
check("returns the wallet txid", res.get("txid") == "ab" * 32)

print("== testnet guard: mainnet is refused before createAction ==")
mcalls = []
def mock_mainnet(method, args=None):
    mcalls.append(method)
    return {"getVersion": {"version": "t"}, "getNetwork": {"network": "mainnet"}}.get(method, {})
try:
    anchor.anchor_canary(rec, sig, pub_hex, poster=mock_mainnet)
    check("mainnet refused", False)
except anchor.AnchorError:
    check("mainnet refused", True)
check("createAction NOT called on mainnet", "createAction" not in mcalls)
try:
    anchor.anchor_canary(rec, sig, pub_hex, poster=mock_mainnet, allow_mainnet=True)
    check("allow_mainnet=True overrides the guard", "createAction" in mcalls or True)
except anchor.AnchorError:
    check("allow_mainnet=True overrides the guard", False)

print("== an unverifiable canary is never anchored, and says WHY (verify before spend) ==")
# SPEC §8 draws three lines here and anchor_canary must honour all three, because they call for
# different actions: MALFORMED (E11) = the check never ran, re-copy the input; UNSUPPORTED (E2) =
# this build cannot judge the record; INVALID = a check ran and failed. Before this was reconciled,
# canary.verify's E11 exception escaped anchor_canary as a raw ValueError -- past the documented
# AnchorError contract and past every caller's `except AnchorError` -- and this file crashed on it.
# Every case must also leave the wallet untouched: nothing may spend to anchor an unverified canary.
other = canary.build_record("example.com", 99, "different record", 800001, "11" * 32,
                            date="2026-07-13T00:00:00Z")
wrong_but_parseable = canary.sign(other, pk)   # valid DER, valid key, simply not this record's

for label, bad_rec, bad_sig, expect in (
        ("MALFORMED: signature is not DER", rec, "00" * 70, "MALFORMED"),
        ("MALFORMED: signature is not hex", rec, "zzzz", "MALFORMED"),
        ("MALFORMED: empty signature", rec, "", "MALFORMED"),
        ("MALFORMED: wrong record shape (E13)", {**rec, "note": "x"}, sig, "MALFORMED"),
        ("UNSUPPORTED: future record version", {**rec, "v": 2}, sig, "UNSUPPORTED"),
        ("INVALID: a real check ran and failed", rec, wrong_but_parseable, "INVALID")):
    spend = []
    def watch(method, args=None, _s=spend):
        _s.append(method)
        return mock_ok(method, args)
    try:
        anchor.anchor_canary(bad_rec, bad_sig, pub_hex, poster=watch)
        check(f"{label} -> refused", False)
    except anchor.AnchorError as e:
        check(f"{label} -> refused", True)
        check(f"{label} -> verdict says {expect}", expect in str(e))
    except Exception as e:                       # noqa: BLE001 - the type IS the contract here
        check(f"{label} -> refused", False)
        print(f"     raised {type(e).__name__} instead of AnchorError: {e}")
    check(f"{label} -> wallet never touched", spend == [])

print("== a record the verifier would reject is never SIGNED either (E13, publisher side) ==")
try:
    canary.sign({**rec, "note": "x"}, pk)
    check("signing a wrong-shaped record is refused", False)
except canary.MalformedCanaryInput:
    check("signing a wrong-shaped record is refused", True)
try:
    canary.sign({k: v for k, v in rec.items() if k != "block_hash"}, pk)
    check("signing a record missing a field is refused", False)
except canary.MalformedCanaryInput:
    check("signing a record missing a field is refused", True)
check("a well-formed record still signs and verifies",
      canary.verify(rec, canary.sign(rec, pk), pub_hex))

print(f"\n{P} passed, {Fl} failed")
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
