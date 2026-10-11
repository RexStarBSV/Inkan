#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Mint a warrant canary: build the record, sign it, and emit the on-chain output.

This is the OPERATOR side of the canary. The verification path (`python -m inkan_standard.verify canary`)
is what everyone else runs; this is the half only the publisher runs, and it deliberately does
**not broadcast**. It prints the record, the signature, the public key and the locking script, and
stops. Broadcasting spends money and is a separate, deliberate act; `inkan_standard.anchor.anchor_canary`
does it when you decide to.

THE SIGNING SEAM, AND WHY THERE IS ONE. The canary key is a mass-distribution key: whoever holds
it can publish "still uncompromised" on your behalf forever. It should be born and used on a
machine that has never been on a network. But signing here needs a secp256k1 implementation, and
the bundled pure-Python curve in `inkan_standard._secp256k1` verifies only, so an in-process sign requires
a compiled dependency the air-gapped machine may not have. Rather than force the key onto a
networked machine, this tool splits:

    --unsigned            build the record and print the exact bytes to sign, then stop.
    --signature/--pubkey  take a signature produced elsewhere, verify it, and assemble the output.

So the record can be prepared anywhere, carried to the offline signer, signed there, and carried
back, with this tool checking at every step that what came back verifies before it is published.
Passing an issuer key directly still works for a machine that is legitimately offline and has a
signing backend available.

NOTHING UNVERIFIED IS EVER PRINTED. Whatever route produced the signature, the record and the
signature are checked together before the script is emitted, because a canary that fails to verify
reads as MALFORMED or INVALID at every reader, and on a canary those verdicts mean "the publisher
may be compromised". Emitting one by accident is a false alarm of the most expensive kind.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inkan_standard import anchor, canary  # noqa: E402


def _load_key(args):
    """The issuer key, or None when the signature is coming from elsewhere.

    A WIF is returned as the string it is, because `canary.sign` accepts one directly. Raw hex is
    NOT interchangeable with a WIF and must be turned into a key object here: `canary.sign` treats
    any non-key argument as WIF, so handing it hex fails deep inside base58 decoding with an error
    about an invalid character, which says nothing about the actual mistake. The import is local so
    that the --unsigned path, which needs no signing backend at all, keeps working without one."""
    if args.issuer_wif:
        return args.issuer_wif
    if args.issuer_hex:
        h = args.issuer_hex.strip()
        try:
            raw = bytes.fromhex(h)
        except ValueError:
            raise SystemExit("--issuer-hex is not hex. For a WIF use --issuer-wif.")
        if len(raw) != 32:
            raise SystemExit("--issuer-hex must be 32 bytes (64 hex chars), got %d" % len(raw))
        from bitcoinx import PrivateKey
        return PrivateKey(raw)
    env = os.environ.get("INKAN_CANARY_ISSUER_WIF")
    if env:
        return env
    return None


def _pubkey_hex(privkey) -> str:
    """Compressed public key for `privkey`. Needs a signing backend, so it is only reached on the
    in-process path; the split path takes the public key as an argument instead."""
    from bitcoinx import PrivateKey
    pk = privkey if hasattr(privkey, "public_key") else PrivateKey.from_WIF(privkey)
    return pk.public_key.to_bytes(compressed=True).hex()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Mint a warrant canary. Does not broadcast.")
    ap.add_argument("--domain", required=True,
                    help="publisher identifier, the same value every reader pins")
    ap.add_argument("--seq", required=True, type=int,
                    help="monotonic sequence number; a reader rejects a record that goes backwards")
    ap.add_argument("--statement", required=True,
                    help="the human-readable assertion this record makes")
    ap.add_argument("--block-height", required=True, type=int,
                    help="a recent chain-tip height; this is the anti-backdate proof")
    ap.add_argument("--block-hash", required=True,
                    help="that tip's block hash")
    ap.add_argument("--date", default=None,
                    help="UTC YYYY-MM-DDTHH:MM:SSZ (default: now)")
    ap.add_argument("--issuer-wif", default=None)
    ap.add_argument("--issuer-hex", default=None)
    ap.add_argument("--unsigned", action="store_true",
                    help="print the record and the exact bytes to sign, then stop")
    ap.add_argument("--signature", default=None,
                    help="DER signature hex produced elsewhere (with --pubkey)")
    ap.add_argument("--pubkey", default=None,
                    help="33-byte compressed public key hex (with --signature)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)

    record = canary.build_record(domain=a.domain, seq=a.seq, statement=a.statement,
                                 block_height=a.block_height, block_hash=a.block_hash,
                                 date=a.date)
    # build_record cannot produce a wrong shape, but a future caller might, and the shape check is
    # cheap. Failing here costs a re-run; failing after publication costs an alarm.
    canary._check_shape(record)
    canonical = canary.canonical_bytes(record)

    if a.unsigned:
        out = {"record": record,
               "canonical_bytes_hex": canonical.hex(),
               "message_hash_hex": canary.message_hash(record).hex(),
               "note": "sign canonical_bytes with the canary issuer key, then re-run with "
                       "--signature and --pubkey and the identical record arguments"}
        print(json.dumps(out, indent=2) if a.json else
              "record:\n%s\n\ncanonical bytes (sign these):\n%s\n"
              % (json.dumps(record, indent=2), canonical.hex()))
        return 0

    if bool(a.signature) != bool(a.pubkey):
        raise SystemExit("--signature and --pubkey are used together: a signature without its key "
                         "cannot be verified, and this tool does not print what it cannot verify")

    if a.signature:
        sig_hex, pub_hex = a.signature, a.pubkey
    else:
        key = _load_key(a)
        if not key:
            raise SystemExit("no issuer key: pass --issuer-wif / --issuer-hex, set "
                             "INKAN_CANARY_ISSUER_WIF, or use --unsigned and sign offline")
        sig_hex = canary.sign(record, key)
        pub_hex = _pubkey_hex(key)

    # The gate. `verify` raises MalformedCanaryInput when the key or signature does not parse and
    # returns False when a check ran and failed; both must stop us here.
    if not canary.verify(record, sig_hex, pub_hex):
        raise SystemExit("the signature does not verify against this record and key. Nothing is "
                         "printed: publishing this would read INVALID at every verifier, which on "
                         "a canary asserts the publisher may be compromised.")

    script_hex = anchor.build_canary_script(record, sig_hex, pub_hex)
    result = {"record": record, "signature": sig_hex, "pubkey": pub_hex,
              "script_hex": script_hex, "broadcast": False}
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        print("record:\n%s\n" % json.dumps(record, indent=2))
        print("signature : %s" % sig_hex)
        print("pubkey    : %s" % pub_hex)
        print("script    : %s" % script_hex)
        print("\nverified offline. NOT broadcast.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
