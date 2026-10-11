#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Emit the Inkan sidecar seal for any distributable artifact.

A Code Inkan is a digest of an artifact's bytes, so it cannot live INSIDE that artifact: embedding
it would change the bytes and invalidate the digest it just recorded. The seal is therefore written
BESIDE the file, never into it:

    <artifact>.inkan.png    the tagged canonical seal (human eyeball + pixel-verify)
    <artifact>.inkan.json   the machine reference {fingerprint, code, ...}

The anchor is SHA-256 over the WHOLE artifact, so it covers every byte actually shipped rather than
some curated subset. The schema is the one an application-side reader consumes when it checks a
bundled copy, so one verification path serves every consumer.

Self-verification without any extra machinery, but mind WHICH digest. Two are recorded and they are
not interchangeable:

    fingerprint          plain SHA-256 over the bytes; the anchor an application-side reader
                         recomputes. Adopter-independent. Reproduce with `sha256sum <artifact>`.
    adopter_fingerprint  SHA256(u8(len(adopter)) || adopter || "/inkan/v<n>" || 0x00 || bytes) --
                         precisely what the web verifier's fingerprint card computes.

To verify the web verifier with itself: save the page, open its fingerprint card, enter the
`adopter` and `fingerprint_version` from the sidecar, and compare to `adopter_fingerprint`.
Comparing against `fingerprint` instead will always mismatch and look like tampering.

SEQUENCING: the seal is only valid for the exact bytes present when it was taken. Emit it LAST,
after the artifact is final; any rebuild invalidates it and it must be re-emitted. `nft` stays null
until the seal is inscribed as a 1Sat ordinal and its outpoint is recorded.

Usage:
    python3 tools/emit_sidecar_seal.py <artifact> [<artifact> ...] [--version V] [--adopter NAME]
    python3 tools/emit_sidecar_seal.py --json web/inkan-verify.html      # machine-readable
    python3 tools/emit_sidecar_seal.py --check web/inkan-verify.html     # re-verify, emit nothing
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))

from inkan_standard import seal as inkan_seal                                   # noqa: E402
from inkan_standard.seed import inkan_code, inkan_digest                        # noqa: E402
from inkan_standard.fingerprint import fingerprint_hex                          # noqa: E402

KIND = "code"
CHUNK = 1 << 20


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def seal_for(path: str, version: str | None, adopter: str | None) -> dict:
    fingerprint = sha256_file(path)
    # TWO digests, deliberately, because they answer different questions and are NOT interchangeable:
    #   fingerprint        = plain SHA-256 over the bytes. What an application-side reader
    #                        recomputes and string-compares. Adopter-independent.
    #   adopter_fingerprint = SHA256(u8(len(adopter)) || adopter || "/inkan/v<n>" || 0x00 || bytes).
    #                        This is what the web verifier's fingerprint card produces, so it is the
    #                        value a user can reproduce with nothing but the page itself.
    # Recording only the first would make the page unable to verify its own artifact: a user feeding
    # the file to the card would get a different hex and read it as tampering.
    adopter_fp = fingerprint_hex(open(path, "rb").read(), adopter, 1) if adopter else None
    return {
        "fingerprint": fingerprint,                      # recompute + string-compare this
        "code": inkan_code(fingerprint, KIND),           # ik1<anchor hex> — self-identifying label
        "kind": KIND,
        "version": version,
        "adopter": adopter,
        "adopter_fingerprint": adopter_fp,   # reproducible in the web verifier's fingerprint card
        "fingerprint_version": 1,
        "seal_version": getattr(inkan_seal, "SEAL_VERSION", None),
        "target": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        # The .inkan.png IS the content to inscribe as a 1Sat ordinal. Null until it is inscribed and
        # the mint records {"outpoint","txid","vout","height","date"}.
        "nft": None,
        "note": "sidecar seal; not yet inscribed on chain (nft records the 1Sat ordinal once it is)",
    }


def emit(path: str, version: str | None, adopter: str | None) -> dict:
    ref = seal_for(path, version, adopter)
    anchor = inkan_digest(ref["fingerprint"], KIND)
    png = inkan_seal.seal_png(anchor, kind=KIND, scale=8, tag=True)
    with open(path + ".inkan.png", "wb") as f:
        f.write(png)
    with open(path + ".inkan.json", "w", encoding="utf-8") as f:
        json.dump(ref, f, indent=2, sort_keys=True)
        f.write("\n")
    return ref


def check(path: str) -> tuple[bool, dict]:
    """Re-verify an artifact against its existing sidecar. Fail loud: a missing or unreadable
    reference is NOT a pass, it is an unverifiable artifact."""
    ref_path = path + ".inkan.json"
    if not os.path.isfile(ref_path):
        return False, {"ok": False, "target": os.path.basename(path),
                       "reason": "no sidecar reference at " + os.path.basename(ref_path)}
    try:
        with open(ref_path, "r", encoding="utf-8") as f:
            ref = json.load(f)
    except (OSError, ValueError) as exc:
        return False, {"ok": False, "target": os.path.basename(path),
                       "reason": "unreadable reference: %s" % exc}
    actual = sha256_file(path)
    ok = actual == ref.get("fingerprint")
    adopter_actual = None
    if ref.get("adopter"):
        adopter_actual = fingerprint_hex(open(path, "rb").read(), ref["adopter"],
                                         ref.get("fingerprint_version") or 1)
        ok = ok and adopter_actual == ref.get("adopter_fingerprint")
    return ok, {
        "ok": ok,
        "target": os.path.basename(path),
        "expected_fingerprint": ref.get("fingerprint"),
        "actual_fingerprint": actual,
        "expected_adopter_fingerprint": ref.get("adopter_fingerprint"),
        "actual_adopter_fingerprint": adopter_actual,
        "code": ref.get("code"),
        "nft": ref.get("nft"),
        "reason": None if ok else "fingerprint mismatch — these are not the sealed bytes",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Emit or check the Inkan sidecar seal for an artifact.")
    ap.add_argument("artifact", nargs="+")
    ap.add_argument("--version", default=None, help="build version recorded in the reference")
    ap.add_argument("--adopter", default=None, help="namespace this build is published under")
    ap.add_argument("--check", action="store_true", help="verify against an existing sidecar; write nothing")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON (for agents/CI)")
    args = ap.parse_args(argv)

    results, failed = [], False
    for path in args.artifact:
        if not os.path.isfile(path):
            failed = True
            results.append({"ok": False, "target": path, "reason": "not a file"})
            continue
        if args.check:
            ok, res = check(path)
            failed = failed or not ok
            results.append(res)
        else:
            results.append(emit(path, args.version, args.adopter))

    if args.json:
        json.dump(results if len(results) > 1 else results[0], sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for res in results:
            if args.check:
                print(("OK   " if res.get("ok") else "FAIL ") + str(res.get("target")))
                if not res.get("ok"):
                    print("  " + str(res.get("reason")))
            else:
                print("sealed", res["target"])
                print("  fingerprint :", res["fingerprint"])
                print("  code        :", res["code"])
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
