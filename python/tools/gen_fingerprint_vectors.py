#!/usr/bin/env python3
"""Generate test-vectors/fingerprint-vectors.json: the inputs SPEC §7 accepts and rejects.

  * accept: names and versions every implementation MUST accept, with the exact fingerprint. They
    include the boundaries of the adopter-name profile (a space and U+00A0 are not control
    characters; a name may contain "nkan/" anywhere but at the start) and versions above 1.
  * reject: inputs every implementation MUST reject before hashing. `rule` names the erratum that
    makes each one a rejection (E21: the adopter-name profile; E22: positive-integer versions), or
    is null for a rule every port already enforces (the 255-byte limit).

Usage:  python3 python/tools/gen_fingerprint_vectors.py
"""
import hashlib
import json
import pathlib
import sys
import unicodedata

OUT = pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "fingerprint-vectors.json"
PAYLOAD = b"build-bytes-v1"


def cps(s):
    return ["%04X" % ord(c) for c in s]


def fp(adopter, version, payload=PAYLOAD):
    """SPEC §7, written out: u8(len(a)) || a || "/inkan/v" || dec(version) || 0x00 || payload."""
    a = unicodedata.normalize("NFC", adopter).encode("utf-8")
    assert len(a) <= 255 and isinstance(version, int) and version >= 1
    return hashlib.sha256(bytes([len(a)]) + a + b"/inkan/v" + str(version).encode() + b"\x00"
                          + payload).hexdigest()


def main():
    accept = []
    for name, adopter, version in [
        ("version-1", "acme", 1),
        ("version-2", "acme", 2),
        ("version-10", "acme", 10),
        ("decomposed-name", "café", 1),
        ("precomposed-name", "café", 1),
        ("space-is-printable", "acme labs", 1),
        ("nbsp-is-printable", "acme labs", 1),
        ("nkan-without-slash", "nkan", 1),
        ("nkan-slash-not-at-start", "x-nkan/v1", 1),
        ("inkan-prefix", "inkan/v1", 1),
        ("255-bytes", "a" * 255, 1),
    ]:
        accept.append({"name": name, "adopter": cps(adopter), "payload_utf8": PAYLOAD.decode(),
                       "version": version, "fingerprint_hex": fp(adopter, version)})
    assert accept[3]["fingerprint_hex"] == accept[4]["fingerprint_hex"]

    collision = "nkan/v1\x00" + "z" * 97
    assert bytes([len(collision.encode())]) + collision.encode() == b"inkan/v1\x00" + b"z" * 97
    reject = [
        ("nkan-prefix-collides-with-anchor-domain", collision, 1, "E21"),
        ("nkan-prefix", "nkan/x", 1, "E21"),
        ("nul", "a\x00b", 1, "E21"),
        ("tab", "acme\tlabs", 1, "E21"),
        ("line-feed", "acme\n", 1, "E21"),
        ("delete", "acme\x7f", 1, "E21"),
        ("c1-control", "acme\x85", 1, "E21"),
        ("256-bytes", "a" * 256, 1, None),
        ("version-0", "acme", 0, "E22"),
        ("version-negative", "acme", -1, "E22"),
        ("version-fraction", "acme", 1.5, "E22"),
    ]
    doc = {
        "comment": ("Tamper-fingerprint inputs (SPEC 7). Code points are hex. accept: every "
                    "implementation MUST accept and return exactly fingerprint_hex. reject: every "
                    "implementation MUST reject the input before hashing; 'rule' names the erratum "
                    "that makes it a rejection, or is null for a rule every implementation already "
                    "enforces. An adopter name must be well-formed (E4), contain no unassigned code "
                    "point (E14) and no code point in U+0000-U+001F or U+007F-U+009F, and must not "
                    "begin with 'nkan/' after NFC (E6, E21). A version is a positive integer (E22)."),
        "accept": accept,
        "reject": [{"name": n, "adopter": cps(a), "payload_utf8": PAYLOAD.decode(), "version": v,
                    "rule": r} for n, a, v, r in reject],
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n")
    print(f"wrote {OUT}: {len(accept)} accept, {len(reject)} reject")


if __name__ == "__main__":
    sys.exit(main())
