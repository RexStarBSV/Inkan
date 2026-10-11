#!/usr/bin/env python3
"""Generate test-vectors/unicode-vectors.json: text inputs and the Unicode database (SPEC E14).

NFC depends on the Unicode Character Database the normaliser uses, and every runtime ships its own
version. For a string whose code points are all assigned in some version V, Unicode's normalisation
stability policy fixes its NFC form in V and in every later version, so two implementations that
both know every code point agree, forever. A code point an implementation does not know has no
stable answer, so SPEC E14 makes it reject the input instead. The vectors therefore come in three
groups:

  * accept: every implementation MUST accept these and produce exactly this result. They contain
    only code points assigned since Unicode 1.1, private-use code points, and noncharacters (which
    E14 does not reject, because they are permanently unassigned and normalise to themselves).
  * either_or: an implementation whose database leaves any listed code point unassigned MUST reject
    the input; any other implementation MUST produce exactly `result_if_accepted`. `never` lists
    results that implementations without E14 produce today from older databases (informative).
  * reject_unless_assigned: code points unassigned in every database up to at least Unicode 17.0.
    An implementation whose database leaves them unassigned MUST reject; no accepted result is
    pinned yet, so an implementation whose database assigns them is not tested by that vector.

Every NFC form below is computed with this interpreter's unicodedata where it knows every code point
(checked), and otherwise taken from the Unicode 17.0 data, which the JavaScript port's tests
reproduce. Codes and fingerprints are then computed from those UTF-8 bytes directly.

Usage:  python3 python/tools/gen_unicode_vectors.py
"""
import hashlib
import json
import pathlib
import sys
import unicodedata

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from inkan_standard import seal
from inkan_standard.fingerprint import domain_prefix
from inkan_standard.seed import INKAN_DOMAIN, inkan_code

OUT = pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "unicode-vectors.json"


def cps(s):
    return ["%04X" % ord(c) for c in s]


def text(points):
    return "".join(chr(int(h, 16)) for h in points)


def known_here(s):
    """Every code point is assigned (or a noncharacter) in THIS interpreter's database."""
    return all(unicodedata.category(c) != "Cn" or _nonchar(ord(c)) for c in s)


def _nonchar(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def nfc(s, unicode17_nfc=None):
    if known_here(s):
        out = unicodedata.normalize("NFC", s)
        if unicode17_nfc is not None:
            assert out == unicode17_nfc, (cps(s), cps(out))
        return out
    assert unicode17_nfc is not None, "this database lacks a code point and no Unicode 17.0 form is given"
    return unicode17_nfc


def code_of(data_nfc, kind_nfc):
    k = kind_nfc.encode("utf-8")
    return "ik1" + hashlib.sha256(INKAN_DOMAIN + bytes([len(k)]) + k + data_nfc.encode("utf-8")).hexdigest()


def fp_of(adopter_nfc, payload):
    a = adopter_nfc.encode("utf-8")
    return hashlib.sha256(bytes([len(a)]) + a + b"/inkan/v1\x00" + payload).hexdigest()


def anchor_case(name, data, kind="", u17_data=None, u17_kind=None, since=None, never=()):
    d, k = nfc(data, u17_data), nfc(kind, u17_kind)
    v = {"name": name, "data": cps(data), "kind": cps(kind),
         "result_if_accepted": {"code": code_of(d, k), "resolve": list(seal.resolve_kind(kind)),
                                "data_nfc": cps(d), "kind_nfc": cps(k)}}
    if since:
        v["newest_code_point_assigned_in"] = since
    if never:
        v["never"] = sorted(set(never) - {v["result_if_accepted"]["code"]})
    return v


def adopter_case(name, adopter, payload, u17=None, since=None, never=()):
    a = nfc(adopter, u17)
    v = {"name": name, "adopter": cps(adopter), "payload_utf8": payload.decode(),
         "fingerprint_version": 1,
         "result_if_accepted": {"fingerprint_hex": fp_of(a, payload), "adopter_nfc": cps(a)}}
    if since:
        v["newest_code_point_assigned_in"] = since
    if never:
        v["never"] = sorted(set(never) - {v["result_if_accepted"]["fingerprint_hex"]})
    return v


def raw_code(data, kind=""):
    """The code an implementation gets when its NFC leaves the string unchanged (an old database)."""
    return inkan_code(data.encode("utf-8"), "") if not kind else code_of(data, kind)


def main():
    E, PEPET, CEDILLA, U1AD0 = "e", "ࢗ", "̧", "\U00001AD0"
    GK_AA = "\U0001611E"
    accept = [
        anchor_case("decomposed-cafe", "café"),
        anchor_case("precomposed-cafe", "café"),
        anchor_case("noncharacters-bmp", "a﷐b￾"),
        anchor_case("noncharacters-supplementary", "\U0010ffff\U0001fffe"),
        anchor_case("noncharacter-in-kind", "x", "nc:﷐@t3"),
        anchor_case("private-use", "\U000f0000"),
        adopter_case("noncharacter-in-adopter", "acme﷯", b"build-bytes-v1"),
    ]
    assert accept[0]["result_if_accepted"]["code"] == accept[1]["result_if_accepted"]["code"]
    # SPEC E19: typed text is text. The same characters taken as bytes give a different code, which a
    # tool that passes typed text as bytes reports (informative, never an accepted result for text).
    accept[0]["if_passed_as_bytes"] = inkan_code("cafe\u0301".encode("utf-8"), "")

    pepet = E + PEPET + CEDILLA                      # U+0897 ARABIC PEPET: assigned in Unicode 16.0
    u17 = E + U1AD0 + CEDILLA                        # U+1AD0: assigned in Unicode 17.0
    either_or = [
        anchor_case("pepet-reorders-and-composes", pepet, since="16.0",
                    never=[raw_code(pepet)]),
        anchor_case("u1ad0-reorders-and-composes", u17, u17_data="ȩ" + U1AD0, since="17.0",
                    never=[raw_code(u17)]),
        anchor_case("both", pepet + u17, u17_data="ȩ" + PEPET + "ȩ" + U1AD0, since="17.0",
                    never=[raw_code(pepet + u17),
                           inkan_code(("ȩ" + PEPET + u17).encode("utf-8"), "")]),
        anchor_case("gurung-khema-composes", GK_AA + GK_AA, since="16.0",
                    never=[raw_code(GK_AA + GK_AA)]),
        anchor_case("pepet-in-kind", "x", "ns:" + pepet, since="16.0",
                    never=[code_of("x", "ns:" + pepet)]),
        adopter_case("pepet-in-adopter", "acme-" + pepet, b"build-bytes-v1", since="16.0",
                     never=[fp_of("acme-" + pepet, b"build-bytes-v1")]),
    ]
    reject = [
        {"name": "u0378-in-data", "data": cps("a͸"), "kind": []},
        {"name": "plane-5-in-data", "data": cps("\U00050000"), "kind": []},
        {"name": "u0378-in-kind", "data": cps("x"), "kind": cps("x͸@t3")},
        {"name": "u0378-in-adopter", "adopter": cps("acme͸"), "payload_utf8": "build-bytes-v1",
         "fingerprint_version": 1},
    ]
    for v in reject:
        for f in ("data", "kind", "adopter"):
            assert all(unicodedata.category(c) == "Cn" for c in text(v.get(f, [])) if ord(c) > 0x7F)
        v["unassigned_through"] = "17.0"

    doc = {
        "comment": ("Text inputs and the Unicode database (SPEC 1, E14). Code points are hex. "
                    "accept: every implementation MUST accept and return exactly result_if_accepted. "
                    "either_or: an implementation whose Unicode database leaves any listed code point "
                    "unassigned (General_Category Cn, other than the 66 noncharacters) MUST reject "
                    "the input; every other implementation MUST return exactly result_if_accepted. "
                    "reject_unless_assigned: MUST be rejected while the implementation's database "
                    "leaves the code point unassigned; no accepted result is pinned yet. 'never' "
                    "lists results produced today by implementations without this rule "
                    "(informative). resolve is the SPEC 4 derivation of the kind as provided."),
        "rule": "E14",
        "accept": accept,
        "either_or": either_or,
        "reject_unless_assigned": reject,
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n")
    print(f"wrote {OUT}: {len(accept)} accept, {len(either_or)} either/or, {len(reject)} reject "
          f"(generated with Unicode {unicodedata.unidata_version})")


if __name__ == "__main__":
    main()
