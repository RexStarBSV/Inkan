#!/usr/bin/env python3
"""Generate test-vectors/canary-vectors.json: canary records and the verdict each must get.

Each case is a record as JSON TEXT, exactly as it would be read from the wire (§8.1), signed with
the published test key (private key 0x01 repeated, the key of BRC-145 TV7). A verifier parses the
text, applies SPEC §8 and reports one of OK, STALE, INVALID, MALFORMED or UNSUPPORTED at the fixed
time `now` with `max_age_days`. `rule` names the erratum that decides a case (E23: the canary input
rules), or is null for behaviour every conforming verifier already has.

Signatures are made over the bytes SPEC §8 defines as canonical for the record. Where a record
breaks the input rules there is no canonical form, so the signature is over the bytes a verifier
without those rules would compute; such a case is MALFORMED whatever its signature, and the
signature exists only so that a verifier that skips the rules reports OK or INVALID visibly.

Signing needs bitcoinx (operator-side). Usage:  python3 python/tools/gen_canary_vectors.py
"""
import json
import pathlib
import sys

from bitcoinx import PrivateKey

OUT = pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "canary-vectors.json"
KEY = PrivateKey(bytes.fromhex("01" * 32))
BASE = {"block_hash": "00ff" * 16, "block_height": 870000, "date": "2026-06-30T00:00:00Z",
        "domain": "acme", "seq": 7, "statement": "No warrant, gag, key compromise or coercion.",
        "v": 1}
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def jstr(s):
    """SPEC §8 string escaping: the seven short escapes, \\u00xx (lower-case hex) for any other code
    point below U+0020, every other code point as itself. A lone surrogate (not well-formed text)
    is written as \\udxxx here only to build a deliberately malformed case."""
    out = []
    for c in s:
        if c in _ESC:
            out.append(_ESC[c])
        elif ord(c) < 0x20 or 0xD800 <= ord(c) <= 0xDFFF:
            out.append("\\u%04x" % ord(c))
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def canonical_text(rec):
    def val(v):
        return jstr(v) if isinstance(v, str) else (repr(v) if isinstance(v, float) else str(v))
    return "{" + ",".join(jstr(k) + ":" + val(rec[k]) for k in sorted(rec)) + "}"


def case(name, expect, rule, rec=None, text=None, sig=None, pub=None, note=None):
    text = text if text is not None else canonical_text(rec)
    sig = sig or KEY.sign(text.encode("utf-8", "surrogatepass")).hex()
    c = {"name": name, "record_json": text, "signature_der_hex": sig, "expect": expect, "rule": rule}
    if pub:
        c["pubkey_hex"] = pub
    if note:
        c["note"] = note
    return c


def high_s(der_hex):
    der = bytes.fromhex(der_hex)
    rl = der[3]; r = int.from_bytes(der[4:4 + rl], "big")
    sl = der[5 + rl]; s = int.from_bytes(der[6 + rl:6 + rl + sl], "big")

    def enc(x):
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        return b"\x00" + b if b[0] & 0x80 else b
    body = b"\x02" + bytes([len(enc(r))]) + enc(r) + b"\x02" + bytes([len(enc(N - s))]) + enc(N - s)
    return (b"\x30" + bytes([len(body)]) + body).hex()


def main():
    tv7 = case("tv7", "OK", None, BASE)
    tampered = canonical_text(dict(BASE, statement="We were compromised."))
    cases = [
        tv7,
        case("tv7-high-s-twin", "INVALID", None, BASE, sig=high_s(tv7["signature_der_hex"]),
             note="the same signature with S replaced by n - S; mathematically valid, never produced "
                  "by a low-S signer, and reported INVALID"),
        case("tampered-statement", "INVALID", None, text=tampered, sig=tv7["signature_der_hex"]),
        case("seq-max-safe-integer", "OK", None, dict(BASE, seq=2 ** 53 - 1)),
        case("escaping", "OK", None,
             dict(BASE, statement='q" b\\ \b\f\n\r\t \x01\x1f \x7f    café \U0001F600'),
             note="the canonical bytes escape exactly the seven short forms and other code points "
                  "below U+0020; U+007F, U+2028, U+2029 and all non-ASCII are written as themselves"),
        case("leap-day-is-a-real-date", "STALE", None, dict(BASE, date="2024-02-29T00:00:00Z")),
        case("unsupported-version", "UNSUPPORTED", None, dict(BASE, v=2)),
        case("version-as-string", "UNSUPPORTED", None, dict(BASE, v="1")),
        case("extra-field", "MALFORMED", None, dict(BASE, alg="ecdsa")),
        case("public-key-not-hex", "MALFORMED", None, BASE, pub="02zz"),
        # E23: the input rules
        case("seq-2-pow-53-plus-1", "MALFORMED", "E23", dict(BASE, seq=2 ** 53 + 1)),
        case("seq-nanosecond-timestamp", "MALFORMED", "E23", dict(BASE, seq=1760112000123456789)),
        case("seq-negative", "MALFORMED", "E23", dict(BASE, seq=-1)),
        case("seq-fraction", "MALFORMED", "E23", dict(BASE, seq=7.5)),
        case("block-height-2-pow-53", "MALFORMED", "E23", dict(BASE, block_height=2 ** 53)),
        case("date-not-zero-padded", "MALFORMED", "E23", dict(BASE, date="2026-6-30T0:0:0Z")),
        case("date-hour-24", "MALFORMED", "E23", dict(BASE, date="2026-06-29T24:00:00Z")),
        case("date-second-60", "MALFORMED", "E23", dict(BASE, date="2026-06-30T23:59:60Z")),
        case("date-february-30", "MALFORMED", "E23", dict(BASE, date="2026-02-30T00:00:00Z")),
        case("date-fullwidth-digits", "MALFORMED", "E23",
             dict(BASE, date="２０２６-06-30T00:00:00Z")),
        case("date-lowercase-z", "MALFORMED", "E23", dict(BASE, date="2026-06-30T00:00:00z")),
        case("date-space-separator", "MALFORMED", "E23", dict(BASE, date="2026-06-30 00:00:00Z")),
        case("statement-lone-surrogate", "MALFORMED", "E23", dict(BASE, statement="ok \ud800")),
        case("record-not-canonical", "MALFORMED", "E23",
             text=canonical_text(BASE).replace('"domain":"acme"', '"domain": "acme"'),
             sig=tv7["signature_der_hex"],
             note="the wire bytes are not the canonical encoding of the record they parse to"),
    ]
    # The form of the key and signature (SPEC §8 E23): hexadecimal text in either case, with only the
    # listed blank characters ignored around it. TV7's own record, key and signature, written out
    # differently.
    sig, pub = tv7["signature_der_hex"], KEY.public_key.to_hex()
    cases += [
        case("hex-upper-case", "OK", None, BASE, sig=sig.upper(), pub=pub.upper()),
        case("hex-blank-space-around", "OK", None, BASE, sig="\t " + sig + "\r\n",
             pub="\u00a0" + pub + "\u3000",
             note="blank space around the hex is ignored: U+0009-U+000D, U+0020, U+00A0, U+1680, "
                  "U+2000-U+200A, U+2028, U+2029, U+202F, U+205F and U+3000"),
        case("signature-0x-prefix", "MALFORMED", "E23", BASE, sig="0x" + sig),
        case("public-key-0x-prefix", "MALFORMED", "E23", BASE, pub="0x" + pub),
        case("signature-spaces-between-pairs", "MALFORMED", "E23", BASE,
             sig=" ".join(sig[i:i + 2] for i in range(0, len(sig), 2))),
        case("public-key-spaces-between-pairs", "MALFORMED", "E23", BASE,
             pub=" ".join(pub[i:i + 2] for i in range(0, len(pub), 2))),
        case("signature-tab-inside", "MALFORMED", "E23", BASE, sig=sig[:8] + "\t" + sig[8:]),
        case("signature-byte-order-mark-around", "MALFORMED", "E23", BASE,
             sig="\ufeff" + sig + "\ufeff"),
        case("public-key-next-line-around", "MALFORMED", "E23", BASE, pub="\x85" + pub + "\x85"),
    ]
    doc = {
        "comment": ("Canary records (SPEC 8, E23). record_json is the record exactly as read from "
                    "the wire; parse it, then report the verdict at time 'now' with max_age_days. "
                    "'rule' names the erratum that decides the case, or is null for behaviour every "
                    "conforming verifier already has. signature_der_hex, and pubkey_hex (the "
                    "case's own, else this one), are given to the verifier exactly as written. All "
                    "signatures use the published test key (private key 0x01 x 32), never a "
                    "production key."),
        "pubkey_hex": KEY.public_key.to_hex(),
        "now": "2026-07-01T00:00:00Z",
        "max_age_days": 35,
        "cases": cases,
    }
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n")
    print(f"wrote {OUT}: {len(cases)} cases")


if __name__ == "__main__":
    sys.exit(main())
