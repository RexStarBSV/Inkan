# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 RexStarBSV
# Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
"""
inkan_standard.canary — warrant / compromise canary.

A canary is a signed, freshness-proofed statement that the operator is uncompromised and un-coerced.
**Absence, staleness, or a failed signature is the warning.** Publish each canary to an immutable,
timestamped anchor (e.g. a BSV 1Sat Ordinal / OP_RETURN) so it cannot be quietly retracted; clients
verify the signature + freshness against the operator's published key.

Record — canonical JSON (sorted keys, no whitespace):
    {"v":1,"domain":<str>,"seq":<int>,"date":<ISO8601 "...Z">,
     "block_height":<int>,"block_hash":<hex>,"statement":<str>}
The `block_height`/`block_hash` are a recent chain tip. They ENABLE an anti-backdate check --
a canary cannot have been signed before the block it names existed -- but performing that check
requires the chain, and THIS LIBRARY DOES NOT PERFORM IT: `block_hash` is written by `build_record`
and is read by no verification branch here, in any port. Offline verification cannot confirm a hash
it has no chain to look up. A verifier with chain access SHOULD resolve `block_hash` at
`block_height` and reject a mismatch; until it does, the fields are a commitment the signer made,
not a proof this code has checked.

Signature: secp256k1 ECDSA (DER) over SHA256(canonical_bytes), by the operator's published public
key. Reference uses `bitcoinx`; any secp256k1 lib (e.g. noble-secp256k1 in JS) interoperates.
"""
import datetime
import hashlib
import json
import re

_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"

#: SPEC §8 E23 rule 1: `seq` and `block_height` are integers from 0 to 2^53 - 1, the range in which
#: every JSON implementation represents every integer exactly (JavaScript rounds 2^53 + 1, for one).
MAX_SAFE_INTEGER = 2 ** 53 - 1

#: SPEC §8 E23 rule 2: exactly 20 ASCII characters. `[0-9]`, not `\d`, which matches every Unicode
#: decimal digit (full-width digits read as a fresh date here and as no date in JavaScript), and
#: `fullmatch`, because `$` would also accept a trailing line feed.
_DATE_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")

#: SPEC §8 E23: a public key or signature is hexadecimal text, an even number of ASCII hex digits in
#: either case, with no prefix and nothing between the digits. Only the characters in `_BLANK` are
#: ignored around it, the set the Python and JavaScript verifiers both ignored before E23. `[0-9A-Fa-f]`
#: rather than `bytes.fromhex`, which also skips white space between digit pairs.
_BLANK = r"[\t-\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*"
_HEX_RE = re.compile(_BLANK + r"((?:[0-9A-Fa-f]{2})+)" + _BLANK)


def canonical_bytes(record: dict) -> bytes:
    """Deterministic serialisation that is signed/verified. Sorted keys, no spaces, UTF-8."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def message_hash(record: dict) -> bytes:
    return hashlib.sha256(canonical_bytes(record)).digest()


def build_record(domain: str, seq: int, statement: str, block_height: int, block_hash: str,
                 date: str = None) -> dict:
    return {
        "v": 1,
        "domain": domain,
        "seq": int(seq),
        "date": date or datetime.datetime.now(datetime.timezone.utc).strftime(_DATE_FMT),
        "block_height": int(block_height),
        "block_hash": block_hash,
        "statement": statement,
    }


def sign(record: dict, privkey) -> str:
    """Operator-side. `privkey` is a bitcoinx PrivateKey or a WIF string. Returns DER signature hex.
    bitcoinx hashes the message with SHA256 by default, so we sign canonical_bytes directly.

    The record's shape is checked HERE as well as in `verify` (SPEC §8 E13). E13 states the defect
    it closes as "nothing validated this in any port, on either side of the wire", and the verifier
    side alone only half-closes it: a publisher who hand-rolls a record instead of calling
    `build_record` gets no signal at all, signs it, and publishes it. The mistake then surfaces at
    every reader at once, as MALFORMED on a canary whose whole purpose is that a bad reading means
    "the operator may be compromised" -- maximum alarm, after the point where it was cheap to fix.
    Nothing is lost by refusing: a record of the wrong shape reads MALFORMED at every conforming
    verifier, so signing it was never going to produce a canary anyone could act on.
    """
    _check_shape(record)
    _check_rules(record)
    from bitcoinx import PrivateKey
    pk = privkey if hasattr(privkey, "sign") else PrivateKey.from_WIF(privkey)
    return pk.sign(canonical_bytes(record)).hex()


class MalformedCanaryInput(ValueError):
    """The record, key or signature is not in the form SPEC §8 fixes, so no signature check ever
    ran (E11, E13, E23).

    Distinct from a failed check. See `status`.
    """


class UnsupportedCanaryVersion(ValueError):
    """The record names a version this verifier does not implement (SPEC §8 E2): UNSUPPORTED, never
    INVALID or OK. A ValueError, as the unknown-version error always was."""


def _reject_constant(name):
    raise ValueError("%s is not JSON" % name)


def parse_record(wire) -> tuple:
    """Read a record from its wire form, ``bytes`` or ``str``, and return ``(record, wire_bytes)``.

    Strict: the bytes must be UTF-8 (no byte-order mark, no encoded surrogates), and the text must be
    JSON; Python's own extensions ``NaN``, ``Infinity`` and ``-Infinity`` are refused, as every other
    JSON reader refuses them. Anything else raises MalformedCanaryInput. Whether the bytes are the
    record's canonical bytes (E23 rule 4) is checked by `verify`, after the version check."""
    if isinstance(wire, str):
        try:
            wire = wire.encode("utf-8")
        except UnicodeEncodeError as e:
            raise MalformedCanaryInput("record text is not well-formed Unicode: %s" % e.reason) from None
    if not isinstance(wire, (bytes, bytearray)):
        raise MalformedCanaryInput("a wire record is bytes or text, got %s" % type(wire).__name__)
    wire = bytes(wire)
    try:
        text = wire.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedCanaryInput("record bytes are not UTF-8: %s" % e.reason) from None
    try:
        return json.loads(text, parse_constant=_reject_constant), wire
    except ValueError as e:
        raise MalformedCanaryInput("record is not JSON: %s" % e) from None


def _record_of(record):
    """``(record, wire_bytes or None)`` for a record given as an object or in its wire form."""
    if isinstance(record, (bytes, bytearray, str)):
        return parse_record(record)
    return record, None


def check_record(record, wire: bytes = None) -> None:
    """Every check SPEC §8 makes before the signature, in its order: the record is an object; its
    version is the integer 1, else UnsupportedCanaryVersion (E2); it has exactly the seven fields
    with their types (E13); it meets the input rules (E23 rules 1-3); and, when it was read from
    bytes, those bytes are exactly its canonical bytes (rule 4). Raises MalformedCanaryInput."""
    if not isinstance(record, dict):
        raise MalformedCanaryInput("canary record must be an object, got %s"
                                   % type(record).__name__)
    v = record.get("v")
    # `True == 1` in Python, so a boolean version passed this test and was then called MALFORMED,
    # where JavaScript (and E2) say UNSUPPORTED. A version is an integer; a boolean is not one.
    if isinstance(v, bool) or v != 1:
        raise UnsupportedCanaryVersion("unsupported canary record version %r (this verifier "
                                       "implements v1)" % (v,))
    _check_shape(record)          # v1 shape, checked only once we know it claims to BE v1
    _check_rules(record)
    if wire is not None and canonical_bytes(record) != wire:
        raise MalformedCanaryInput(
            "the record's bytes are not its canonical bytes (SPEC §8 E23 rule 4): it must be written "
            "on one line, members in key order, with no spaces and no escapes other than the "
            "canonical ones")


def _hex_bytes(text, what: str) -> bytes:
    """The bytes a public key or signature written as hexadecimal text stands for (SPEC §8 E23), or
    MalformedCanaryInput."""
    m = _HEX_RE.fullmatch(text) if isinstance(text, str) else None
    if not m:
        raise MalformedCanaryInput(
            "the %s is not hexadecimal text: it must be an even number of the digits 0-9 and a-f "
            "(either case), with no 0x prefix and nothing between the digits (SPEC §8 E23)" % what)
    return bytes.fromhex(m.group(1))


def verify(record, signature_hex: str, pubkey_hex: str) -> bool:
    """True iff `signature_hex` is a valid secp256k1 signature over the record by `pubkey_hex`.

    `record` is an object (a dict), or its wire form (``bytes`` or ``str``), which must then be
    exactly the record's canonical bytes (SPEC §8 E23). False means a check RAN and failed; an
    unknown record version raises UnsupportedCanaryVersion (E2): a future v2 record fed to a v1
    verifier must read UNSUPPORTED, never a false INVALID. A record that breaks the shape (E13) or
    the input rules (E23) raises MalformedCanaryInput.
    Verification NEVER goes dark with a dependency: bitcoinx when installed, else the built-in
    pure-Python fallback (`inkan_standard._secp256k1`, differentially tested against bitcoinx, 0
    divergences over 1270 cases). Signing (operator-side) still requires bitcoinx."""
    record, wire = _record_of(record)
    check_record(record, wire)
    msg = canonical_bytes(record)

    # A malformed key or signature is NOT a failed check -- it is a check that never ran, and
    # collapsing the two reports the maximum-severity alarm for what is usually a typo or a
    # truncated copy-paste. `_secp256k1` already draws this line ("returning False would misreport
    # 'checked and bad' for 'never parsed'"); this preserves it instead of swallowing it, on the
    # same principle as E2's unknown-version rule.
    pub_bytes = _hex_bytes(pubkey_hex, "public key")
    sig_bytes = _hex_bytes(signature_hex, "signature")

    try:
        from bitcoinx import PublicKey
    except ModuleNotFoundError:
        from ._secp256k1 import verify_der
        try:
            return verify_der(pub_bytes, sig_bytes, msg)
        except ValueError as e:
            raise MalformedCanaryInput(str(e)) from None
    try:
        pub = PublicKey.from_bytes(pub_bytes)
    except Exception as e:
        raise MalformedCanaryInput("public key did not parse: %s" % e) from None
    try:
        return bool(pub.verify_der_signature(sig_bytes, msg))
    except Exception as e:
        # bitcoinx raises for structurally bad DER as well as for a bad signature; the pure-Python
        # fallback distinguishes them, so ask it rather than guess.
        from ._secp256k1 import verify_der
        try:
            return verify_der(pub_bytes, sig_bytes, msg)
        except ValueError:
            raise MalformedCanaryInput("signature did not parse: %s" % e) from None


#: SPEC §8 (E1) fixes the record at exactly these seven fields.
_FIELDS = {"v": int, "domain": str, "seq": int, "date": str,
           "block_height": int, "block_hash": str, "statement": str}


def _check_shape(record: dict) -> None:
    """The signature covers whatever fields are present, so a wrong shape cannot be FORGED -- but a
    publisher can emit one by mistake and every verifier would still say OK, and downstream readers
    would disagree about what they were reading. Nothing validated this in any port, on either side
    of the wire. Fail closed: a record that is not the shape the spec fixes is MALFORMED, not valid.
    """
    if not isinstance(record, dict):
        raise MalformedCanaryInput("canary record must be an object")
    missing = sorted(set(_FIELDS) - set(record))
    extra = sorted(set(record) - set(_FIELDS))
    if missing or extra:
        raise MalformedCanaryInput(
            "canary record must carry exactly the seven fields SPEC §8 fixes"
            + (" (missing %s)" % missing if missing else "")
            + (" (unexpected %s)" % extra if extra else ""))
    for k, ty in _FIELDS.items():
        if isinstance(record[k], bool) or not isinstance(record[k], ty):
            raise MalformedCanaryInput("canary field %r must be %s, got %s"
                                       % (k, ty.__name__, type(record[k]).__name__))


def _real_utc_time(date: str):
    """The datetime a record's `date` names, or None unless it is exactly ``YYYY-MM-DDTHH:MM:SSZ`` in
    ASCII digits and a real UTC time (SPEC §8 E23 rule 2): year 0001-9999, month 01-12, a day that
    exists in that month of that year, hour 00-23, minute 00-59, second 00-59."""
    m = _DATE_RE.fullmatch(date) if isinstance(date, str) else None
    if not m:
        return None
    y, mo, d, h, mi, sec = (int(g) for g in m.groups())
    if not (1 <= y and h <= 23 and mi <= 59 and sec <= 59):
        return None
    try:
        return datetime.datetime(y, mo, d, h, mi, sec)      # refuses month 13, February 30, ...
    except ValueError:
        return None


def _check_rules(record: dict) -> None:
    """SPEC §8 E23 rules 1-3, on a record of the right shape. Before E23 the Python and JavaScript
    verifiers gave different verdicts for many records that broke them: a `seq` above 2^53 that a
    double cannot hold exactly read OK here and INVALID in JavaScript, which rounds it; a date with one-digit fields was fresh here and
    stale there, hour 24 and second 60 the reverse, full-width digits fresh here only; and a statement
    holding an unpaired surrogate was mislabelled UNSUPPORTED here. Each is MALFORMED now."""
    for k in ("seq", "block_height"):
        if not 0 <= record[k] <= MAX_SAFE_INTEGER:
            raise MalformedCanaryInput("canary field %r must be an integer from 0 to 2^53 - 1, got %d "
                                       "(SPEC §8 E23)" % (k, record[k]))
    if _real_utc_time(record["date"]) is None:
        raise MalformedCanaryInput("canary date must be exactly YYYY-MM-DDTHH:MM:SSZ in ASCII digits "
                                   "and name a real UTC time, got %r (SPEC §8 E23)" % (record["date"],))
    for k in ("domain", "date", "block_hash", "statement"):
        try:
            record[k].encode("utf-8")
        except UnicodeEncodeError:
            raise MalformedCanaryInput("canary field %r is not well-formed Unicode text: it holds an "
                                       "unpaired surrogate (SPEC §8 E23)" % k) from None


def is_fresh(record: dict, now: datetime.datetime = None, max_age_days: int = 35) -> bool:
    """Within the staleness window (and not implausibly future-dated). A date that is not exactly
    the SPEC §8 form naming a real time is never fresh."""
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    d = _real_utc_time(record.get("date")) if isinstance(record, dict) else None
    if d is None:
        return False
    age = (now - d).total_seconds()
    return -86400 <= age <= max_age_days * 86400


def status(record, signature_hex: str, pubkey_hex: str,
           now: datetime.datetime = None, max_age_days: int = 35) -> str:
    """'OK' | 'STALE' | 'INVALID' | 'MALFORMED' — the single value a client surfaces.

    `record` is an object, or its wire form (``bytes`` or ``str``), as `verify` takes it. MALFORMED
    means the check could not RUN: the record breaks the shape or input rules, or the key or
    signature did not parse. It is deliberately distinct from INVALID, which means a check ran and
    the signature was wrong. Reporting a typo as INVALID fires the maximum-severity alarm -- "this
    publisher may be compromised" -- for what is nearly always a truncated paste, and an alarm that
    cries wolf is one people learn to ignore. Same principle as E2: never report a check that did not
    happen as one that did. An unknown record version raises UnsupportedCanaryVersion.

    Both are fail-closed. Neither is ever OK.
    """
    try:
        record, wire = _record_of(record)
        ok = verify(record if wire is None else wire, signature_hex, pubkey_hex)
    except MalformedCanaryInput:
        return "MALFORMED"
    if not ok:
        return "INVALID"
    if not is_fresh(record, now, max_age_days):
        return "STALE"
    return "OK"
