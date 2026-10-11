# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""
inkan_standard.anchor — OPTIONAL on-chain anchoring of a canary via a BRC-100 wallet. OPT-IN ONLY.

The trust root is UNCHANGED. The canary is still signed by the operator's bare secp256k1 key
(`inkan_standard.canary.sign`) and verified OFFLINE (`inkan_standard.canary.verify`); this module NEVER signs the canary
and the parity-tested core (`inkan_standard.canary`, `inkan_standard.fingerprint`, `inkan_standard.seal`, the `inkan` npm port) has ZERO
dependency on it. All this does is BROADCAST an already-signed canary to an immutable on-chain anchor via
the wallet's `createAction` — the wallet funds the tx, nothing more. This realises the note in
`canary.py` ("publish each canary to an immutable, timestamped anchor") without coupling verification to
a wallet.

It runs the Metanet Academy first action (getVersion → getNetwork → isAuthenticated → getPublicKey →
createAction) and HARD-REFUSES createAction on any network but testnet unless `allow_mainnet=True`
(mainnet / real funds LAST). Talks the standard BRC-100 json-api wire shape (as @bsv/sdk):
POST /{method} with a JSON body. Stdlib only (urllib) — no new dependency.
"""
import json
import urllib.request
from typing import Any, Callable, Dict, Optional

from . import canary

# Default to the plain loopback substrate (the operator's own machine). secure-json-api :2121 is also
# valid but its self-signed cert needs a caller-supplied ssl context, so it is not the default here.
DEFAULT_ENDPOINT = "http://127.0.0.1:3321"

# On-chain marker identifying an Inkan canary output (v1).
MARKER = b"INKANC1"


class AnchorError(RuntimeError):
    pass


def _encode_push(data: bytes) -> bytes:
    """Minimal Bitcoin script pushdata encoding for one blob."""
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([0x4C, n]) + data
    if n <= 0xFFFF:
        return bytes([0x4D, n & 0xFF, (n >> 8) & 0xFF]) + data
    return bytes([0x4E, n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF]) + data


def build_canary_script(record: dict, signature_hex: str, pubkey_hex: str) -> str:
    """OP_RETURN locking-script hex carrying a self-verifying canary: MARKER, canonical record, sig, pubkey.

    Everything a verifier needs is on-chain — the record (canonical bytes), the DER signature, and the
    operator's public key — so the anchored output can be checked with `inkan_standard.canary.verify` alone.
    """
    out = bytearray([0x6A])  # OP_RETURN
    for blob in (MARKER, canary.canonical_bytes(record),
                 bytes.fromhex(signature_hex), bytes.fromhex(pubkey_hex)):
        out += _encode_push(blob)
    return out.hex()


def parse_canary_script(script_hex: str) -> Optional[Dict[str, Any]]:
    """Reverse of build_canary_script: pull a canary back OFF-CHAIN so it can be re-verified offline.

    Returns {"record": dict, "record_bytes": bytes, "signature_hex": str, "pubkey_hex": str}, or None
    if the script is not a well-formed Inkan canary output. This reader does NOT trust the bytes — the
    caller re-checks with `inkan_standard.canary.verify` / `.status`, passing `record_bytes`, so that a record
    whose on-chain bytes are not its canonical bytes reads MALFORMED (SPEC §8 E23). Example:

        parsed = anchor.parse_canary_script(on_chain_script_hex)
        if parsed:
            state = canary.status(parsed["record_bytes"], parsed["signature_hex"],
                                  parsed["pubkey_hex"])
    """
    try:
        buf = bytes.fromhex(script_hex)
    except ValueError:
        return None
    if not buf or buf[0] != 0x6A:  # OP_RETURN
        return None
    pos = 1

    def read_push() -> Optional[bytes]:
        nonlocal pos
        if pos >= len(buf):
            return None
        first = buf[pos]; pos += 1
        if first < 0x4C:
            ln = first
        elif first == 0x4C:
            if pos >= len(buf):
                return None
            ln = buf[pos]; pos += 1
        elif first == 0x4D:
            if pos + 1 >= len(buf):
                return None
            ln = buf[pos] | (buf[pos + 1] << 8); pos += 2
        elif first == 0x4E:
            if pos + 3 >= len(buf):
                return None
            ln = int.from_bytes(buf[pos:pos + 4], "little"); pos += 4
        else:
            return None
        data = buf[pos:pos + ln]; pos += ln
        return data if len(data) == ln else None

    if read_push() != MARKER:
        return None
    rec_bytes = read_push()
    sig_bytes = read_push()
    pub_bytes = read_push()
    if rec_bytes is None or sig_bytes is None or pub_bytes is None:
        return None
    try:
        record = json.loads(rec_bytes)
    except (ValueError, UnicodeDecodeError):
        return None
    return {"record": record, "record_bytes": rec_bytes, "signature_hex": sig_bytes.hex(),
            "pubkey_hex": pub_bytes.hex()}


def _http_poster(endpoint: str, timeout: float) -> Callable[[str, Optional[dict]], Any]:
    def post(method: str, args: Optional[dict] = None) -> Any:
        data = json.dumps(args or {}).encode("utf-8")
        req = urllib.request.Request(
            f"{endpoint}/{method}", data=data, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "Originator": "inkan"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - loopback wallet
            return json.loads(resp.read() or b"{}")
    return post


def anchor_canary(record: dict, signature_hex: str, pubkey_hex: str, *,
                  endpoint: str = DEFAULT_ENDPOINT, allow_mainnet: bool = False,
                  timeout: float = 300.0,
                  poster: Optional[Callable[[str, Optional[dict]], Any]] = None) -> Dict[str, Any]:
    """Broadcast an already-signed canary on-chain via the wallet's createAction.

    Order: verify OFFLINE first (never spend to anchor an invalid canary) → first-action handshake →
    testnet guard → createAction. Returns the wallet's createAction result (txid or signableTransaction).
    `poster` is injectable for tests.

    Every refusal raises `AnchorError`, and each says WHICH of the three distinct things went wrong,
    because they call for different actions from whoever is anchoring:

      * MALFORMED (SPEC §8 E11) — the key or signature did not parse, so no signature check ever ran.
        Almost always a truncated paste; re-copy the input.
      * UNSUPPORTED (SPEC §8 E2) — the record announces a version this build does not implement.
        Anchor it with a build that does; this one cannot judge it.
      * INVALID — a check ran and the signature was wrong. Treat as a real failure.

    None of the three may spend, so the wallet is never touched for any of them.
    """
    # `canary.verify` raises for the first two cases and returns False for the third. Before E11 it
    # only ever returned a bool, so this module called it bare; once E11 introduced
    # MalformedCanaryInput a truncated signature stopped being refused and started escaping
    # `anchor_canary` as a raw ValueError -- past the documented AnchorError contract, past every
    # caller's `except AnchorError`, and reported with no indication that the check had not run.
    # MalformedCanaryInput subclasses ValueError, so it MUST be caught first or E11's distinction
    # collapses back into the generic branch.
    try:
        verified = canary.verify(record, signature_hex, pubkey_hex)
    except canary.MalformedCanaryInput as e:
        raise AnchorError(
            "MALFORMED: the canary key, signature or record shape did not parse, so no signature "
            "check ran (SPEC §8 E11 — this is NOT 'the signature is wrong'). Refusing to anchor "
            "something that was never verified: %s" % e) from e
    except ValueError as e:
        raise AnchorError(
            "UNSUPPORTED: this build cannot verify the record (SPEC §8 E2 — reporting an unreadable "
            "record as INVALID would assert a check that never happened). Refusing to anchor: %s"
            % e) from e
    if not verified:
        raise AnchorError("INVALID: canary signature does not verify — refusing to anchor an "
                          "invalid canary")

    post = poster or _http_poster(endpoint, timeout)

    ver = post("getVersion")
    if not isinstance(ver, dict) or not isinstance(ver.get("version"), str):
        raise AnchorError(f"wallet did not answer getVersion: {ver!r}")

    net = post("getNetwork")
    network = net.get("network") if isinstance(net, dict) else None
    if network != "testnet" and not allow_mainnet:
        raise AnchorError(
            f"refusing createAction: wallet network is {network!r}, need 'testnet' "
            f"(pass allow_mainnet=True to override — mainnet / real funds LAST)")

    post("isAuthenticated")
    post("getPublicKey", {"identityKey": True})

    script = build_canary_script(record, signature_hex, pubkey_hex)
    result = post("createAction", {
        "description": "inkan canary anchor",
        "outputs": [{"lockingScript": script, "satoshis": 0, "outputDescription": "inkan-canary"}],
    })
    if not isinstance(result, dict):
        raise AnchorError(f"createAction returned an unexpected result: {result!r}")
    return result
