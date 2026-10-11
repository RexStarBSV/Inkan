#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Inkan MCP server — lets an agent generate, verify and seal Inkan artifacts.

Minimal JSON-RPC 2.0 over stdio (newline-delimited), zero dependencies:

    python3 tools/inkan_mcp.py        # speaks MCP on stdin/stdout

Configure in an MCP client as a stdio server running that command.

WHAT THIS SERVER CANNOT DO, BY CONSTRUCTION
-------------------------------------------
Every tool is pure computation over local bytes. There is no wallet, no key material, no signing,
no minting, no network egress of any kind. Inkan's verification layer is deliberately incapable of
spending, and exposing it to an agent must not smuggle that capability in. Minting an Inkan as a
1Sat ordinal needs the user's own BRC-100 wallet and is a separate, deliberate act; it is not
reachable from here and must not become so.

Consequently there is nothing to gate with a capability manifest: a denied tool and an allowed tool
can both only read local files and compute digests. The one exception is the write scope, which is
bounded explicitly rather than trusted: `inkan_seal_artifact` writes ONLY `<artifact>.inkan.png`
and `<artifact>.inkan.json` beside its target, and refuses anything else.

Errors are returned to the caller, never swallowed: an unreadable file, an absent sidecar, or a
mismatched digest is a reported failure, not a quiet success.
"""
from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inkan_standard import seal as inkan_seal                                          # noqa: E402
from inkan_standard import verify as inkan_verify                                      # noqa: E402
from inkan_standard.fingerprint import fingerprint_hex                                 # noqa: E402
from inkan_standard.seed import inkan_code, inkan_digest, inkan_short_code             # noqa: E402
import emit_sidecar_seal                                                      # noqa: E402

PROTOCOL_VERSION = "2024-11-05"
SERVER = {"name": "inkan", "version": "1.0"}


def _read(path: str) -> bytes:
    if not os.path.isfile(path):
        raise ValueError("not a file: %s" % path)
    with open(path, "rb") as f:
        return f.read()


def _payload(args: dict):
    """Accept inline text, base64, or a path. Exactly one, so an agent cannot silently hash the
    wrong thing by supplying two.

    `text` is returned AS TEXT (a str), and `base64` and `path` as bytes. Text passed to a tool is
    what a person typed or pasted, and SPEC §1 (E19) anchors text over its NFC form; this used to
    encode it to bytes first, so a decomposed "café" anchored to a different code here than in every
    library. A fingerprint payload is bytes by definition (§7), and op_fingerprint encodes text as
    UTF-8 itself."""
    given = [k for k in ("text", "base64", "path") if args.get(k) is not None]
    if len(given) != 1:
        raise ValueError("supply exactly one of text/base64/path (got %d)" % len(given))
    if args.get("path") is not None:
        return _read(args["path"])
    if args.get("base64") is not None:
        return base64.b64decode(args["base64"])
    if not isinstance(args["text"], str):
        raise ValueError("text must be a string, got %s" % type(args["text"]).__name__)
    return args["text"]


def op_generate(args: dict) -> dict:
    data, kind = _payload(args), args.get("kind", "")
    digest = inkan_digest(data, kind)
    out = {
        "code": inkan_code(data, kind),
        "short_code": inkan_short_code(data, kind),
        "digest_hex": digest.hex(),
        "kind": kind or None,
        "seal_version": inkan_seal.SEAL_VERSION,
    }
    if args.get("png"):
        scale = int(args.get("scale", 8))
        out["png_base64"] = base64.b64encode(
            inkan_seal.seal_png(digest, kind=kind, scale=scale, tag=True)).decode("ascii")
    return out


def op_verify_seal(args: dict) -> dict:
    presented = _read(args["seal_path"]) if args.get("seal_path") else None
    res = inkan_verify.verify_seal(_payload(args), args.get("kind", ""), presented)
    return {"ok": res.ok, "summary": res.summary, "detail": res.detail}


def op_fingerprint(args: dict) -> dict:
    payload = _payload(args)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")       # a fingerprint payload is bytes (SPEC §7)
    adopter = args.get("adopter")
    if not adopter:
        raise ValueError("adopter is required: it is inside the digest, so omitting it "
                         "silently produces a different namespace")
    # Passed through as given and checked by fingerprint_hex: a positive integer (SPEC §7 E22). This
    # used int(...), which truncated 1.5 to 1 and so verified a fraction as version 1.
    version = args.get("version", 1)
    got = fingerprint_hex(payload, adopter, version)
    out = {"fingerprint": got, "adopter": adopter, "version": version, "bytes": len(payload)}
    expect = args.get("expect")
    if expect:
        out["expected"] = expect
        out["ok"] = got == expect.lower().replace("0x", "")
    return out


def op_seal_artifact(args: dict) -> dict:
    path = args["path"]
    if not os.path.isfile(path):
        raise ValueError("not a file: %s" % path)
    return emit_sidecar_seal.emit(path, args.get("build_version"), args.get("adopter"))


def op_check_artifact(args: dict) -> dict:
    path = args["path"]
    if not os.path.isfile(path):
        raise ValueError("not a file: %s" % path)
    _ok, res = emit_sidecar_seal.check(path)
    return res


def op_selftest(args: dict) -> dict:
    res = inkan_verify.selftest(args.get("vectors_path"))
    return {"ok": res.ok, "summary": res.summary, "detail": res.detail}


_PAYLOAD_PROPS = {
    "text": {"type": "string", "description": "payload as text; for a seal it is NFC-normalised "
                                              "(SPEC §1), for a fingerprint hashed as its UTF-8 bytes"},
    "base64": {"type": "string", "description": "payload as base64 bytes"},
    "path": {"type": "string", "description": "read the payload from this local file"},
}

TOOLS = {
    "inkan_generate": (op_generate,
        "Compute the canonical Inkan for (data, kind): ik1 code, short code, digest, optionally the "
        "seal PNG. Pure computation, no network.",
        {"type": "object", "properties": dict(_PAYLOAD_PROPS, **{
            "kind": {"type": "string", "description": "any kind string; suffix @t1/@t2/@t3 to set tier"},
            "png": {"type": "boolean", "description": "also return the tagged seal PNG as base64"},
            "scale": {"type": "integer", "description": "integer upscale for the PNG (default 8)"}})}),

    "inkan_verify_seal": (op_verify_seal,
        "Recompute the canonical seal for (data, kind) and, if a seal PNG is given, compare it "
        "pixel-for-pixel. A resized or screenshotted image cannot be byte-compared.",
        {"type": "object", "properties": dict(_PAYLOAD_PROPS, **{
            "kind": {"type": "string"},
            "seal_path": {"type": "string", "description": "presented seal PNG to check"}})}),

    "inkan_fingerprint": (op_fingerprint,
        "Compute the adopter-namespaced tamper fingerprint of a payload "
        "(SHA256 over adopter domain prefix + bytes). Optionally compare against an expected hex.",
        {"type": "object",
         "properties": dict(_PAYLOAD_PROPS, **{
             "adopter": {"type": "string", "description": "namespace; REQUIRED, it is inside the digest"},
             "version": {"type": "integer", "minimum": 1,
                         "description": "fingerprint version, a positive integer (default 1)"},
             "expect": {"type": "string", "description": "expected fingerprint hex to compare"}}),
         "required": ["adopter"]}),

    "inkan_seal_artifact": (op_seal_artifact,
        "Write the sidecar Code Inkan for a built artifact: <path>.inkan.png and <path>.inkan.json "
        "beside it. Writes nowhere else. Re-run after any rebuild; a seal is only valid for the "
        "exact bytes it covered.",
        {"type": "object", "properties": {
            "path": {"type": "string", "description": "artifact to seal"},
            "adopter": {"type": "string", "description": "namespace this build is published under"},
            "build_version": {"type": "string"}}, "required": ["path"]}),

    "inkan_check_artifact": (op_check_artifact,
        "Re-verify an artifact against its existing sidecar. A missing or unreadable reference is a "
        "FAILURE, not a pass: the artifact is unverifiable.",
        {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),

    "inkan_selftest": (op_selftest,
        "Prove this implementation renders the canonical standard, by recomputing the pinned "
        "known-answer vectors.",
        {"type": "object", "properties": {"vectors_path": {"type": "string"}}}),
}


def ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def err(mid, code, message):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def tool_err(mid, message):
    return ok(mid, {"content": [{"type": "text", "text": message}], "isError": True})


def handle(msg):
    if not isinstance(msg, dict):
        return err(None, -32600, "invalid request: message must be a JSON object")
    mid, method = msg.get("id"), msg.get("method")
    params = msg.get("params") or {}
    if not isinstance(params, dict):
        return err(mid, -32600, "invalid request: params must be an object")
    if method == "initialize":
        return ok(mid, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                        "serverInfo": SERVER})
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return ok(mid, {})
    if method == "tools/list":
        return ok(mid, {"tools": [{"name": n, "description": t[1], "inputSchema": t[2]}
                                  for n, t in TOOLS.items()]})
    if method == "tools/call":
        name = params.get("name")
        spec = TOOLS.get(name)
        if spec is None:
            return tool_err(mid, "unknown tool: %s" % name)
        try:
            result = spec[0](params.get("arguments") or {})
        except Exception as exc:            # fail-loud to the caller, never a silent success
            return tool_err(mid, "%s: %s" % (type(exc).__name__, exc))
        return ok(mid, {"content": [{"type": "text", "text": json.dumps(result, indent=1)}],
                        "isError": bool(isinstance(result, dict) and result.get("ok") is False)})
    return err(mid, -32601, "method not found: %s" % method)


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            resp = err(None, -32700, "parse error: %s" % exc)
        else:
            resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
