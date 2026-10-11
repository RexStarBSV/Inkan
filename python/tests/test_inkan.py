import datetime
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from inkan_standard import fingerprint as fp
from inkan_standard import canary, seal
from inkan_standard.seed import inkan_digest as fpseed_digest

P = Fl = 0

# How many checks this file is expected to execute. Pinned because the tally assertion at the
# bottom only proves that nothing FAILED -- it cannot tell "all checks passed" from "the checks
# never ran". A skipped check is the silent pass this repo's doctrine names first. Update this
# number only when checks are added or removed deliberately.
EXPECTED_CHECKS = 49
def check(n, c):
    global P, Fl
    if c: P += 1; print("  PASS", n)
    else: Fl += 1; print("  ** FAIL", n)

print("== fingerprint digest ==")
d1 = fp.fingerprint_digest(b"build-bytes-v1", "acme")
check("digest is 32 bytes", len(d1) == 32)
check("deterministic", fp.fingerprint_digest(b"build-bytes-v1", "acme") == d1)
check("avalanche (1-byte change → different)",
      fp.fingerprint_digest(b"build-bytes-v2", "acme") != d1)
check("per-adopter namespacing → distinct",
      fp.fingerprint_digest(b"build-bytes-v1", "otherapp") != d1)
check("domain prefix format",
      fp.domain_prefix("acme", 1) == b"\x04acme/inkan/v1\x00")

print("== warrant canary ==")
from bitcoinx import PrivateKey
pk = PrivateKey(bytes.fromhex("01" * 32))          # FIXED key → reproducible vectors
pub_hex = pk.public_key.to_hex()
rec = canary.build_record("acme", 7, "No warrant, gag, key compromise or coercion.",
                          870000, "00ff" * 16, date="2026-06-30T00:00:00Z")
sig_hex = canary.sign(rec, pk)
check("verify true for genuine sig", canary.verify(rec, sig_hex, pub_hex))
tampered = dict(rec); tampered["statement"] = "We were totally compromised lol"
check("verify FALSE if record tampered", not canary.verify(tampered, sig_hex, pub_hex))
other_pub = PrivateKey(bytes.fromhex("02" * 32)).public_key.to_hex()
check("verify FALSE for wrong key", not canary.verify(rec, sig_hex, other_pub))
now = datetime.datetime(2026, 6, 30, 12, 0, 0)
check("fresh within window", canary.is_fresh(rec, now, 35))
check("STALE beyond window",
      not canary.is_fresh(rec, datetime.datetime(2026, 9, 1), 35))
check("status OK", canary.status(rec, sig_hex, pub_hex, now) == "OK")
check("status INVALID on tamper", canary.status(tampered, sig_hex, pub_hex, now) == "INVALID")
check("status STALE when old",
      canary.status(rec, sig_hex, pub_hex, datetime.datetime(2026, 9, 1)) == "STALE")
# dependency death: without bitcoinx, verification survives via the vendored pure-Python
# fallback (inkan_standard._secp256k1) — never a false INVALID, never dark
from unittest import mock
with mock.patch.dict(sys.modules, {"bitcoinx": None}):
    check("verify FALLS BACK to vendored secp256k1 when bitcoinx missing",
          canary.verify(rec, sig_hex, pub_hex) is True)
    check("fallback still rejects a tampered record", not canary.verify(tampered, sig_hex, pub_hex))
    check("status works without bitcoinx", canary.status(rec, sig_hex, pub_hex, now) == "OK")
check("verify still works after backend restored", canary.verify(rec, sig_hex, pub_hex))
# SPEC §8 E2: unknown record version must raise (UNSUPPORTED path), never read as INVALID/OK
try:
    canary.verify(dict(rec, v=2), sig_hex, pub_hex); raised = False
except ValueError:
    raised = True
check("unknown record version RAISES (UNSUPPORTED), never a false INVALID", raised)


print("== normalization vectors (additive; pin the frozen NFC/raw split) ==")
import unicodedata as _ud
_nv = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors", "normalization-vectors.json")))
_a = _nv["anchor_layer"]
_nfd_kind = "".join(chr(int(h, 16)) for h in _a["kind_nfd_codepoints"])
check("anchor layer normalizes (NFC == NFD anchor)",
      fpseed_digest(_a["data_utf8"], _a["kind_nfc"]) == fpseed_digest(_a["data_utf8"], _nfd_kind))
for _layer in _nv["derivation_layer"]:
    _kind = bytes.fromhex(_layer["kind_utf8_hex"]).decode()
    check(f"derivation raw-bytes resolve pinned ({_layer['kind_form']})",
          list(seal.resolve_kind(_kind)) == _layer["resolve"])
    _dg = fpseed_digest(_a["data_utf8"], _kind)
    _rgb = bytes(c for px in seal.seal_rgb(_dg, _kind) for c in px)
    check(f"derivation rgb pinned ({_layer['kind_form']})",
          __import__("hashlib").sha256(_rgb).hexdigest() == _layer["rgb_sha256"])

print("== Inkan Seal v3 image (original engine; no third-party dependency) ==")
import hashlib
png = fp.fingerprint_image_png(b"build-bytes-v1", "acme", scale=2)
img_sha = hashlib.sha256(png).hexdigest()
check("PNG renders (signature ok)", png[:8] == b"\x89PNG\r\n\x1a\n")

# -- the codes, verified not asserted ------------------------------------------------
cws = {seal.golay24(i) for i in range(4096)}
check("Golay [24,12,8] is injective (4096 distinct codewords)", len(cws) == 4096)
wts = sorted({bin(c).count("1") for c in cws if c})
check("Golay minimum weight is 8", wts[0] == 8)
check("extended Golay weights are all even", all(w % 2 == 0 for w in wts))
# Cell floor for interleaved Golay profiles is a THEOREM, not a scan: cell i differs iff
# bit i of A-diff or B-diff is set, so |cells| = popcount(A|B) >= max(|A|,|B|) >= 8.
e8 = next(x for x in range(1, 4096) if bin(seal.golay24(x)).count("1") == 8)
w0, _, _ = seal.seal_fields(bytes(32), "")
w1 = (w0[0] ^ e8,) + w0[1:]
d = sum(a != b for a, b in zip(seal.cells_from_words(w0, 48), seal.cells_from_words(w1, 48)))
check("constructed minimum-distance pair differs in exactly 8 cells", d == 8)

# -- kinds: tiered, rotation-distinct, all renderable --------------------------------
def _rots(m):
    return {((m << r) | (m >> (6 - r))) & 0b111111 for r in range(6)}
clash = False
groups = {}
for kname, (c, k, m) in seal.KINDS.items():
    groups.setdefault((c, k), []).append(m)
for ms in groups.values():
    for i in range(len(ms)):
        for j in range(i + 1, len(ms)):
            if _rots(ms[i]) & _rots(ms[j]):
                clash = True
check("kinds sharing a (cells,k) config have rotation-distinct motifs", not clash)
ok_render = True
for kname in seal.KINDS:
    q = seal.seal_png(hashlib.sha256(kname.encode()).digest(), kname)
    if q[:8] != b"\x89PNG\r\n\x1a\n":
        ok_render = False
check("every kind (incl. custom presets) renders a valid PNG", ok_render)

# -- fields: constant-weight core, weighted palette, colour count --------------------
n5 = 0
avoided = 0
AVOID = {i for i, w in enumerate(seal.SELECT_WEIGHTS) if w != 6}
for i in range(200):
    dgt = hashlib.sha256(f"prop/{i}".encode()).digest()
    words, pix, core = seal.seal_fields(dgt, "")
    check_once = bin(core).count("1") == 2
    if not check_once:
        check("core pattern is constant-weight 2", False)
        break
    if pix in AVOID:
        avoided += 1
    ncol = len(set(seal.seal_rgb_from_fields(words, pix, core, "")))
    if not 4 <= ncol <= 5:
        check("seal renders 4-5 flat colours", False)
        break
    if ncol == 5:
        n5 += 1
else:
    check("core pattern is constant-weight 2 (200 digests)", True)
    check("seal renders 4-5 flat colours (200 digests)", True)
check("all 5 colours appear in >=90% of seals", n5 >= 180)
check("brand-avoided classes stay rare (<8% of 200)", avoided < 16)
try:
    fp.digest_to_lifehash_png_v1(bytes(32))
    check("legacy LifeHash path is removed", False)
except NotImplementedError:
    check("legacy LifeHash path is removed", True)

print("== clean metadata (every Inkan image carries NO metadata) ==")
# Works without lifehash: encode synthetic RGB directly through the shared PNG writer.
clean = fp._png_rgb888(3, 2, bytes([10, 20, 30]) * 6, scale=4)
tags = fp.png_chunk_tags(clean)
check("truecolor PNG has ONLY IHDR/IDAT/IEND", tags == ["IHDR", "IDAT", "IEND"])
check("no ancillary/text chunk present",
      not any(t in tags for t in ("tEXt", "iTXt", "zTXt", "tIME", "pHYs", "eXIf", "iCCP")))
# The rule is "no METADATA", and PNG encodes that structurally: ancillary chunks begin with a
# lowercase letter. Seal v2 ships 2-bit indexed colour, for which PLTE is a MANDATORY (critical,
# uppercase) chunk -- so assert the rule itself rather than a chunk list that only ever held for
# the truecolor writer.
seal_tags = fp.png_chunk_tags(fp.fingerprint_image_png(b"build-bytes-v1", "acme", scale=8))
check("rendered Inkan seal carries no ancillary (metadata) chunk",
      not [t for t in seal_tags if t[0].islower()])
check("rendered Inkan seal chunks are exactly IHDR/PLTE/IDAT/IEND",
      seal_tags == ["IHDR", "PLTE", "IDAT", "IEND"])

# ── emit language-agnostic test vectors ──────────────────────────────────────────────────────────
vec = {
    "fingerprint": [
        {"adopter": a, "version": 1, "payload_utf8": p,
         "digest_hex": fp.fingerprint_hex(p.encode(), a)}
        for a, p in [("acme", "build-bytes-v1"), ("acme", "build-bytes-v2"),
                     ("otherapp", "build-bytes-v1"), ("acme", "")]
    ],
    "canary": {
        "privkey_hex": "01" * 32,
        "pubkey_hex": pub_hex,
        "record": rec,
        "canonical_bytes_utf8": canary.canonical_bytes(rec).decode(),
        "signature_der_hex": sig_hex,
        "verify": True,
    },
}
# The image example is the release-provenance construction of SPEC §7.1 (E15), computed exactly as
# tools/emit_sidecar_seal.py computes it for a 14-byte file whose bytes are `payload_utf8`: the
# anchor is the Inkan of the lower-case hex of SHA-256(file bytes) under kind "code", the inscribed
# image is that anchor's TAGGED seal at scale 8, and the §7 fingerprint is published beside it.
# It pins pixels (rgb_sha256), never a hash of the compressed PNG: deflate output is
# per-implementation, so a png_sha256 would fail an honest port (SPEC §5).
from inkan_standard.seed import inkan_code as _code, inkan_seed as _seed
from inkan_standard import verify as _verify
_payload = b"build-bytes-v1"
_file_hex = hashlib.sha256(_payload).hexdigest()
_anchor = fpseed_digest(_file_hex, "code")
vec["inkan_image_example"] = {
    "comment": ("Release provenance (SPEC 7.1): anchor = Inkan(data = lower-case hex of "
                "SHA-256(file bytes), kind = 'code'); the inscription is its tagged Seal v3 PNG; "
                "the SPEC 7 fingerprint is published beside it and is not the inscribed seal. The file "
                "here is the bytes of payload_utf8."),
    "payload_utf8": _payload.decode(),
    "file_sha256_hex": _file_hex,
    "kind": "code",
    "seed_hex": _seed(_file_hex, "code").hex(),
    "code": _code(_file_hex, "code"),
    "resolve": list(seal.resolve_kind("code")),
    "rgb_sha256": hashlib.sha256(bytes(c for px in seal.seal_rgb(_anchor, "code") for c in px)).hexdigest(),
    "scale": 8,
    "tag": {"inkan-code": _code(_file_hex, "code"), "inkan-kind": "code"},
    "adopter": "acme",
    "fingerprint_version": 1,
    "fingerprint_hex": fp.fingerprint_hex(_payload, "acme", 1),
}
_tagged = seal.seal_png(_anchor, kind="code", scale=8, tag=True)
check("provenance example: the tagged scale-8 seal verifies against the pinned pixels and tags",
      _verify.verify_seal(_file_hex, "code", _tagged).ok
      and hashlib.sha256(_verify._downscale_to_native(_verify.decode_png_rgb(_tagged))).hexdigest()
      == vec["inkan_image_example"]["rgb_sha256"]
      and _verify.read_embedded_tag(_tagged) == {"code": vec["inkan_image_example"]["code"],
                                                 "kind": "code"})
# The SPEC describes what the release tool does, so hold the tool to it: run its own seal_for() over
# a file holding the payload, and recompute the code of every sidecar record the repository carries.
# A change to either construction must fail here, because a mint made from it cannot be redone.
import tempfile as _tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
import emit_sidecar_seal as _emit
with _tempfile.TemporaryDirectory() as _td:
    _f = os.path.join(_td, "build-bytes-v1.bin")
    with open(_f, "wb") as _fh:
        _fh.write(_payload)
    _ref = _emit.seal_for(_f, None, "acme")
check("release tool computes the SPEC §7.1 construction (code, file hash, §7 fingerprint)",
      (_ref["code"], _ref["fingerprint"], _ref["adopter_fingerprint"], _ref["kind"])
      == (vec["inkan_image_example"]["code"], _file_hex, vec["inkan_image_example"]["fingerprint_hex"],
          "code"))
_web = os.path.join(os.path.dirname(__file__), "..", "..", "web")
_sidecars = sorted(f for f in os.listdir(_web) if f.endswith(".inkan.json"))
_side_ok = bool(_sidecars)
for _s in _sidecars:
    with open(os.path.join(_web, _s), encoding="utf-8") as _fh:
        _r = json.load(_fh)
    _side_ok = _side_ok and _r["kind"] == "code" and _r["code"] == _code(_r["fingerprint"], "code")
check("every published sidecar record's code is Inkan(hex SHA-256 of its file, 'code')", _side_ok)
out_path = os.path.join(os.path.dirname(__file__), "..", "..", "test-vectors", "vectors.json")
# The committed vectors are the immutable cross-implementation reference (JS ports prove parity
# against them — see SPEC.md). So by DEFAULT we ASSERT the freshly-computed values against the
# committed file (a formula regression fails the test) rather than silently overwriting it. Set
# INKAN_REGEN_VECTORS=1 to intentionally regenerate after a deliberate spec change.
print("== test-vector conformance ==")
if os.environ.get("INKAN_REGEN_VECTORS") == "1":
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    # READ-MERGE-WRITE: this script computes only the fingerprint/canary/image blocks. Blocks
    # owned by other generators (the `inkan` glyph block from tools/gen_inkan_vectors.py) MUST
    # survive a regen — overwriting the whole file silently dropped them once (2026-07 trap).
    merged = dict(vec)
    if os.path.exists(out_path):
        with open(out_path) as fh:
            prior = json.load(fh)
        for key in prior:
            if key not in merged:
                merged[key] = prior[key]
    with open(out_path, "w") as fh:
        json.dump(merged, fh, indent=2, sort_keys=True)
    print("  REGENERATED test-vectors/vectors.json (INKAN_REGEN_VECTORS=1; foreign blocks preserved: %s)"
          % sorted(k for k in merged if k not in vec))
else:
    with open(out_path) as fh:
        committed = json.load(fh)
    # The glyph block is owned by tools/gen_inkan_vectors.py but its PRESENCE is asserted here,
    # so a bad regen can never silently ship a vectors.json without it.
    check("inkan glyph block present in committed vectors", "inkan" in committed)
    # deterministic values (hashes, canonical bytes, record) must match byte-for-byte
    check("fingerprint vectors match committed reference", vec["fingerprint"] == committed["fingerprint"])
    check("canary record matches committed reference",
          vec["canary"]["record"] == committed["canary"]["record"])
    check("canary canonical_bytes match committed reference",
          vec["canary"]["canonical_bytes_utf8"] == committed["canary"]["canonical_bytes_utf8"])
    check("canary pubkey matches committed reference",
          vec["canary"]["pubkey_hex"] == committed["canary"]["pubkey_hex"])
    check("provenance example (inkan_image_example) matches committed reference",
          vec["inkan_image_example"] == committed.get("inkan_image_example"))
    # signature: verify the COMMITTED signature semantically (robust to any nonce scheme)
    check("committed canary signature verifies",
          canary.verify(committed["canary"]["record"], committed["canary"]["signature_der_hex"],
                        committed["canary"]["pubkey_hex"]))

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
