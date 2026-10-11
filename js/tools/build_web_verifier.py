#!/usr/bin/env python3
"""Generate a single self-contained HTML Inkan verifier from the canonical JS engine.

The output has ZERO external references -- engine, styles and logic are inlined -- so it runs
from a file://, a static host, or an on-chain inscription with equal fidelity. It is a
GENERATED artifact: never hand-edit inkan-verify.html; change the engine or this script and
regenerate, so the web verifier can never silently drift from the reference.
"""
import base64
import pathlib
import re

VERIFIER_VERSION = "1"          # the page's own release; bump on every published change
SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
BRAND = pathlib.Path(__file__).resolve().parents[2] / "branding"


def _b64(path: pathlib.Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


# THE BRAND INPUTS ARE NOT IN EVERY DISTRIBUTION. The mark is not licensed (LICENSE-MARK) and its
# source artwork, with the font subsets below, stays in the Licensor's source repository. The built
# pages in web/ ARE the published artifacts; this builder regenerates them. Run from a tree that
# lacks the inputs, it stops here and says why, rather than failing on the first file it opens.
_FONT_FILES = [("fonts", "InkanSans-%s.subset.ttf" % w) for w in ("Regular", "SemiBold", "Bold")]
_ICON_FILE = "icon_inkan.svg"
_missing = [str(BRAND.joinpath(*f)) for f in _FONT_FILES + [(_ICON_FILE,)]
            if not BRAND.joinpath(*f).is_file()]
if _missing:
    raise SystemExit(
        "build_web_verifier: cannot rebuild the page here -- its brand inputs are absent:\n  "
        + "\n  ".join(_missing) + "\n"
        "The Inkan mark is not licensed for reuse (LICENSE-MARK), so its source artwork and the\n"
        "font subsets it is built with are not part of this distribution. The pages in web/ are\n"
        "the published, self-verifying artifacts; check them with\n"
        "  node js/tools/check_web_verifier.mjs web/inkan-verify.html\n"
        "  python3 tools/emit_sidecar_seal.py --check web/inkan-verify.html")

# Inkan Sans: a Modified Version of IBM Plex Sans under the SIL OFL 1.1, subset to Basic Latin +
# Latin-1 + the few symbols the UI uses, and RENAMED, because IBM's licence header reserves the font
# name "Plex" and OFL section 3 forbids a Modified Version to use it (tools/rename_font_subsets.py
# records exactly what the rename changed in the subsets: the name table and the vendor ID, nothing
# else; the subsetting itself is what cut the other tables down).
# TTF, not WOFF2: WOFF2 is Brotli-compressed font data, and this artifact is inscribed uncompressed
# on purpose -- a century-scale reader should need no decoder. Anything outside the subset falls back
# down the stack rather than failing to render.
#
# The faces sit inside an SPDX SNIPPET, because the page around them is Apache-2.0 and they are not:
# the snippet is the machine-readable form of the carve-out NOTICE and LICENSE-FONTS state in prose,
# and tools/check_licence_map.py holds the page to it.
#
# OFL condition 2: every copy of the font must contain IBM's copyright notice and the licence. The
# page is the copy that travels -- saved, re-hosted, inscribed -- usually without LICENSE-FONTS beside
# it, so the full text goes inside the snippet, next to the font data. It is taken verbatim from
# LICENSE-FONTS (everything below its rule line), and tools/check_licence_map.py holds each page to it.
_OFL_PARTS = re.split(r"^=+$", (BRAND.parent / "LICENSE-FONTS").read_text(encoding="utf-8"),
                      maxsplit=1, flags=re.M)
OFL_TEXT = _OFL_PARTS[1].strip("\n") if len(_OFL_PARTS) == 2 else ""
if ("SIL OPEN FONT LICENSE Version 1.1" not in OFL_TEXT or "DISCLAIMER" not in OFL_TEXT
        or "Copyright" not in OFL_TEXT or "*/" in OFL_TEXT):
    raise SystemExit("FATAL: LICENSE-FONTS does not hold IBM's notice and the SIL OFL 1.1 text below a "
                     "rule line of '=' (or the text contains '*/', which would end the CSS comment); "
                     "the page must not embed the font without its licence")
FONT_FACES = ("/* SPDX-SnippetBegin */\n"
              "/* SPDX-License-Identifier: OFL-1.1 */\n"
              "/* SPDX-SnippetCopyrightText: Copyright 2017 IBM Corp. with Reserved Font Name \"Plex\" */\n"
              "/* Inkan Sans, a Modified Version of IBM Plex Sans (subset and renamed). As OFL condition 2\n"
              "   requires of every copy, IBM's copyright notice and the licence follow in full.\n\n"
              + OFL_TEXT + "\n*/\n"
              + "\n".join(
                  "@font-face{font-family:'Inkan Sans';font-style:normal;font-weight:%d;"
                  "font-display:swap;src:url(data:font/ttf;base64,%s) format('truetype')}"
                  % (weight, _b64(BRAND.joinpath(*f)))
                  for weight, f in zip((400, 600, 700), _FONT_FILES))
              + "\n/* SPDX-SnippetEnd */")

# The mark, inside an SPDX snippet of its own: it is NOT licensed by the page's Apache-2.0 grant, or
# by anything else here (LICENSE-MARK). Comments in the source SVG (its own licence header) are
# dropped, because the snippet states the licence for the embedded copy.
ICON_SVG = ("<!-- SPDX-SnippetBegin --><!-- SPDX-License-Identifier: LicenseRef-Inkan-Mark -->"
            "<!-- SPDX-SnippetCopyrightText: 2026 RexStarBSV -->"
            + re.sub(r"\s+", " ", re.sub(r"<!--.*?-->", "", (BRAND / _ICON_FILE).read_text(),
                                         flags=re.S)).strip()
            + "<!-- SPDX-SnippetEnd -->")


def strip_module(text: str) -> str:
    out = []
    for line in text.splitlines():
        if re.match(r"\s*import\s", line):
            continue
        if re.match(r"\s*export\s*\{[^}]*\}\s*from", line):     # re-export lines
            continue
        line = re.sub(r"^\s*export\s+(function|const|class|let|var)\b", r"\1", line)
        line = re.sub(r"^\s*export\s+default\s+", "", line)
        out.append(line)
    return "\n".join(out)


_DECL = re.compile(r"^(?:const|let|var|function|class)\s+([A-Za-z_$][A-Za-z0-9_$]*)")


def merge_modules(modules) -> str:
    """Flatten the modules into ONE scope, refusing to emit a page that cannot parse.

    Inlining destroys module boundaries, so two modules declaring the same top-level name is a
    SyntaxError that kills the ENTIRE inline script -- the page renders as a dead shell with no
    console visible to a normal user. That is exactly the silent failure this project forbids, and
    it is not hypothetical: `seed.js` and `fingerprint.js` both declare `const encoder`, which
    broke the artifact the moment the fingerprint layer was added.

    A duplicate whose declaration line is byte-identical is a shared helper: keep the first, drop
    the rest. Anything else is a genuine conflict a build must not paper over -- fail loud.
    """
    seen, out = {}, []
    for text in modules:
        kept = []
        for line in text.splitlines():
            m = _DECL.match(line)
            if m:
                name = m.group(1)
                prev = seen.get(name)
                if prev is not None:
                    single_line = line.rstrip().endswith((")", ";")) and "{" not in line
                    if prev.strip() == line.strip() and single_line:
                        continue                       # identical one-line helper: de-duplicate
                    raise SystemExit(
                        "FATAL: top-level name '%s' is declared twice and the declarations differ "
                        "(or span multiple lines), so they cannot be merged safely.\n"
                        "  first: %s\n  again: %s\n"
                        "Rename one, or hoist a single shared declaration."
                        % (name, prev.strip(), line.strip()))
                seen[name] = line
            kept.append(line)
        out.append("\n".join(kept))
    return "\n".join(out)


engine = merge_modules([
    strip_module((SRC / "sha256.js").read_text()),
    strip_module((SRC / "seed.js").read_text()),
    strip_module((SRC / "seal_tables.js").read_text()),
    "const CANVAS_ = CANVAS;",                          # seal.js aliases CANVAS as CANVAS_
    strip_module((SRC / "seal.js").read_text()),
    # BRC-145 specifies TWO layers: the typed content anchor (seal, above) and software/build
    # provenance (the tamper fingerprint). An inscribed page that could only do the first would
    # put half the published standard on chain. +1.6 KB against 223 KB buys the other half.
    strip_module((SRC / "fingerprint.js").read_text()),
    # secp256k1 here is VERIFY-ONLY and must stay that way: a verification surface that could
    # sign is one that could be made to spend, and an inscribed copy cannot be recalled.
    strip_module((SRC / "secp256k1.js").read_text()),
    strip_module((SRC / "canary.js").read_text()),
])

# Known-answer self-test: pinned (digest, kind, rgb_sha256) triples spanning all four cell
# profiles. The web self-test recomputes each and compares -- proving the inlined engine renders
# the CANONICAL standard, not merely that it runs. A tampered engine fails this.
import json as _json
_vec = _json.loads((SRC.parents[1] / "test-vectors" / "seal-v3-vectors.json").read_text())
# Transcribed verbatim from the MERGED BRC-145 "Test Vectors" section (apps/0145.md) -- NOT derived
# from this repo. These are the standard's own normative examples, so a page that reproduces them
# can honestly say "per BRC-145". The previous badge made that claim while checking only repo-local
# vectors, none of which the standard publishes. TV7 (ECDSA canary) is out of scope: the web engine
# carries no secp256k1.
_A = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
BRC145 = {
    "seed": [{"d": "Hello", "k": "", "h": "696e6b616e2f7631000048656c6c6f",
              "w": "TV1 seed: domain || u8(len kind) || kind || data"}],
    "code": [
        {"d": "Hello", "k": "", "h": "ik1ae63a28a7b3fbae640f24ab4003d285a453e5493b89741326a7fbcc36a2a6a44",
         "w": "TV1 anchor of text, default kind"},
        {"d": _A, "k": "address", "h": "ik112cf1aaca7ef50793d990e94c9ae889af6f9e8fdfc28b2f9a72d4028bde05dcd",
         "w": "TV2 anchor of a typed address (reserved kind)"},
        {"d": "X", "k": "address", "h": "ik1b49a32c4d99c6b80b331223166711da0a91105d1aea989430b8dc22e073c97fd",
         "w": "TV5 (address,X) — length prefix keeps the boundary unambiguous"},
        {"d": "addressX", "k": "", "h": "ik13780ad6190697cc754df1159766f9c9781aa610529d0654a197a9a31c691a7f7",
         "w": "TV5 ('',addressX) — must NOT collide with the line above"},
        {"d": "x", "k": "caf\u00e9", "h": "ik188858a890fa01bf5a463e0e4ca0181d18fe261f34799fe5c5d0ab76e0647f6af",
         "w": "TV4 kind as NFC — normalises before hashing"},
        {"d": "x", "k": "cafe\u0301", "h": "ik188858a890fa01bf5a463e0e4ca0181d18fe261f34799fe5c5d0ab76e0647f6af",
         "w": "TV4 same kind as NFD — must give the identical anchor"},
    ],
    "kind": [
        {"k": "", "h": [48, 2, 63], "w": "TV1 reserved kind '' resolves to (cells,k,motif)"}, {"k": "address", "h": [72, 1, 51], "w": "TV2 reserved kind, tier t1"},
        {"k": "acme:invoice@t3", "h": [24, 5, 21], "w": "TV3 open kind + @t3, derived with no registry"}, {"k": "myapp:thing", "h": [48, 4, 11], "w": "TV3 open kind, default tier"},
        {"k": "acme:vault@t1", "h": [72, 2, 27], "w": "TV3 open kind + @t1"}, {"k": "caf\u00e9@t2", "h": [48, 3, 1], "w": "TV4 non-ASCII kind resolves stably"},
    ],
    # TV7: canonical record bytes, message hash, and the ECDSA verdict over them.
    "canary": [{
        "r": {"v": 1, "domain": "acme", "seq": 7, "date": "2026-06-30T00:00:00Z",
              "block_height": 870000,
              "block_hash": "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff",
              "statement": "No warrant, gag, key compromise or coercion."},
        "bytes": 222,
        "mh": "7b0991a1ab13b4b17384e1c6acd0017edb77bd563cdea59cdc776993d8c99362",
        "pub": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        "sig": "3045022100d336085483c2dea86794ef3404d7dc7beef56368fd380000e4d0d8f3ac3fe50c"
               "02200a4fff49ba1173d1b66f8d4a335cb587c221db79280df23fc2b495b081c65e11",
        "w": "TV7 signed canary: canonical bytes, hash, and signature"}],
    "fp": [
        {"p": "build-bytes-v1", "a": "acme", "v": 1,
         "h": "d88657e80e283d5a44bd29b83cf8a93ec60729ec635e642b5454b8829bd3e3c6",
         "w": "TV6 fingerprint under adopter acme"},
        {"p": "build-bytes-v1", "a": "otherapp", "v": 1,
         "h": "1847961553e04828204efb7322f1763b8ade6faa14f6f78e30b43957a0c24ab1",
         "w": "TV6 same payload, different adopter — must differ"},
    ],
}

_want = ["", "address", "signer", "identity", "code", "custom/48", "custom/72", "vault"]
_seen, _render = set(), []
for v in _vec["sampled"]:
    if v["kind"] in _want and v["kind"] not in _seen:
        _seen.add(v["kind"])
        _render.append({"d": v["digest_hex"], "k": v["kind"], "h": v["rgb_sha256"]})
# Fail loud on a kind we asked for and did not get. Silently shrinking coverage is how the badge
# came to read a confident 7/7 while quietly testing one kind fewer than intended.
_missing = [k for k in _want if k not in _seen]
if _missing:
    raise SystemExit("FATAL: no seal vector for kind(s) %r — self-test coverage would silently shrink" % _missing)

# END-TO-END vectors: raw data -> anchor -> pixels. Without these the self-test exercises only the
# RENDERER; the anchor construction that is the point of the standard goes unchecked, and a page
# emitting wrong ik1 codes still shows a green tick.
_e2e = _json.loads((SRC.parents[1] / "test-vectors" / "vectors.json").read_text())
_anchor = [{"d": v["data_utf8"], "k": v["kind"], "s": v["seed_hex"], "h": v["rgb888_sha256"]}
           for v in _e2e["inkan"]["vectors"]]
_fp = [{"p": v["payload_utf8"], "a": v["adopter"], "v": v["version"], "h": v["digest_hex"]}
       for v in _e2e["fingerprint"]]
if not (_anchor and _fp and _render):
    raise SystemExit("FATAL: empty self-test group — the page would report a pass over nothing")

# TEXT AND THE BROWSER'S UNICODE DATABASE (SPEC §1 E14). The page refuses text holding a code point its
# character check (\p{Cn}) does not know, and normalises the rest with String.prototype.normalize. That
# is sound only if the two use the same Unicode data, which an engine need not guarantee. So the page
# checks, on load: the unicode-vectors.json cases (rejected, or exactly the pinned result), and these
# probes, one to three per Unicode version from 3.0 to 17.0, each a short string holding a code point
# that version added and that normalisation acts on (a combining mark between "a" and a mark of another
# combining class, or a decomposable character), with its NFC form. A probe whose code points the
# character check knows must normalise to exactly that form; a normaliser that does not know the
# character leaves it unchanged. Ages are from the Unicode Character Database; the expected forms were
# computed with Unicode 17.0 and agree with Unicode 16.0 on every probe it can answer. If a probe or
# vector fails, the page refuses non-ASCII text rather than normalise it wrongly.
PROBES = '[["3.0","61 346 323","1EA1 346"],["3.0","61 347 301","E1 347"],["3.0","4E 300","1F8"],["3.1","61 1D165 301","E1 1D165"],["3.1","61 1D166 301","E1 1D166"],["3.2","61 363 323","1EA1 363"],["3.2","61 364 323","1EA1 364"],["4.0","61 350 323","1EA1 350"],["4.0","61 351 323","1EA1 351"],["4.1","61 358 301","E1 358"],["4.1","61 359 301","E1 359"],["5.0","61 5BA 301","E1 5BA"],["5.0","61 7EB 323","1EA1 7EB"],["5.0","1B05 1B35","1B06"],["5.1","61 487 323","1EA1 487"],["5.1","61 616 323","1EA1 616"],["5.2","61 816 323","1EA1 816"],["5.2","61 817 323","1EA1 817"],["6.0","61 65F 301","E1 65F"],["6.0","61 859 301","E1 859"],["6.1","61 8E4 323","1EA1 8E4"],["6.1","61 8E5 323","1EA1 8E5"],["7.0","61 8FF 323","1EA1 8FF"],["7.0","61 1AB0 323","1EA1 1AB0"],["7.0","11347 1133E","1134B"],["8.0","61 8E3 301","E1 8E3"],["8.0","61 A69E 323","1EA1 A69E"],["9.0","61 8D4 323","1EA1 8D4"],["9.0","61 8D5 323","1EA1 8D5"],["10.0","61 D3B 301","E1 D3B"],["10.0","61 D3C 301","E1 D3C"],["11.0","61 7FD 301","E1 7FD"],["11.0","61 8D3 301","E1 8D3"],["12.0","61 EBA 301","E1 EBA"],["12.0","61 119E0 301","E1 119E0"],["13.0","61 1ABF 301","E1 1ABF"],["13.0","61 1AC0 301","E1 1AC0"],["13.0","11935 11930","11938"],["14.0","61 898 323","1EA1 898"],["14.0","61 899 301","E1 899"],["15.0","61 10EFD 301","E1 10EFD"],["15.0","61 10EFE 301","E1 10EFE"],["16.0","61 897 323","1EA1 897"],["16.0","61 10D69 323","1EA1 10D69"],["16.0","105D2 307","105C9"],["17.0","61 1ACF 323","1EA1 1ACF"],["17.0","61 1AD0 323","1EA1 1AD0"]]'
_uni = _json.loads((SRC.parents[1] / "test-vectors" / "unicode-vectors.json").read_text())
SELFTEST_JS = ("const SELFTEST = " + _json.dumps(
    {"brc": BRC145, "anchor": _anchor, "render": _render, "fp": _fp,
     "unicode": {k: _uni[k] for k in ("accept", "either_or", "reject_unless_assigned")},
     "probes": _json.loads(PROBES)}) + ";")

# The BUILT PAGE is Apache-2.0 (NOTICE), not BSL. It embeds the Apache-2.0 engine and is meant to be
# inscribed on chain and run by strangers, so a licence forbidding redistribution in a product could
# not describe what this artifact is for. The BUILDER stays BSL — it is release tooling.
HTML = r'''<!doctype html>
<!--
  Inkan Generator & Verifier — the reference verification surface for BRC-145.
  Source, licence documents and this page's published values: https://github.com/RexStarBSV/Inkan

  SPDX-License-Identifier: Apache-2.0
  SPDX-FileCopyrightText: 2026 RexStarBSV

  This page is licensed under the Apache License, Version 2.0
  (https://www.apache.org/licenses/LICENSE-2.0): verify Inkan codes and seals, and generate your
  own, in any product, commercial or not, forever, patent grant included. Copy it, host it,
  inscribe it. It is designed to be a single self-contained file precisely so that it can outlive
  the site it came from.

  Two parts of it are NOT covered by this page's Apache-2.0 grant, and each is marked in place as an
  SPDX snippet:
  - the embedded font, Inkan Sans: a Modified Version of IBM Plex Sans (subset, and renamed because
    "Plex" is a Reserved Font Name), Copyright 2017 IBM Corp., under the SIL Open Font License 1.1
    (http://scripts.sil.org/OFL; the full licence text is reproduced with the font data below).
    It is IBM's work, not endorsed by IBM.
  - the Inkan mark, the seal-ring logo at the top of the page: (c) 2026 RexStarBSV, all rights
    reserved, licensed by nothing here (see LICENSE-MARK in the repository above). You may pass
    this page on unmodified with the mark in it; a changed page must remove the mark or replace it
    with your own.

  The wider Inkan repository is multi-licence and most of it is NOT Apache-2.0; its NOTICE and
  LICENSING.md give the full map.
-->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Inkan Generator &amp; Verifier</title>
<style>
__FONTS__
:root{--bg:#f6f7f6;--panel:#fff;--line:#dfe3e1;--ink:#12201b;--dim:#5d6b65;
 --accent:#003022;--good:#0d6b4f;--bad:#b03427;--rule:#e3e7e5}
@media(prefers-color-scheme:dark){:root{--bg:#0b0f0d;--panel:#121815;--line:#232b27;
 --ink:#e6ebe8;--dim:#8fa098;--accent:#b9c8c4;--good:#4fbf95;--bad:#e06a5b;--rule:#232b27}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);padding:40px 18px 80px;
 font:15px/1.6 'Inkan Sans',ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:760px;margin:0 auto;display:flex;flex-direction:column;gap:26px}
.eyebrow{font:600 17px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.16em;
 text-transform:uppercase;color:var(--accent)}
h1{font-size:clamp(24px,4vw,32px);margin:10px 0 0;letter-spacing:-.02em}
.dek{color:var(--dim);max-width:60ch;margin-top:8px}
.lockup{display:flex;align-items:center;gap:16px}
.mark{display:block;width:64px;height:64px;flex:0 0 64px}
.mark svg{display:block;width:100%;height:100%}
.vtag{font:600 13px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;
 color:var(--bg);background:var(--accent);padding:5px 8px}
.card{background:var(--panel);border:1px solid var(--line);padding:22px}
.card h2{font-size:15px;margin:0 0 4px}
.kindcol{flex:0 1 230px}
.cardnote{margin:0 0 14px}
label{display:block;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:var(--dim);
 margin:14px 0 6px}
input[type=text],select{width:100%;padding:10px 12px;border:1px solid var(--line);
 background:var(--bg);color:var(--ink);font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
#kindsel{margin-bottom:8px}
input[type=file]{margin-top:6px;color:var(--dim);font-size:13px}
textarea{width:100%;padding:10px 12px;border:1px solid var(--line);background:var(--bg);
 color:var(--ink);font:12px ui-monospace,SFMono-Regular,Menlo,monospace;resize:vertical}
button{margin-top:18px;padding:11px 18px;border:0;background:var(--accent);
 color:var(--bg);font:600 14px 'Inkan Sans',system-ui;cursor:pointer}
.ghost{background:transparent;border:1px solid var(--line);color:var(--ink)}
button:disabled{opacity:.5;cursor:default}
a[href]{color:var(--accent)}
a.btn{display:inline-block;margin-top:18px;padding:11px 18px;text-decoration:none;font:600 14px 'Inkan Sans',system-ui;cursor:pointer}
a.btn[aria-disabled=true]{opacity:.5;cursor:default;pointer-events:none}
.row{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-start}
.row>div{flex:1 1 240px;min-width:0}
.result{display:none;margin-top:22px;padding:16px 18px;border:1px solid var(--line)}
.result.show{display:block}
.result.good{border-color:var(--good)}
.result.bad{border-color:var(--bad)}
.verdict{font:700 18px 'Inkan Sans',system-ui;display:flex;align-items:center;gap:10px}
.verdict.good{color:var(--good)} .verdict.bad{color:var(--bad)}
.seals{display:flex;gap:20px;margin-top:16px;flex-wrap:wrap}
.seals figure{margin:0;text-align:center}
canvas,figure img{width:160px;height:160px;image-rendering:pixelated;background:#111;display:block}
figure a{display:inline-block;line-height:0;text-decoration:none;cursor:pointer}
figcaption{font:11px ui-monospace,Menlo,monospace;color:var(--dim);margin-top:6px;
 width:160px;line-height:1.45;overflow-wrap:anywhere}
.kv{margin-top:14px;font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--dim);
 overflow-wrap:anywhere;line-height:1.7}
.kv b{color:var(--ink)}
footer{color:var(--dim);font-size:12px;border-top:1px solid var(--rule);padding-top:18px}
footer p{margin:0 0 8px;max-width:70ch}
code{font-family:ui-monospace,Menlo,monospace;background:var(--bg);padding:1px 5px;border:1px solid var(--line)}
.stline{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;color:var(--dim);margin-top:14px}
@media(max-width:600px){
 body{padding:22px 14px 56px}
 .wrap{gap:20px}
 .card{padding:16px}
 .row>div,.kindcol{flex:1 1 100%}
 .seals{gap:14px;justify-content:center}
 a.btn,button{width:100%;text-align:center}
 .dek,.cardnote{max-width:none}
}
[hidden]{display:none!important}
.gen{display:grid;grid-template-columns:minmax(0,1fr) 230px;grid-template-areas:"live live" "data kind";
 gap:4px 14px;margin-top:8px;align-items:start}
.live{grid-area:live;margin:6px 0 4px;display:flex;flex-direction:column;align-items:flex-start;gap:8px}
.live a{display:inline-block;line-height:0;text-decoration:none;cursor:pointer}
.live canvas,.live img{width:168px;height:168px}
.live figcaption{width:auto;max-width:100%;margin:0;display:flex;flex-direction:column;gap:2px}
.livecode{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--ink);overflow-wrap:anywhere}
.livecode.bad{color:var(--bad)} .livecode.idle{color:var(--dim)}
.livenote{font:12px/1.4 'Inkan Sans',system-ui;color:var(--dim)}
.datacol{grid-area:data;min-width:0} .gen .kindcol{grid-area:kind;min-width:0}
.modes{display:flex;flex-wrap:wrap;gap:4px 16px;margin:2px 0 6px}
.modes label{display:inline-flex;align-items:center;gap:6px;margin:0;font-size:13px;letter-spacing:0;
 text-transform:none;color:var(--ink);cursor:pointer}
.hint{margin:0 0 6px;min-height:1.5em;font-size:13px;line-height:1.5;color:var(--accent)}
.hint.again:not(:empty){animation:hintin .35s ease-out}
@keyframes hintin{from{opacity:0}to{opacity:1}}
@media(prefers-reduced-motion:reduce){.hint.again:not(:empty){animation:none}}
#data,#datahex{font-size:15px;line-height:1.45}
.fieldnote{margin:6px 0 0;font-size:12px;color:var(--dim)}
.scope{font-size:13px}
@media(max-width:600px){
 .gen{grid-template-columns:minmax(0,1fr);grid-template-areas:"live" "data" "kind"}
 .live{align-items:center;text-align:center} .live figcaption{align-items:center}
 .live canvas,.live img{width:144px;height:144px}
 #data,#datahex{font-size:16px}
}
@media(max-width:680px){.hint{min-height:3em}}
.pill{display:inline-block;font:600 10px ui-monospace,Menlo,monospace;letter-spacing:.08em;
 padding:2px 7px;border:1px solid var(--line);color:var(--dim);cursor:help}
.tipwrap{position:relative;display:inline-block}
.tip{position:absolute;left:0;top:calc(100% + 6px);z-index:20;width:max-content;
 max-width:min(92ch,94vw);max-height:82vh;overflow:auto;background:var(--panel);border:1px solid var(--line);
 padding:12px 14px;white-space:pre-wrap;overflow-wrap:anywhere;text-align:left;
 font:11px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--dim);
 box-shadow:0 8px 24px rgba(0,0,0,.35)}
.tip[hidden]{display:none}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="lockup"><span class="mark">__ICON__</span><span class="eyebrow">Inkan Generator &amp; Verifier</span><span class="vtag">V__VERSION__</span></div>
  <h1>Generate or verify an Inkan — trust nothing, recompute everything</h1>
  <p class="dek">An Inkan is a permanent fingerprint of a piece of content, together with a picture
  of that fingerprint. This page is the reference verifier for the standard that defines them,
  <b>BRC-145</b>, and it is the whole implementation: everything below is computed here, on this
  device.</p>
  <p class="dek">Enter a <code>(data, kind)</code> pair and this page renders its canonical seal and
  its <code>ik1</code> code — the fingerprint written as text, always <code>ik1</code> followed by
  64 hex characters: that is <b>generation</b>. Add a seal image you were
  shown and the same render is compared to it pixel-for-pixel: that is <b>verification</b>. A phishing
  lookalike fails, because it is not the byte-exact render. Both are the same computation, which is why
  they cannot disagree. No network, no server, no storage: it runs from a local file, a static host, or
  an on-chain inscription with equal fidelity.</p>
  <p class="dek scope"><b>What this page checks:</b> <code>ik1</code> codes (anchor version 1, SHA-256 over
  the domain <code>inkan/v1</code>), Seal v3 seals, tamper fingerprints of SPEC §7 (SHA-256; version 1
  unless you enter another) and version-1 canary records. Anything newer is refused or reads
  UNSUPPORTED, never guessed. Text is checked against this browser's <span id="univer">Unicode</span>
  character database.</p>
  <p class="stline"><span class="tipwrap"><span class="pill" id="selftest" tabindex="0"
    role="button" aria-describedby="selftip">self-test…</span><span class="tip" id="selftip"
    role="tooltip" hidden></span></span>
  <span>recomputed from the standard's pinned vectors on every load</span></p>
</header>

<div class="card">
  <h2>Content anchor — typed commitment &amp; seal</h2>
  <p class="dek cardnote">The first layer of the standard. A <code>(data, kind)</code> pair commits to
  <i>typed</i> content: the kind is folded into the digest, so a seal over an address and a seal over a
  contract can never collide even when the underlying bytes are identical. Enter a pair to generate its
  anchor and seal; add the seal image someone showed you to check it pixel-for-pixel.</p>
  <p class="dek cardnote"><b>Peer-to-peer identity checks.</b> Two parties who should be holding the
  same key, address or handle can each seal it and compare: a mismatch is visible at once. Define your
  own kind — <code>yourapp:member</code> — and that comparison can never be confused with another
  application's, because the kind is inside the digest. Per §9 of the standard, treat a visual match as
  a <i>tamper-notice channel only</i>: it is never sufficient authentication for a value-at-risk
  decision, and a GENUINE verdict requires the full 32-byte digest — which is what the seal-image
  comparison below actually does.</p>
  <p class="dek cardnote"><b>Tiers.</b> A kind may carry <code>@t1</code>, <code>@t2</code> or
  <code>@t3</code>, choosing how many cells the seal draws: <b>72, 48 or 24</b>. More cells means more
  visible entropy and a costlier visual forgery — roughly <b>2<sup>79.5</sup></b> distinct seals at T1,
  <b>2<sup>55.5</sup></b> at T2 and <b>2<sup>31.5</sup></b> at T3. Reserved kinds have a fixed tier
  (<code>address</code> is T1, <code>code</code> is T3). <b>Any other string defaults to T2</b>, and so
  does an unrecognised suffix: <code>@t4</code> is not a tier, so <code>thing@t4</code> is simply a kind
  whose name ends in "@t4", still at T2. Tier changes the picture only. The anchor is the full 32-byte
  digest at every tier, which is why T3's findable <i>image</i> collisions are a documented design
  choice rather than a weakness — the digest is what commits, never the picture.</p>
  <div class="gen">
    <figure class="live" id="live">
      <a id="sealLink" download title="Save this seal as a tagged PNG"><canvas id="cvExpected" width="224" height="224" aria-hidden="true"></canvas><img id="imExpected" alt="Your Inkan seal for the data and kind below" style="display:none"></a>
      <figcaption><span class="livecode" id="livecode"></span>
        <span class="livenote">Your Inkan, redrawn as you type. Click it to save the seal.</span></figcaption>
    </figure>
    <div class="datacol">
      <label for="data" id="datalabel">Data to seal (an address, a key, any text…)</label>
      <div class="modes" role="radiogroup" aria-label="Read the data as">
        <label><input type="radio" name="dmode" id="modeText" value="text" checked> text</label>
        <label><input type="radio" name="dmode" id="modeFile" value="file"> text file</label>
        <label><input type="radio" name="dmode" id="modeHex" value="hex"> raw bytes (hex)</label>
      </div>
      <p class="hint" id="datahint" aria-live="polite"></p>
      <textarea id="data" rows="3" autocomplete="off" autocapitalize="off" spellcheck="false"
                aria-describedby="datahint datanote"></textarea>
      <textarea id="datahex" rows="3" autocomplete="off" autocapitalize="off" spellcheck="false"
                aria-describedby="datanote" placeholder="for example 48656c6c6f" hidden></textarea>
      <input type="file" id="datafile" aria-describedby="datanote" hidden>
      <p class="fieldnote" id="datanote"></p>
    </div>
    <div class="kindcol">
      <label for="kindsel">Kind — what the data is</label>
      <select id="kindsel"></select>
      <input type="text" id="kind" value="address" autocomplete="off"
             placeholder="any kind; add @t1/@t2/@t3 for tier">
    </div>
  </div>
  <label for="file">Seal image to compare (optional PNG — leave empty to generate only)</label>
  <input type="file" id="file" accept="image/png">
  <div class="row">
    <button id="go">Compare seal image</button>
    <a class="btn ghost" id="dlseal" aria-disabled="true" download>Download seal PNG</a>
    <a class="btn ghost" id="dl" aria-disabled="true" download>Download report</a>
    <button class="ghost" id="avjump">Avalanche check</button>
  </div>

  <div class="result" id="result">
    <div class="verdict" id="verdict"></div>
    <div class="seals">
      <figure id="figCmp" style="display:none"><canvas id="cvCmp" width="224" height="224"></canvas><figcaption>recomputed (genuine)</figcaption></figure>
      <figure id="figGot" style="display:none"><canvas id="cvGot" width="224" height="224"></canvas><figcaption>presented</figcaption></figure>
    </div>
    <div class="kv" id="kv"></div>
  </div>
</div>

<div class="card" id="avcard">
  <h2>Avalanche — why a lookalike cannot be grown from yours</h2>
  <p class="dek cardnote">The seal above is not a picture of your data, it is a picture of its digest,
  so neighbouring inputs are not neighbouring images. This flips <b>every single bit</b> of whatever is
  in the sealed-data field, recomputes the cells each time, and reports the <b>fewest</b> that moved —
  the best an attacker could hope for by nudging the input. The worst case is drawn beside yours, so
  you can see that even the least dramatic single-bit neighbour is unmistakable.</p>
  <div class="row"><button id="avgo">Flip every bit of the current data</button></div>
  <div class="result" id="avresult">
    <div class="verdict" id="avverdict"></div>
    <div class="seals" id="avseals">
      <figure><canvas id="cvAv0" width="224" height="224"></canvas>
        <figcaption>your data</figcaption></figure>
      <figure id="figAv1" style="display:none"><canvas id="cvAv1" width="224" height="224"></canvas>
        <figcaption>closest single-bit neighbour</figcaption></figure>
    </div>
    <div class="kv" id="avkv"></div>
  </div>
</div>

<div class="card">
  <h2>Code fingerprint — software &amp; build provenance</h2>
  <p class="dek cardnote">The second layer of the standard. A release publishes the
  fingerprint of the exact bytes it shipped; you recompute it here from the file you actually hold. A
  match proves the code you are running is the code that was released. Different adopters get different
  digests for identical bytes, because the adopter name is inside the hash.</p>
  <div class="row">
    <div>
      <label for="fpadopter">Adopter (namespace, e.g. the project publishing the build)</label>
      <input type="text" id="fpadopter" placeholder="acme" autocomplete="off">
    </div>
    <div style="flex:0 0 120px">
      <label for="fpver">Version</label>
      <input type="text" id="fpver" value="1" autocomplete="off">
    </div>
  </div>
  <label for="fpfile">File to fingerprint (any bytes; stays on this device)</label>
  <input type="file" id="fpfile">
  <label for="fpclaim">Claimed fingerprint to compare (optional hex)</label>
  <input type="text" id="fpclaim" placeholder="64 hex characters" autocomplete="off">
  <div class="row"><button id="fpgo">Compute fingerprint</button></div>
  <div class="result" id="fpresult">
    <div class="verdict" id="fpverdict"></div>
    <div class="kv" id="fpkv"></div>
  </div>
</div>

<div class="card">
  <h2>Warrant canary — is the operator still uncompromised?</h2>
  <p class="dek cardnote">The third layer of the standard. A canary is a signed, freshness-proofed
  statement that the publisher has not
  been compromised or coerced. <b>Absence, staleness or a bad signature is the warning.</b> The record
  embeds a recent block height and hash, so it cannot have been signed before that block existed. This
  page verifies only: it holds no key and can sign nothing.</p>
  <p class="dek cardnote"><b>How to use it.</b>
  <b>1.</b> Get the publisher's public key from somewhere you <i>already</i> trust — pinned in an app
  you installed earlier, a previous release, or handed to you in person. Taking the key from the same
  page that serves the canary proves nothing, because whoever controls that page controls both.
  <b>2.</b> Fetch their latest canary record and signature from wherever they anchor it. On-chain is
  the point: an inscription or <code>OP_RETURN</code> cannot be quietly withdrawn, so a canary that
  stops appearing leaves a visible gap instead of vanishing.
  <b>3.</b> Paste record, key and signature below and check.
  <b>4.</b> Read the verdict, and sanity-check the record yourself: <code>seq</code> should be higher
  than the last one you saw, and <code>block_height</code> should be recent.</p>
  <p class="dek cardnote"><b>What the verdicts mean.</b>
  <b>OK</b> — signed by that key and inside the freshness window.
  <b>STALE</b> — the signature is good but the record is old. The publisher has stopped renewing;
  that is a warning, not a pass.
  <b>INVALID</b> — the signature does not verify. Wrong key, altered record, or forgery.
  <b>UNSUPPORTED</b> — a newer record version than this page implements. Get a newer verifier; it is
  not a finding against the publisher.
  <b>MALFORMED</b> — the record, key or signature is not in the form the standard requires, so the
  signature could not be checked at all. Usually a truncated paste. It is not a pass, and not
  evidence of forgery.
  And the one no button can show you: <b>nothing to check at all.</b> If a canary you expect is simply
  missing, that is the loudest result of all — the design assumes silence is what a coerced
  publisher is able to produce.</p>
  <p class="dek cardnote">This checks <b>any publisher's</b> canary — paste theirs below. Nothing
  here is specific to Inkan or to any one project.
  <a href="#" id="cnexample">Load the BRC-145 example</a> if you would rather see it work first; that
  record is dated 2026-06-30 and will read STALE once it ages past the 35-day window, which is itself
  worth seeing — it is what a canary nobody renewed looks like.</p>
  <label for="cnrec">Canary record, exactly as published (canonical JSON)</label>
  <textarea id="cnrec" rows="5" spellcheck="false"></textarea>
  <p class="dek cardnote">Paste the record exactly as the publisher published it. The standard fixes
  its form byte for byte: one line, the seven members in key order, no spaces. A copy that has been
  re-formatted reads MALFORMED, because a verifier must judge the bytes that were signed. Blank space
  around the record is ignored.</p>
  <div class="row">
    <div>
      <label for="cnpub">Publisher public key (hex)</label>
      <input type="text" id="cnpub" autocomplete="off" placeholder="33-byte compressed SEC">
    </div>
  </div>
  <label for="cnsig">Signature (DER hex)</label>
  <input type="text" id="cnsig" autocomplete="off">
  <div class="row">
    <div>
      <label for="cnas">Evaluate as of (blank = now)</label>
      <input type="text" id="cnas" autocomplete="off" placeholder="YYYY-MM-DD">
    </div>
    <div>
      <label for="cnwin">Freshness window (days)</label>
      <input type="text" id="cnwin" value="35" autocomplete="off">
    </div>
    <div>
      <label for="cnheight">Current block height (optional)</label>
      <input type="text" id="cnheight" autocomplete="off">
    </div>
  </div>
  <p class="dek cardnote">The record cites a block height and hash, which is what stops it being
  backdated: it cannot have been signed before that block existed. Checking that needs a fact about
  the chain, and this page never goes online — so bring one. Enter a height you trust, from your own
  node or a wallet, and the arithmetic happens here. Leave it blank to skip the check entirely.</p>
  <div class="row"><button id="cngo">Check canary</button></div>
  <div class="result" id="cnresult">
    <div class="verdict" id="cnverdict"></div>
    <div class="kv" id="cnkv"></div>
  </div>
</div>

<footer>
<p><b>Keep this file.</b> It is entirely self-contained: save it locally and it keeps working with no
network, no install and no server, exactly as it does now. That local copy is the durable form.</p>
<p><b>Verify this page against its own standard.</b> Its release publishes a sidecar
<code>inkan-verify.html.inkan.json</code> carrying an <code>adopter_fingerprint</code>. Drop this very
file into the fingerprint card above, using the <code>adopter</code> and version from that sidecar,
and compare. Use <code>adopter_fingerprint</code>, not <code>fingerprint</code>: the latter is a plain
SHA-256 of the bytes and will not match what the card computes.</p>
<p>Inkan Seal <span id="ver"></span> · anchor + fingerprint layers · original work ·
generated from the reference engine · self-contained &amp; inscription-ready</p>
</footer>
</div>

<script>
// ==== canonical Inkan engine (inlined from Inkan/js/src — DO NOT EDIT; regenerate) ====
__ENGINE__
// ==== verifier UI ====
(function(){
  const $ = id => document.getElementById(id);
  const toHex = u => Array.from(u).map(b=>b.toString(16).padStart(2,'0')).join('');
  document.getElementById('ver').textContent = 'v' + SEAL_VERSION;

  // Every result below is built from DOM nodes, never from a string of HTML. Several of the values
  // shown come from outside this page: the ik1 code read from an uploaded PNG's metadata, each
  // field of a pasted canary record, and whatever is typed as a kind or an adopter. Parsed as
  // markup, any of them could run script and repaint a verdict, so a crafted file could make a
  // forgery read GENUINE. Text goes in as text nodes; only the fixed labels are elements.
  const BR = {};
  const bold = s => { const e = document.createElement('b'); e.textContent = String(s); return e; };
  const tone = (s, colour) => {
    const e = document.createElement('span'); e.textContent = String(s);
    e.style.color = 'var(--' + colour + ')'; return e;
  };
  function fill(el, ...parts){
    el.textContent = '';
    for (const p of parts){
      if (p === null || p === undefined || p === false || p === '') continue;
      el.appendChild(p === BR ? document.createElement('br')
                   : (typeof p === 'object' ? p : document.createTextNode(String(p))));
    }
  }

  const sel = $('kind');
  const ksel = $('kindsel');
  // The reserved kinds are a convenience, NOT the whole namespace: the standard lets anyone define
  // a kind without asking, and an unrecognised string is a valid open kind at the default tier. The
  // text field therefore stays the source of truth and the dropdown only fills it in; a select on
  // its own would misrepresent the standard as a closed list.
  for (const k of Object.keys(KINDS)) {
    const o = document.createElement('option');
    o.value = k;
    o.textContent = (k === '') ? '(generic)' : k;
    ksel.appendChild(o);
  }
  ksel.value = sel.value;
  ksel.onchange = () => { sel.value = ksel.value; live(); };
  sel.addEventListener('input', () => {
    // never let a hand-typed custom kind look like a reserved selection
    if (Object.prototype.hasOwnProperty.call(KINDS, sel.value)) ksel.value = sel.value;
    else ksel.selectedIndex = -1;
  });

  // ==== verifiable-PNG decoder (SPEC §6.1, E24) ====
  // The page decides on its OWN decode of the file's bytes, under exactly the rules the reference
  // verifier applies, and never asks the browser's image decoder. A browser decodes far more than
  // the profile allows and draws some of it differently from its pixels: it read a looping animated
  // GIF named seal.png as its first frame, honoured colour-space and orientation chunks, and opened
  // RGBA, 16-bit, 4-bit-palette and interlaced files, so a forgery could read GENUINE here while the
  // reference rejected it. The canvas is used only to show the pixels this decoder produced.
  const PNG_SIGNATURE = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
  const PNG_ALLOWED = ['IHDR', 'PLTE', 'IDAT', 'IEND', 'tEXt', 'zTXt', 'iTXt', 'pHYs', 'tIME'];
  const PNG_RENDERING = ['tRNS', 'gAMA', 'iCCP', 'sRGB', 'cHRM', 'sBIT', 'bKGD', 'cICP', 'eXIf', 'mDCV',
                         'cLLI', 'acTL', 'fcTL', 'fdAT'];
  // The largest image this page will inflate in memory: a 42x upscale of a truecolour seal. Larger
  // files are reported as too large to check here, never as a verdict.
  const PNG_MAX_RAW = 1 << 28;
  const PNG_CRC = (() => { const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++){ let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
    return t; })();
  function pngCrc(u, from, to){
    let c = 0xFFFFFFFF;
    for (let i = from; i < to; i++) c = PNG_CRC[(c ^ u[i]) & 0xFF] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }
  const be32 = (u, i) => ((u[i] << 24) | (u[i + 1] << 16) | (u[i + 2] << 8) | u[i + 3]) >>> 0;
  const chunkName = (u, i) => String.fromCharCode(u[i], u[i + 1], u[i + 2], u[i + 3]);
  class NotVerifiable extends Error {}
  class TooLarge extends Error {}
  class WrongSize extends Error {}
  const refuse = (m, rule) => { throw new NotVerifiable(m + (rule ? ' (SPEC §6.1 rule ' + rule + ')' : '')); };

  // RFC 1950/1951 inflate, written to refuse exactly what zlib refuses (it follows zlib's puff.c):
  // the zlib header (method 8, window up to 32 KiB, no preset dictionary), block type 3, a stored
  // block whose length check fails, too many length or distance codes, a repeat with nothing to
  // repeat, a missing end-of-block code, an over-subscribed or incomplete code (a single one-bit
  // code excepted), symbols 286, 287, 30 and 31, a distance too far back, a wrong Adler-32, and any
  // byte after the stream. It stops as soon as the output would pass `want` bytes.
  function inflateZlib(z, want){
    if (z.length < 2 || (z[0] & 15) !== 8 || (z[0] >> 4) > 7 || ((z[0] << 8) | z[1]) % 31 !== 0 || (z[1] & 32))
      refuse('the image data is not a zlib stream with compression method 8 and no preset dictionary', 6);
    const out = new Uint8Array(want);
    let op = 0, ip = 2, bitbuf = 0, bitcnt = 0;
    const corrupt = m => refuse('corrupt PNG: ' + m, 6);
    const bits = n => {
      while (bitcnt < n){ if (ip >= z.length) corrupt('the zlib stream is truncated'); bitbuf |= z[ip++] << bitcnt; bitcnt += 8; }
      const v = bitbuf & ((1 << n) - 1); bitbuf >>>= n; bitcnt -= n; return v;
    };
    const put = b => { if (op >= want) refuse('corrupt PNG: IDAT expands beyond the size IHDR declares (compression bomb, or a mismatched header)'); out[op++] = b; };
    // Canonical Huffman code from code lengths: count[len] codes of each length and the symbols in
    // code order. `left` > 0 means incomplete, < 0 over-subscribed.
    function build(lengths, n){
      const count = new Uint16Array(16), symbol = new Uint16Array(n), offs = new Uint16Array(16);
      for (let s = 0; s < n; s++) count[lengths[s]]++;
      let left = 1;
      if (count[0] === n) return { count, symbol, left: 0 };     // no codes: complete, unusable
      for (let len = 1; len <= 15; len++){ left <<= 1; left -= count[len]; if (left < 0) return { left }; }
      for (let len = 1; len < 15; len++) offs[len + 1] = offs[len] + count[len];
      for (let s = 0; s < n; s++) if (lengths[s]) symbol[offs[lengths[s]]++] = s;
      return { count, symbol, left };
    }
    function decode(h){
      let code = 0, first = 0, index = 0;
      for (let len = 1; len <= 15; len++){
        code |= bits(1);
        const c = h.count[len];
        if (code - c < first) return h.symbol[index + (code - first)];
        index += c; first += c; first <<= 1; code <<= 1;
      }
      corrupt('an invalid Huffman code');
    }
    const LBASE = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
    const LEXT = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
    const DBASE = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
    const DEXT = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];
    function codes(lc, dc){
      for (;;){
        let sym = decode(lc);
        if (sym < 256) { put(sym); continue; }
        if (sym === 256) return;
        sym -= 257;
        if (sym >= 29) corrupt('an invalid length code');
        const len = LBASE[sym] + bits(LEXT[sym]);
        const ds = decode(dc);
        if (ds >= 30) corrupt('an invalid distance code');
        const dist = DBASE[ds] + bits(DEXT[ds]);
        if (dist > op) corrupt('a distance too far back');
        for (let i = 0; i < len; i++) put(out[op - dist]);
      }
    }
    let fixedL = null, fixedD = null;
    let last;
    do {
      last = bits(1);
      const type = bits(2);
      if (type === 0){
        bitbuf = 0; bitcnt = 0;                       // a stored block starts on a byte boundary
        if (ip + 4 > z.length) corrupt('the zlib stream is truncated');
        const len = z[ip] | (z[ip + 1] << 8), nlen = z[ip + 2] | (z[ip + 3] << 8);
        ip += 4;
        if (len !== (~nlen & 0xFFFF)) corrupt('a stored block\'s length check fails');
        if (ip + len > z.length) corrupt('the zlib stream is truncated');
        for (let i = 0; i < len; i++) put(z[ip++]);
      } else if (type === 1){
        if (!fixedL){
          const l = new Uint8Array(288);
          for (let s = 0; s < 288; s++) l[s] = s < 144 ? 8 : s < 256 ? 9 : s < 280 ? 7 : 8;
          fixedL = build(l, 288);
          fixedD = build(new Uint8Array(30).fill(5), 30);
        }
        codes(fixedL, fixedD);
      } else if (type === 2){
        const nlen = bits(5) + 257, ndist = bits(5) + 1, ncode = bits(4) + 4;
        if (nlen > 286 || ndist > 30) corrupt('too many length or distance codes');
        const ORDER = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];
        const cl = new Uint8Array(19);
        for (let i = 0; i < ncode; i++) cl[ORDER[i]] = bits(3);
        const ch = build(cl, 19);
        if (ch.left !== 0) corrupt('an incomplete or over-subscribed code-length code');
        const lengths = new Uint8Array(nlen + ndist);
        for (let i = 0; i < nlen + ndist;){
          let sym = decode(ch);
          if (sym < 16){ lengths[i++] = sym; continue; }
          let len = 0, rep;
          if (sym === 16){ if (i === 0) corrupt('a repeat with no previous length'); len = lengths[i - 1]; rep = 3 + bits(2); }
          else if (sym === 17) rep = 3 + bits(3);
          else rep = 11 + bits(7);
          if (i + rep > nlen + ndist) corrupt('too many code lengths');
          while (rep--) lengths[i++] = len;
        }
        if (lengths[256] === 0) corrupt('no end-of-block code');
        const lc = build(lengths.subarray(0, nlen), nlen);
        if (lc.left < 0 || (lc.left > 0 && nlen !== lc.count[0] + lc.count[1])) corrupt('an incomplete or over-subscribed literal/length code');
        const dc = build(lengths.subarray(nlen), ndist);
        if (dc.left < 0 || (dc.left > 0 && ndist !== dc.count[0] + dc.count[1])) corrupt('an incomplete or over-subscribed distance code');
        codes(lc, dc);
      } else corrupt('an invalid block type');
    } while (!last);
    bitbuf = 0; bitcnt = 0;
    if (ip + 4 > z.length) corrupt('the zlib stream has no Adler-32 check');
    let a = 1, b = 0;
    for (let i = 0; i < op; i++){ a = (a + out[i]) % 65521; b = (b + a) % 65521; }
    if ((((b << 16) | a) >>> 0) !== be32(z, ip)) corrupt('the zlib stream\'s Adler-32 check fails');
    ip += 4;
    if (ip !== z.length) refuse((z.length - ip) + ' byte(s) follow the end of the zlib stream', 6);
    if (op !== want) corrupt('wrong scanline length');
    return out;
  }

  // The profile itself: chunks, order, header, palette, metadata, then the image data. Returns
  // {width, height, pixels} (RGB888) or throws NotVerifiable with the rule broken, or TooLarge.
  // `sizeProblem(width, height)`, if given, names a size the caller can never use, and the file is
  // then refused with WrongSize before its image data is inflated.
  function decodePng(u, sizeProblem){
    for (let i = 0; i < 8; i++) if (u[i] !== PNG_SIGNATURE[i]) refuse('not a PNG: the file does not begin with the PNG signature');
    const chunks = [];
    let pos = 8;
    for (;;){
      if (pos + 12 > u.length) refuse('the file ends inside a chunk, or has no IEND', 1);
      const len = be32(u, pos), name = chunkName(u, pos + 4);
      if (len > 0x7FFFFFFF) refuse('a chunk length is over 2^31 - 1', 1);
      if (pos + 12 + len > u.length) refuse('chunk ' + name + ' runs past the end of the file', 1);
      if (pngCrc(u, pos + 4, pos + 8 + len) !== be32(u, pos + 8 + len)) refuse('chunk ' + name + ' has a wrong CRC', 1);
      if (PNG_ALLOWED.indexOf(name) < 0)
        refuse('the file carries chunk ' + name + (PNG_RENDERING.indexOf(name) >= 0
          ? ', which changes what a viewer draws without changing the pixels compared' : '') +
          '; a verifiable PNG may carry only IHDR, PLTE, IDAT, IEND, tEXt, zTXt, iTXt, pHYs and tIME', 2);
      chunks.push({ name, data: u.subarray(pos + 8, pos + 8 + len) });
      pos += 12 + len;
      if (name === 'IEND') break;
    }
    if (pos !== u.length) refuse((u.length - pos) + ' byte(s) follow IEND', 1);
    const names = chunks.map(c => c.name);
    const at = n => names.reduce((a, x, i) => (x === n ? a.concat(i) : a), []);
    const idat = at('IDAT');
    if (names[0] !== 'IHDR' || at('IHDR').length !== 1) refuse('IHDR must come first and appear once', 3);
    if (chunks[chunks.length - 1].data.length) refuse('IEND must have no data', 3);
    if (!idat.length) refuse('there is no IDAT chunk', 6);
    if (idat[idat.length - 1] - idat[0] !== idat.length - 1) refuse('the IDAT chunks are not consecutive', 3);
    for (const [n, beforeIdat] of [['PLTE', true], ['pHYs', true], ['tIME', false]]){
      const a = at(n);
      if (a.length > 1 || (beforeIdat && a.length && a[0] > idat[0]))
        refuse(n + ' must appear at most once' + (beforeIdat ? ', before the first IDAT' : ''), 3);
    }
    const h = chunks[0].data;
    if (h.length !== 13) refuse('IHDR must hold 13 bytes', 4);
    const width = be32(h, 0), height = be32(h, 4), depth = h[8], ctype = h[9];
    if (width < 1 || width > 0x7FFFFFFF || height < 1 || height > 0x7FFFFFFF) refuse('width and height must be from 1 to 2^31 - 1', 4);
    if (depth !== 8) refuse('bit depth ' + depth + '; a verifiable PNG is 8-bit', 4);
    if (ctype !== 2 && ctype !== 3) refuse('colour type ' + ctype + '; a verifiable PNG is truecolour (2) or indexed-colour (3)', 4);
    if (h[10] !== 0 || h[11] !== 0) refuse('the IHDR compression and filter methods must be 0', 4);
    if (h[12] !== 0) refuse('the image is interlaced; a verifiable PNG is not', 4);
    const plte = ctype === 3 ? (chunks.find(c => c.name === 'PLTE') || null) : null;
    if (ctype === 3){
      if (!plte) refuse('an indexed-colour image needs a PLTE', 5);
      if (plte.data.length % 3 || plte.data.length < 3 || plte.data.length > 768) refuse('PLTE must hold 1 to 256 three-byte entries', 5);
    }
    for (const c of chunks){
      if ((c.name === 'pHYs' && c.data.length !== 9) || (c.name === 'tIME' && c.data.length !== 7))
        refuse(c.name + ' must hold ' + (c.name === 'pHYs' ? 9 : 7) + ' bytes', 7);
    }
    // A size the caller can never use is refused here, before the size limit below: otherwise a file
    // whose header declares a huge image read "too large to check", where the reference verifier,
    // which decodes first and checks the size after, reads REJECTED.
    const wrong = sizeProblem ? sizeProblem(width, height) : null;
    if (wrong) throw new WrongSize(wrong);
    const ch = ctype === 2 ? 3 : 1, stride = width * ch, want = (stride + 1) * height;
    if (want > PNG_MAX_RAW) throw new TooLarge('this image (' + width + '×' + height + ') is too large for this page to decode in memory');
    let zl = 0; for (const i of idat) zl += chunks[i].data.length;
    const z = new Uint8Array(zl); { let o = 0; for (const i of idat){ z.set(chunks[i].data, o); o += chunks[i].data.length; } }
    const raw = inflateZlib(z, want);
    const px = new Uint8Array(width * height * 3);
    let prev = new Uint8Array(stride), line = new Uint8Array(stride), o = 0;
    const entries = plte ? plte.data.length / 3 : 0;
    for (let y = 0, r = 0; y < height; y++){
      const ft = raw[r++];
      if (ft > 4) refuse('a scanline has filter type ' + ft + '; only 0 to 4 exist', 6);
      for (let i = 0; i < stride; i++){
        const x = raw[r++], a = i >= ch ? line[i - ch] : 0, b = prev[i], c = i >= ch ? prev[i - ch] : 0;
        let v;
        if (ft === 0) v = x;
        else if (ft === 1) v = x + a;
        else if (ft === 2) v = x + b;
        else if (ft === 3) v = x + ((a + b) >> 1);
        else { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
               v = x + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c); }
        line[i] = v & 0xFF;
      }
      if (ctype === 3){
        for (let i = 0; i < stride; i++){
          const k = line[i];
          if (k >= entries) refuse("a pixel's palette index is not less than the number of PLTE entries", 5);
          px[o++] = plte.data[k * 3]; px[o++] = plte.data[k * 3 + 1]; px[o++] = plte.data[k * 3 + 2];
        }
      } else { px.set(line, o); o += stride; }
      const t = prev; prev = line; line = t;
    }
    return { width, height, pixels: px };
  }

  // A presented image, reduced to the native canvas exactly as SPEC §6 says: an exact integer
  // upscale is reduced only if EVERY pixel of each block is identical (E10), a non-uniform block is
  // its own failure, and any other size is not the seal. Returns {width, height, pixels, size} or
  // {rejected: reason} or {tooLarge: reason}.
  function presentedNative(bytes){
    const n = CANVAS;
    const sizeProblem = (w, h) => (w !== h || w % n !== 0)
      ? 'the image is ' + w + '×' + h + ', not ' + n + '×' + n + ' or an exact integer multiple of it' : null;
    let png;
    try { png = decodePng(bytes, sizeProblem); }
    catch (e){
      if (e instanceof WrongSize) return { rejected: e.message, size: true };
      if (e instanceof TooLarge) return { tooLarge: e.message };
      if (e instanceof NotVerifiable) return { rejected: 'the file is not a verifiable PNG: ' + e.message };
      throw e;
    }
    const W = png.width;
    const scale = W / n, px = new Uint8Array(n * n * 3);
    for (let y = 0; y < n; y++) for (let x = 0; x < n; x++){
      const s = ((y * scale) * W + x * scale) * 3, d = (y * n + x) * 3;
      px[d] = png.pixels[s]; px[d + 1] = png.pixels[s + 1]; px[d + 2] = png.pixels[s + 2];
      for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++){
        const s2 = ((y * scale + dy) * W + (x * scale + dx)) * 3;
        if (png.pixels[s2] !== px[d] || png.pixels[s2 + 1] !== px[d + 1] || png.pixels[s2 + 2] !== px[d + 2])
          return { rejected: 'the image is a valid ' + scale + '× upscale of ' + n + ', but its pixel blocks are ' +
                   'not uniform: pixels WITHIN a block differ, so it is not an upscale of any seal. A clean ' +
                   'upscale repeats each pixel exactly.' };
      }
    }
    return { width: n, height: n, pixels: px, size: png.width + '×' + png.height };
  }
  // ==== end verifiable-PNG decoder ====

  // Set by the self-test when this browser's character check and its normaliser disagree (SPEC §1
  // E14): non-ASCII text is then refused, since it cannot be normalised the way the standard needs.
  let textProblem = null;
  const cps = a => String.fromCodePoint(...(a || []).map(h => parseInt(h, 16)));
  const knowsAll = t => { try { rejectUnassigned(t, 'text'); return true; } catch (e) { return false; } };
  $('univer').textContent = 'Unicode ' + (unicodeVersion() || '(older than 3.0)');

  // Known-answer self-test, run on every load.
  //
  //   brc     the vectors BRC-145 itself publishes (TV1-TV6). These are what licenses the phrase
  //           "per BRC-145"; the rest are this implementation's own regression corpus.
  //   anchor  raw data -> inkanSeed -> sha256 -> sealRgb, end to end
  //   render  pinned digest -> sealRgb, across every cell profile
  //   png     pinned digest -> sealPng, so the download path is covered too
  //   fp      payload + adopter -> fingerprintHex
  //
  // History worth keeping: this once fed pinned DIGESTS straight to the renderer, so destroying
  // inkanSeed still produced a green tick while the page emitted garbage codes -- it asserted
  // conformance to the one construction it never executed.
  try {
    let pass = 0, total = 0, brcPass = 0, brcTotal = 0;
    const bytes = hx => Uint8Array.from(hx.match(/../g).map(x => parseInt(x, 16)));
    const eq = (a, b) => { total++; if (a === b) pass++; return a === b; };
    const eqBrc = (a, b) => { brcTotal++; if (eq(a, b)) brcPass++; };

    for (const v of SELFTEST.brc.seed) eqBrc(toHex(inkanSeed(v.d, v.k)), v.h);
    for (const v of SELFTEST.brc.code) eqBrc('ik1' + toHex(sha256(inkanSeed(v.d, v.k))), v.h);
    for (const v of SELFTEST.brc.kind) eqBrc(JSON.stringify(resolveKind(v.k)), JSON.stringify(v.h));
    for (const v of SELFTEST.brc.fp)
      eqBrc(fingerprintHex(new TextEncoder().encode(v.p), v.a, v.v), v.h);
    for (const v of SELFTEST.brc.canary){
      eqBrc(String(canonicalBytes(v.r).length), String(v.bytes));
      eqBrc(toHex(messageHash(v.r)), v.mh);
      eqBrc(String(verify(v.r, v.sig, v.pub)), 'true');
      // an always-accept verifier passes every positive vector; only a negative catches it
      eq(String(verify({...v.r, seq: v.r.seq + 1}, v.sig, v.pub)), 'false');
      eq(String(verify(v.r, v.sig.slice(0, -2) + '00', v.pub)), 'false');
    }

    for (const v of SELFTEST.anchor){
      const seed = inkanSeed(v.d, v.k);
      eq(toHex(seed), v.s);
      eq(toHex(sha256(sealRgb(sha256(seed), v.k).pixels)), v.h);
    }
    for (const v of SELFTEST.render)
      eq(toHex(sha256(sealRgb(bytes(v.d), v.k).pixels)), v.h);

    // The PNG is checked STRUCTURALLY, never by digest. BRC-145 requires the canonical seal to be
    // an 8-bit indexed PNG whose chunks are exactly IHDR, PLTE, IDAT, IEND with no ancillary
    // chunks -- and states in the same breath that the cross-language invariant is the decoded RGB,
    // "not the compressed bytes (deflate output is per-implementation)". Asserting a png_sha256
    // would therefore fail honest ports for conforming output.
    {
      const png = sealPng(bytes(SELFTEST.render[0].d), SELFTEST.render[0].k);
      const names = [];
      for (let o = 8; o + 8 <= png.length; ){
        const len = (png[o]<<24 | png[o+1]<<16 | png[o+2]<<8 | png[o+3]) >>> 0;
        names.push(String.fromCharCode(png[o+4], png[o+5], png[o+6], png[o+7]));
        o += 12 + len;
      }
      eq(names.join(','), 'IHDR,PLTE,IDAT,IEND');
      eq(String.fromCharCode(...png.slice(1,4)) + png[0], 'PNG' + 137);
      // The page's own PNG decoder (SPEC §6.1): it reads the canonical seal back to its pixels, and
      // refuses a copy with a wrong CRC and a copy carrying a chunk outside the allow-list.
      const back = decodePng(png);
      eq(toHex(sha256(back.pixels)), SELFTEST.render[0].h);
      const refused = u => { try { decodePng(u); return 'accepted'; } catch (e) { return e instanceof NotVerifiable ? 'refused' : 'error'; } };
      const badCrc = Uint8Array.from(png); badCrc[29] ^= 1;          // the IHDR CRC
      eq(refused(badCrc), 'refused');
      const cicp = Uint8Array.from([0, 0, 0, 4, 0x63, 0x49, 0x43, 0x50, 1, 13, 0, 1, 0, 0, 0, 0]);
      const crcIn = cicp.subarray(4, 12); const cv = pngCrc(crcIn, 0, 8);
      cicp.set([cv >>> 24, (cv >>> 16) & 255, (cv >>> 8) & 255, cv & 255], 12);
      const withCicp = new Uint8Array(png.length + cicp.length);
      withCicp.set(png.subarray(0, 33)); withCicp.set(cicp, 33); withCicp.set(png.subarray(33), 33 + cicp.length);
      eq(refused(withCicp), 'refused');
    }
    for (const v of SELFTEST.fp)
      eq(fingerprintHex(new TextEncoder().encode(v.p), v.a, v.v), v.h);

    // Text and this browser's Unicode database (SPEC §1 E14). The accept vectors use characters every
    // database knows, so they bind here like any other vector. The either/or vectors, the rejections
    // and the probes test that the character check and the normaliser use the same data: a vector is
    // rejected exactly when the check does not know one of its code points, and otherwise gives the
    // pinned result; a probe the check knows normalises to its pinned form.
    const uniResult = v => v.adopter
      ? { fingerprint_hex: fingerprintHex(new TextEncoder().encode(v.payload_utf8), cps(v.adopter), v.fingerprint_version) }
      : { code: 'ik1' + toHex(sha256(inkanSeed(cps(v.data), cps(v.kind)))), resolve: resolveKind(cps(v.kind)) };
    const pinned = v => { const r = v.result_if_accepted, o = {};
      for (const k of ['code', 'resolve', 'fingerprint_hex']) if (k in r) o[k] = r[k]; return o; };
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    for (const v of SELFTEST.unicode.accept) eq(same(uniResult(v), pinned(v)), true);
    let uniTotal = 0, uniPass = 0;
    const disagree = what => { if (!textProblem) textProblem = what; };
    for (const v of [...SELFTEST.unicode.either_or, ...SELFTEST.unicode.reject_unless_assigned]){
      uniTotal++;
      const knows = knowsAll(cps(v.data) + cps(v.kind) + cps(v.adopter));
      let got = null;
      try { got = uniResult(v); } catch (e) { got = null; }
      if (knows ? (got !== null && (!v.result_if_accepted || same(got, pinned(v)))) : got === null) uniPass++;
      else disagree('the vector ' + v.name + ' gave neither its pinned result nor a refusal');
    }
    for (const [ver, sHex, eHex] of SELFTEST.probes){
      uniTotal++;
      const probe = cps(sHex.split(' '));
      if (!knowsAll(probe) || probe.normalize('NFC') === cps(eHex.split(' '))) uniPass++;
      else disagree('a Unicode ' + ver + ' character is known to the character check but not to the normaliser');
    }

    // Tooltip generated FROM the vectors that just ran, never hand-maintained, so it cannot drift
    // from what the page actually executed.
    // Kept short enough to read at a glance without scrolling. The 15 published vectors are listed
    // individually because each proves a different property; the implementation's own corpus is
    // summarised, since listing eight near-identical render lines adds height and no information.
    const q = s => { s = String(s); return JSON.stringify(s.length > 16 ? s.slice(0, 15) + '\u2026' : s); };
    const kinds = a => a.map(v => v.k === '' ? "''" : v.k).join(' ');
    const lines = [pass + ' of ' + total + ' checks, recomputed on every load.', '',
                   'TEXT \u2014 this browser\'s character database is ' + $('univer').textContent + '. ' +
                   uniPass + ' of ' + uniTotal + ' Unicode checks agree' + (textProblem
                     ? ': ' + textProblem + ', so non-ASCII text is refused here.' : ' (character check and normaliser).'), '',
                   'PUBLISHED IN BRC-145 (apps/0145.md) \u2014 ' + brcTotal + ':'];
    for (const v of SELFTEST.brc.seed) lines.push('  seed ' + q(v.d) + ' \u2014 ' + v.w);
    for (const v of SELFTEST.brc.code) lines.push('  code ' + q(v.d) + ' ' + q(v.k) + ' \u2014 ' + v.w);
    for (const v of SELFTEST.brc.kind) lines.push('  kind ' + q(v.k) + ' \u2014 ' + v.w);
    for (const v of SELFTEST.brc.fp)   lines.push('  fp ' + q(v.p) + ' @' + v.a + ' \u2014 ' + v.w);
    for (const v of SELFTEST.brc.canary) lines.push('  canary ' + v.r.domain + ' seq' + v.r.seq + ' \u2014 ' + v.w);
    lines.push('', 'OWN CORPUS \u2014 ' + (total - brcTotal) + ':',
      '  end-to-end \u00d7' + SELFTEST.anchor.length + ' \u2014 data \u2192 anchor bytes \u2192 pixels (' +
        kinds(SELFTEST.anchor) + ')',
      '  render \u00d7' + SELFTEST.render.length + ' \u2014 pinned digest \u2192 pinned pixels, every cell profile',
      '  fingerprint \u00d7' + SELFTEST.fp.length + ' \u2014 adopter-namespaced digests',
      '  png \u00d72 \u2014 chunks exactly IHDR,PLTE,IDAT,IEND',
      '  png decoder \u00d73 \u2014 reads the seal back; refuses a bad CRC and a cICP chunk',
      '  unicode \u00d7' + SELFTEST.unicode.accept.length + ' \u2014 text and adopter names every database knows (SPEC \u00a71)',
      '  canary negatives \u00d72 \u2014 tampered record and corrupted signature must be rejected',
      '', 'PNG bytes are never compared: BRC-145 makes decoded RGB the',
      'invariant, deflate output being per-implementation.',
      'Verification only: this page holds no key and can sign nothing.');
    const tip = $('selftip'), pill = $('selftest'), wrap = pill.parentNode;
    tip.textContent = lines.join('\n');
    const show = v => { tip.hidden = !v; };
    wrap.addEventListener('mouseenter', () => show(true));
    wrap.addEventListener('mouseleave', () => show(false));
    pill.addEventListener('focus', () => show(true));
    pill.addEventListener('blur', () => show(false));
    // tap toggles, so touch devices get it too -- a native title never appears on touch at all
    pill.addEventListener('click', e => { e.preventDefault(); show(tip.hidden); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') show(false); });

    // An empty corpus is no evidence, not perfect evidence.
    const ok = total > 0 && brcTotal > 0 && pass === total;
    $('selftest').textContent = ok
      ? ('self-test ✓ ' + pass + '/' + total + ' vectors · ' + brcPass + ' published in BRC-145' +
         (textProblem ? ' · non-ASCII text refused in this browser' : ''))
      : ('self-test FAILED ' + pass + '/' + total + ' vectors — do not trust this page');
    $('selftest').style.color = ok ? 'var(--good)' : 'var(--bad)';
  } catch(e){
    $('selftest').textContent = 'self-test ✗ engine error — do not trust this page';
    $('selftest').style.color = 'var(--bad)';
  }

  function drawRGB(canvas, img){
    const ctx = canvas.getContext('2d');
    const id = ctx.createImageData(img.width, img.height);
    for (let i=0;i<img.width*img.height;i++){
      id.data[i*4]=img.pixels[i*3]; id.data[i*4+1]=img.pixels[i*3+1];
      id.data[i*4+2]=img.pixels[i*3+2]; id.data[i*4+3]=255;
    }
    ctx.putImageData(id,0,0);
  }


  // --- the embedded tag (iTXt) of a presented PNG: an untrusted hint, cross-checked, never believed ---
  function readTag(bytes){
    if(bytes.length<8) return {};
    const dv=new DataView(bytes.buffer, bytes.byteOffset);
    let pos=8, out={}; const dec=new TextDecoder();
    while(pos+8<=bytes.length){
      const len=dv.getUint32(pos); const name=dec.decode(bytes.subarray(pos+4,pos+8));
      const body=bytes.subarray(pos+8,pos+8+len); pos+=12+len;
      if(name==='iTXt'){ const nul=body.indexOf(0); const kw=dec.decode(body.subarray(0,nul));
        const tx=dec.decode(body.subarray(nul+5));
        if(kw==='inkan-code')out.code=tx; else if(kw==='inkan-kind')out.kind=tx; }
      else if(name==='IEND') break;
    }
    return out;
  }

  let lastReport = null;
  const b64 = bytes => { let s=''; const C=0x8000;
    for (let i=0;i<bytes.length;i+=C) s += String.fromCharCode.apply(null, bytes.subarray(i,i+C));
    return btoa(s); };

  // ---- the data to seal: text as typed, a file's exact bytes, or bytes written in hex ----
  // What a person types or pastes is text and is normalised (SPEC §1 E19); a file and a hex string are
  // bytes and are used exactly. A browser text box reads every line break as LF, so text with CRLF
  // line breaks is sealed as a file.
  const HINT = 'Type text here to watch your Inkan generate live';
  const mode = () => $('modeHex').checked ? 'hex' : ($('modeFile').checked ? 'file' : 'text');
  let dataFile = null;                       // {name, bytes} of the chosen data file
  const NOTES = {
    text: () => 'Text, as typed or pasted. It is normalised (NFC) before it is hashed, so text typed two ' +
      'ways gives one Inkan. Line breaks are read as LF: a Windows CRLF becomes LF, as in every browser ' +
      'text box; to seal text with CRLF line breaks exactly, use "text file". Text holding a character ' +
      'this browser’s ' + $('univer').textContent + ' database does not know is refused (SPEC §1).' +
      (textProblem ? ' In this browser only ASCII text can be sealed: ' + textProblem + '.' : ''),
    file: () => 'The file’s exact bytes, line breaks included and nothing normalised, as the command ' +
      'line reads @file. The file stays on this device.',
    hex: () => 'Bytes, written as hexadecimal digits (0–9, a–f); spaces and line breaks between ' +
      'them are ignored. Nothing is normalised.',
  };
  function readHex(t){
    const h = t.replace(/[ \t\r\n]+/g, '');
    if (/[^0-9a-fA-F]/.test(h)) throw new Error('the hex holds a character that is not a hex digit (0–9, a–f)');
    if (h.length % 2) throw new Error('the hex has an odd number of digits');
    return Uint8Array.from(h.match(/../g) || [], x => parseInt(x, 16));
  }
  const ASCII_ONLY = /^[\x00-\x7F]*$/;
  // {value, report} for the current input, or {error} (and {idle} when there is simply nothing yet).
  function currentData(){
    const m = mode();
    if (m === 'hex'){
      try { const b = readHex($('datahex').value); return { value: b, report: { data_mode: 'hex', data_hex: toHex(b) } }; }
      catch (e){ return { error: e.message }; }
    }
    if (m === 'file'){
      if (!dataFile) return { error: 'choose a file to seal', idle: true };
      return { value: dataFile.bytes, report: { data_mode: 'file', data_file: dataFile.name,
        data_bytes: dataFile.bytes.length, data_sha256: toHex(sha256(dataFile.bytes)) } };
    }
    const t = $('data').value;
    if (textProblem && !ASCII_ONLY.test(t)) return { error: 'this browser cannot normalise non-ASCII text reliably (' + textProblem + ')' };
    return { value: t, report: { data_mode: 'text', data: t } };
  }

  // The live seal, above the data box, and its ik1 code beneath it.
  function showLive(img, code){
    drawRGB($('cvExpected'), img);
    $('livecode').className = 'livecode'; $('livecode').textContent = code;
  }
  function refuseInput(message, idle){
    const lc = $('livecode');
    lc.className = 'livecode ' + (idle ? 'idle' : 'bad');
    lc.textContent = idle ? 'Choose a file to seal.' : 'Cannot seal this input: ' + message;
    $('cvExpected').getContext('2d').clearRect(0, 0, CANVAS, CANVAS);
    $('imExpected').style.display = 'none';
    $('cvExpected').style.display = 'block';
    $('sealLink').removeAttribute('href');
    // The engine refuses input the standard does not allow: text with a code point this browser's
    // Unicode database does not assign (E14), or text that is not well-formed (E4). Say so, and show
    // no seal and no code, rather than leave the last one on screen as if it were this input's.
    const res = $('result');
    res.className = 'result show ' + (idle ? '' : 'bad');
    $('verdict').className = 'verdict ' + (idle ? '' : 'bad');
    $('verdict').textContent = idle ? '• Choose a file to seal.' : '✗ Cannot seal this input: ' + message;
    fill($('kv'));
    $('figGot').style.display = 'none'; $('figCmp').style.display = 'none';
    for (const id of ['dl', 'dlseal']) $(id).setAttribute('aria-disabled', 'true');
  }

  // Each run is numbered. A run that has to wait for a presented file to be read is superseded by
  // any run started meanwhile, and then shows nothing: its verdict and its seal are for the data and
  // kind it began with, and the box may hold something else by then.
  let runs = 0;
  async function run(compare){
    const me = ++runs;
    const kind = sel.value;
    const d = currentData();
    let digest;
    try {
      if (d.error) throw new Error(d.error);
      if (textProblem && !ASCII_ONLY.test(kind)) throw new Error('this browser cannot normalise a non-ASCII kind reliably (' + textProblem + ')');
      digest = sha256(inkanSeed(d.value, kind));
    } catch (e) { refuseInput(e.message, d.idle); return; }
    const code = 'ik1' + toHex(digest);            // self-identifying code
    const shortCode = 'ik1' + toHex(digest).slice(0, 16);
    const expected = sealRgb(digest, kind);
    showLive(expected, code);
    drawRGB($('cvAv0'), expected);          // keep the avalanche panel showing the current seal
    $('avresult').style.display = 'block';
    $('avseals').style.display = '';
    const rgbHex = toHex(sha256(expected.pixels));

    const res = $('result'), verdict = $('verdict'), kv = $('kv'), figGot = $('figGot'), figCmp = $('figCmp');
    let ok = null, summary, presentedHex = null, presentedSize = null;
    figGot.style.display = 'none'; figCmp.style.display = 'none';

    const file = compare ? $('file').files[0] : null;
    let embedded = null;
    if (file){
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      if (me !== runs) return;               // superseded while the file was read
      const p = presentedNative(fileBytes);
      if (p.tooLarge){ ok=null; summary='Genuine seal recomputed above. The presented file could not be checked: '+p.tooLarge+'.'; }
      else if (p.rejected){
        ok=false;
        summary='REJECTED — '+p.rejected+'.'+(p.size ? ' A screenshot or resized copy cannot be byte-compared (that strictness is what defeats look-alikes); compare it by eye to the genuine seal above, or present the original seal PNG (224×224, or an exact integer multiple).' : '');
      } else {
        // Only a file the profile accepts is read for its embedded tag, which is a hint and never trusted.
        embedded = readTag(fileBytes);
        drawRGB($('cvCmp'), expected); figCmp.style.display='';
        drawRGB($('cvGot'), p); figGot.style.display='';
        presentedHex = toHex(sha256(p.pixels)); presentedSize = p.size;
        ok = presentedHex === rgbHex;
        summary = ok ? 'GENUINE — presented seal is the exact render for this (data, kind)'
                     : 'MISMATCH — presented seal is NOT the genuine render (possible lookalike)';
      }
    } else {
      summary = 'Recomputed the canonical seal shown above. Choose a seal image and press Compare to check one.';
    }

    verdict.className = 'verdict ' + (ok===false?'bad':'good');
    verdict.textContent = (ok===false?'✗ ':(ok===true?'✓ ':'• ')) + summary;
    res.className = 'result show ' + (ok===false?'bad':(ok===true?'good':''));
    fill(kv,
      bold('data:'), ' ' + ({ text: 'text, ' + d.value.length + ' UTF-16 units, normalised (NFC)',
        hex: 'raw bytes from hex, ' + (d.value.length || 0) + ' bytes',
        file: 'the bytes of ' + (dataFile ? dataFile.name : '') + ', ' + (d.value.length || 0) + ' bytes' })[d.report.data_mode], BR,
      bold('kind:'), ' '+(kind||'(generic)')+'   ', bold('seal:'), ' v'+SEAL_VERSION, BR,
      bold('code:'), ' '+code, BR,
      bold('genuine RGB sha256:'), ' '+rgbHex,
      ...(presentedHex ? [BR, bold('presented RGB sha256:'), ' '+presentedHex+' ('+presentedSize+')'] : []),
      ...(embedded && embedded.code ? [BR, bold('embedded code (untrusted):'), ' '+embedded.code+' — ',
        embedded.code===code ? tone('matches', 'good') : tone('DOES NOT MATCH recomputed', 'bad')] : []));

    lastReport = Object.assign({report:'inkan-verification', verifier_version:'V__VERSION__', seal_version:SEAL_VERSION,
      generated_utc:new Date().toISOString(), kind:kind}, d.report, {
      verdict: ok===false?'FAIL':(ok===true?'PASS':'INFO'), summary:summary,
      code:code, short_code:shortCode, digest_hex:toHex(digest), genuine_rgb_sha256:rgbHex,
      presented_rgb_sha256:presentedHex, presented_size:presentedSize});
    // inkan-<kind>-<short_code>: identifiable in a downloads folder, and still keyed by the code
    // the way the sidecar seal files are named. Kind is sanitised because it may contain
    // '/' or '@' (namespaces and tier suffixes), which are not safe in a filename.
    const slug = (kind||'generic').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') || 'generic';
    const base = 'inkan-' + slug + '-' + shortCode;

    const rep = $('dl');
    rep.href = 'data:application/json;base64,' +
      b64(new TextEncoder().encode(JSON.stringify(lastReport, null, 2)));
    rep.download = base + '.json';
    rep.removeAttribute('aria-disabled');

    // The saved seal is the engine's own canonical PNG with its tag (8-bit indexed, SPEC §5), not a
    // canvas export: a canvas writes RGBA, which the verifiable-PNG profile refuses, so a seal saved
    // from here and presented back to any verifier would have read REJECTED. It is also shown as an
    // <img> of those bytes, so right-click "Save image" keeps the embedded ik1 code too.
    const url = 'data:image/png;base64,' + b64(sealPng(digest, kind, { tag: true }));
    const dls = $('dlseal');
    dls.href = url; dls.download = base + '.png';
    dls.removeAttribute('aria-disabled');
    const sl = $('sealLink'); sl.href = url; sl.download = base + '.png';
    const im = $('imExpected');
    im.src = url; im.style.display = 'block';
    $('cvExpected').style.display = 'none';
  };

  // Generation is LIVE: the seal, code and digest track what you type, so the page behaves as a
  // generator rather than a form you submit. Comparison stays explicit -- it needs a file, and
  // re-reading it on every keystroke would be wasteful and would make a MISMATCH verdict flicker
  // while a user is mid-edit.
  $('go').onclick = () => run(true);
  $('file').onchange = () => run(true);
  let liveTimer = null;
  const live = () => {
    clearTimeout(liveTimer);
    liveTimer = setTimeout(() => run(false), 120);
  };
  const syncAvalanche = () => {
    const d = currentData();
    const empty = !!d.error || !d.value.length;
    for (const id of ['avgo', 'avjump']){
      $(id).disabled = empty;
      $(id).title = empty ? 'Enter some data to seal to enable this' : '';
    }
  };
  // The hint stands beside the box, never over it: shown while the text box is empty, gone as soon as
  // anything is typed, and announced politely to a screen reader whenever it appears.
  // It is simply there on load; when it comes back after the box is emptied it fades in, unless the
  // reader asked for reduced motion.
  const syncHint = () => {
    const want = (mode() === 'text' && !$('data').value.length) ? HINT : '';
    const h = $('datahint');
    if (h.textContent === want) return;
    if (want && hintShown) h.className = 'hint again';
    h.textContent = want;
    if (want) hintShown = true;
  };
  let hintShown = false;
  const syncMode = () => {
    const m = mode();
    $('data').hidden = m !== 'text';
    $('datahex').hidden = m !== 'hex';
    $('datafile').hidden = m !== 'file';
    $('datalabel').htmlFor = m === 'hex' ? 'datahex' : (m === 'file' ? 'datafile' : 'data');
    $('datanote').textContent = NOTES[m]();
    syncHint(); syncAvalanche(); live();
  };
  for (const id of ['modeText', 'modeFile', 'modeHex']) $(id).addEventListener('change', syncMode);
  $('data').addEventListener('input', () => { syncHint(); live(); syncAvalanche(); });
  $('datahex').addEventListener('input', () => { live(); syncAvalanche(); });
  // The same for the file to seal: a file picked later is never replaced by an earlier pick that
  // took longer to read.
  let picks = 0;
  $('datafile').addEventListener('change', async () => {
    const me = ++picks;
    const f = $('datafile').files[0];
    const picked = f ? { name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) } : null;
    if (me !== picks) return;
    dataFile = picked;
    syncAvalanche(); run(false);
  });
  sel.addEventListener('input', live);
  $('datanote').textContent = NOTES[mode()]();
  syncHint();
  syncAvalanche();

  // Render once at load so the page arrives as a working generator rather than an empty form: the
  // default (empty data, kind 'address') is a legitimate input with a real seal, and showing it
  // immediately demonstrates what the tool does without asking anyone to type first.
  run(false);
  $('avverdict').className = 'verdict';
  $('avverdict').textContent = 'Showing your current seal. Run the check to draw its closest single-bit neighbour.';

  // The canary card stays EMPTY on load. Prefilling it with the specification example made a
  // general-purpose checker look like a report on one fictional publisher, and once that example
  // ages out it would greet every visitor with a red staleness warning under a heading asking
  // whether the operator is compromised. The example is one click away instead.
  $('cnexample').onclick = e => {
    e.preventDefault();
    const c = SELFTEST.brc.canary[0];
    $('cnrec').value = new TextDecoder().decode(canonicalBytes(c.r));   // exactly its canonical bytes
    $('cnpub').value = c.pub;
    $('cnsig').value = c.sig;
    $('cngo').click();
  };

  // ---- avalanche: the anti-lookalike property, measured on the user's own input ----
  function runAvalanche(){
    const res = $('avresult'), verdict = $('avverdict'), kv = $('avkv');
    res.style.display = 'block';
    const kind = sel.value;
    let cells;
    try { cells = resolveKind(kind)[0]; inkanSeed('', kind); }
    catch (e) {
      verdict.className = 'verdict bad';
      verdict.textContent = 'Cannot run the check for this kind: ' + e.message;
      $('figAv1').style.display = 'none';
      fill(kv);
      return;
    }
    // The bytes the anchor actually hashes: a file or hex as they are, text in its NFC form (SPEC §1),
    // so the left-hand seal here is always the live seal above.
    const d = currentData();
    let base;
    try {
      if (d.error && !d.idle) throw new Error(d.error);
      base = d.idle ? new Uint8Array(0) : typeof d.value === 'string'
        ? (rejectUnassigned(d.value, 'data'), encodeUtf8(d.value.normalize('NFC'), 'data')) : d.value;
    } catch (e) {
      verdict.className = 'verdict bad';
      verdict.textContent = 'Cannot run the check for this data: ' + e.message;
      $('figAv1').style.display = 'none';
      fill(kv);
      return;
    }
    verdict.className = 'verdict';
    if (!base.length){
      verdict.className = 'verdict';
      verdict.textContent = 'Nothing to flip yet — type into the sealed-data field above.';
      $('figAv1').style.display = 'none';
      fill(kv, 'An empty input has no bits, so there are no neighbours to compare. Any value ' +
               'works: an address, a name, a sentence.');
      return;
    }
    $('avseals').style.display = '';
    // Cap the work: 64 bytes is 512 recomputes, which is instant, and the minimum over a large
    // sample is what the claim rests on -- more bytes would not change the conclusion.
    const nBytes = Math.min(base.length, 64);
    const cellsOf = bytes => {
      const f = sealFields(sha256(inkanSeed(bytes, kind)), kind);
      return cellsFromWords(f.words, cells);
    };
    const c0 = cellsOf(base);
    let min = Infinity, max = 0, sum = 0, n = 0, worst = null;
    for (let b = 0; b < nBytes; b++) for (let k = 0; k < 8; k++){
      const m = Uint8Array.from(base); m[b] ^= 1 << k;
      const c1 = cellsOf(m);
      let d = 0;
      for (let j = 0; j < cells; j++) if (c0[j] !== c1[j]) d++;
      if (d < min){ min = d; worst = m; }
      if (d > max) max = d;
      sum += d; n++;
    }
    drawRGB($('cvAv0'), sealRgb(sha256(inkanSeed(base, kind)), kind));
    drawRGB($('cvAv1'), sealRgb(sha256(inkanSeed(worst, kind)), kind));
    $('figAv1').style.display = '';
    const pct = (min / cells * 100).toFixed(0);
    verdict.className = 'verdict good';
    verdict.textContent = '\u2713 the closest of ' + n + ' single-bit neighbours still moved ' +
      min + ' of ' + cells + ' cells (' + pct + '%)';
    fill(kv,
      bold('kind:'), ' ' + (kind || '(generic)') + ' \u00a0 ', bold('cells:'), ' ' + cells + ' \u00a0 ',
      bold('bits flipped:'), ' ' + n + (base.length > nBytes ? ' (first 64 bytes)' : ''), BR,
      bold('cells changed \u2014 fewest:'), ' ' + min + ' \u00a0 ', bold('mean:'), ' ' + (sum / n).toFixed(1) +
      ' \u00a0 ', bold('most:'), ' ' + max, BR,
      'The right-hand seal is the FEWEST-change case, so every other single-bit edit differs more. ' +
      'A seal is a picture of the digest, not of the data \u2014 which is why similar inputs do not ' +
      'produce similar images, and a lookalike cannot be approached by nudging.');
  }
  $('avgo').onclick = runAvalanche;
  // Jumping without running would land the reader on an empty panel and ask for a second click, so
  // this computes first and then moves; the result is already there when the scroll finishes.
  $('avjump').onclick = () => {
    runAvalanche();
    const still = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    $('avcard').scrollIntoView({ behavior: still ? 'auto' : 'smooth', block: 'start' });
  };

  // ---- canary layer: has the publisher gone quiet? ----
  $('cngo').onclick = () => {
    const res = $('cnresult'), verdict = $('cnverdict'), kv = $('cnkv');
    res.style.display = 'block';
    // The record is judged as the text it was published as (SPEC §8 E23 rule 4: its bytes must be
    // its canonical bytes). Only blank space around it, as a paste often carries, is dropped.
    const wire = $('cnrec').value.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '');
    // The key and signature go to the engine exactly as typed. It alone decides which blank space
    // around them is ignored (SPEC §8 E23), so this page and every other verifier give one verdict.
    const sig = $('cnsig').value, pub = $('cnpub').value;
    const asOfRaw = $('cnas').value.trim();
    const asOf = asOfRaw ? Date.parse(asOfRaw + 'T00:00:00Z') : Date.now();
    if (isNaN(asOf)){
      verdict.className = 'verdict bad';
      verdict.textContent = 'Could not read that date. Use YYYY-MM-DD, or leave it blank for now.';
      kv.textContent = ''; return;
    }
    const win = parseInt($('cnwin').value, 10) || 35;
    let state;
    try { state = status(wire, sig, pub, asOf, win); }
    catch (e) {
      // A future record version must read UNSUPPORTED, never INVALID: refusing to judge what you
      // cannot parse is the honest answer, and calling it invalid would imply tampering.
      verdict.className = 'verdict';
      verdict.textContent = 'UNSUPPORTED — ' + e.message;
      fill(kv, bold('This verifier implements v1.'), ' A newer record needs a newer verifier.');
      return;
    }
    // Only OK, STALE and INVALID mean a signature check ran. MALFORMED means it could not run: the
    // record, key or signature is not in the form the standard fixes, which is usually a truncated
    // paste. That is never a valid signature, and it is not evidence of forgery either, so it gets
    // its own answer. Any other value this page does not know is treated the same way.
    if (state !== 'OK' && state !== 'STALE' && state !== 'INVALID'){
      let why = '';
      try { verify(wire, sig, pub); } catch (e) { why = e.message; }
      verdict.className = 'verdict';
      verdict.textContent = '\u25cf ' + state + ' \u2014 could not check. The record, key or signature ' +
        'is not in the form the standard requires, so no signature check ran. This is not a pass.';
      fill(kv, bold('signature:'), ' not checked', ...(why ? [' \u00a0 ', bold('reason:'), ' ' + why] : []), BR,
        'Paste the record exactly as published, with all seven fields, and the complete public key and ' +
        'signature in hex.');
      return;
    }
    const rec = parseRecord(wire)[0];       // it parsed, or the verdict above would be MALFORMED
    // Report the two questions SEPARATELY. They have different lifetimes and different remedies:
    // a signature is either valid forever or never, while freshness is relative to when you ask.
    // Merging them into one verdict makes a permanently-valid signature look broken once the record
    // ages, and hides which of the two actually needs attention.
    const sigOK = state === 'OK' || state === 'STALE';
    const fresh = state === 'OK';
    const ageDays = (() => {
      const m = /^(\d{4})-(\d{2})-(\d{2})T/.exec(String(rec.date));
      if (!m) return null;
      return Math.round((asOf - Date.UTC(+m[1], +m[2] - 1, +m[3])) / 86400000);
    })();
    // The block anchor is checked against a height the READER supplies. The page holds no chain
    // state and will not fetch one; a canary you cannot check offline is a canary you cannot check
    // on the machine where it matters most.
    const hRaw = $('cnheight').value.trim();
    let blockNote = [];
    let impossible = false;
    if (hRaw){
      const known = parseInt(hRaw.replace(/[ ,_]/g, ''), 10);
      if (!Number.isFinite(known) || known < 0){
        blockNote = [BR, bold('block check:'), ' that height is not a number.'];
      } else if (typeof rec.block_height !== 'number'){
        blockNote = [BR, bold('block check:'), ' the record carries no numeric block_height.'];
      } else if (rec.block_height > known){
        impossible = true;
        blockNote = [BR, bold('block check:'), ' ', tone('the record cites block ' +
          rec.block_height + ', which is ahead of the ' + known + ' you supplied. A record cannot ' +
          'name a block that does not exist yet — either your height is behind, or this is not genuine.', 'bad')];
      } else {
        const gap = known - rec.block_height;
        const days = (gap * 10 / 60 / 24);
        blockNote = [BR, bold('block check:'), ' ' + gap.toLocaleString() + ' blocks since the cited tip, ' +
          'roughly ' + days.toFixed(1) + ' days at 10 min/block. Signed no earlier than block ' +
          rec.block_height + '.'];
        if (ageDays !== null && days > 1 && Math.abs(days - ageDays) > Math.max(7, ageDays * 0.5)){
          blockNote.push(' ', tone('That disagrees with the stated date (' +
            ageDays + ' days) — worth questioning.', 'bad'));
        }
      }
    }
    verdict.className = 'verdict ' + (impossible ? 'bad' : (fresh ? 'good' : (sigOK ? '' : 'bad')));
    verdict.textContent = (fresh ? '\u2713 OK' : (sigOK ? '\u25cf ' + state : '\u2717 INVALID')) +
      ' \u2014 ' + ({
        OK: 'signature valid, and the record is inside the window',
        STALE: 'signature valid \u2014 the record has simply aged out. Renewal stopped, or you are looking at an old copy',
        INVALID: 'the signature does not verify for this record and key'
      })[state];
    fill(kv,
      bold('signature:'), ' ', sigOK ? tone('VALID', 'good') : tone('DOES NOT VERIFY', 'bad'),
      ' \u00a0 ', bold('freshness:'), ' ' + (ageDays === null ? 'unreadable date' :
        ageDays + ' day' + (ageDays === 1 ? '' : 's') + ' old, window ' + win +
        (fresh ? '' : ' — aged out')),
      ...(asOfRaw ? [' \u00a0 ', bold('judged as of:'), ' ' + asOfRaw] : []), ...blockNote, BR,
      bold('domain:'), ' ' + (rec.domain || '(none)') + ' \u00a0 ', bold('seq:'), ' ' + rec.seq +
      ' \u00a0 ', bold('date:'), ' ' + rec.date, BR,
      bold('block:'), ' ' + rec.block_height + ' \u00a0 ', bold('canonical bytes:'), ' ' +
        canonicalBytes(rec).length, BR,
      bold('message hash:'), ' ' + toHex(messageHash(rec)),
      ...(rec.statement ? [BR, bold('statement:'), ' ' + rec.statement] : []));
  };

  // ---- fingerprint layer: software / build provenance (BRC-145 second layer) ----
  $('fpgo').onclick = async ()=>{
    const res = $('fpresult'), verdict = $('fpverdict'), kv = $('fpkv');
    const adopter = $('fpadopter').value.trim();
    const file = $('fpfile').files[0];
    res.style.display = 'block';
    if (!adopter){ verdict.className='verdict bad'; verdict.textContent='Adopter is required — it is inside the digest, so an empty one is a different namespace.'; kv.textContent=''; return; }
    if (!file){ verdict.className='verdict bad'; verdict.textContent='Choose a file to fingerprint.'; kv.textContent=''; return; }
    // A positive integer, typed as decimal digits (SPEC §7 E22). parseInt read "1.5" as 1 and "2x" as
    // 2, so a fraction or a typo was silently checked as some other version.
    const vtxt = $('fpver').value.trim();
    const version = /^[0-9]+$/.test(vtxt) ? BigInt(vtxt) : null;
    if (version === null || version < 1n){ verdict.className='verdict bad'; verdict.textContent='Version must be a positive integer (1, 2, 3, …).'; kv.textContent=''; return; }
    let hex;
    try { hex = fingerprintHex(new Uint8Array(await file.arrayBuffer()), adopter, version); }
    catch (e){ verdict.className='verdict bad'; verdict.textContent='Could not compute: '+e.message; kv.textContent=''; return; }
    const claim = $('fpclaim').value.trim().toLowerCase().replace(/^0x/,'');
    if (claim){
      const match = claim === hex;
      verdict.className = 'verdict ' + (match ? 'good' : 'bad');
      verdict.textContent = match
        ? 'MATCH — these bytes are the released build for this adopter.'
        : 'NO MATCH — these bytes are NOT what that fingerprint attests. Do not trust this file.';
    } else {
      verdict.className = 'verdict';
      verdict.textContent = 'Computed. No claimed fingerprint given, so nothing was compared.';
    }
    fill(kv,
      bold('adopter:'), ' '+adopter+' \u00a0 ', bold('version:'), ' '+version+' \u00a0 ',
      bold('bytes:'), ' '+file.size, BR,
      bold('fingerprint:'), ' '+hex,
      ...(claim ? [BR, bold('claimed:'), ' '+claim] : []));
  };
})();
</script>
</body>
</html>
'''

out = pathlib.Path(__file__).resolve().parents[2] / "web" / "inkan-verify.html"
out.parent.mkdir(exist_ok=True)
full = (HTML.replace("__ENGINE__", engine + "\n" + SELFTEST_JS)
            .replace("__VERSION__", VERIFIER_VERSION)
            .replace("__FONTS__", FONT_FACES)
            .replace("__ICON__", ICON_SVG))
out.write_text(full)
print(f"wrote {out}  ({out.stat().st_size/1024:.0f} KB)")

# Artifact-compatible variant: same bytes of engine + UI, but stripped of the
# <!doctype>/<html>/<head>/<body> wrapper (the Artifact host supplies those). Generated from
# the same source, so it cannot drift from the standalone/inscription file.
import re as _re
inner = full
inner = inner.split("<body>", 1)[1].rsplit("</body>", 1)[0]
style = _re.search(r"<style>.*?</style>", full, _re.S).group(0)
title = "<title>Inkan Generator &amp; Verifier</title>"
art = pathlib.Path(__file__).resolve().parents[2] / "web" / "inkan-verify.artifact.html"
# The body-only variant loses the <!doctype> wrapper, and the licence comment with it. An inscribed
# or re-hosted copy must still state what it is licensed under, so re-emit the notice here.
_LIC = (
    "<!--\n"
    "  Inkan Generator & Verifier \u2014 the reference verification surface for BRC-145.\n"
    "  Source, licence documents and this page's published values: https://github.com/RexStarBSV/Inkan\n\n"
    "  SPDX-License-Identifier: Apache-2.0\n"
    "  SPDX-FileCopyrightText: 2026 RexStarBSV\n\n"
    "  Licensed under the Apache License, Version 2.0 (https://www.apache.org/licenses/LICENSE-2.0):\n"
    "  verify Inkan codes and seals, and generate your own, in any product, commercial or not,\n"
    "  forever, patent grant included. Copy it, host it, inscribe it.\n\n"
    "  NOT covered by this grant, each marked in place as an SPDX snippet: the embedded font, Inkan\n"
    "  Sans, a Modified Version of IBM Plex Sans (Copyright 2017 IBM Corp., SIL OFL 1.1, reproduced in\n"
    "  full with the font data), and the Inkan mark, the seal-ring logo ((c) 2026 RexStarBSV, all\n"
    "  rights reserved; see LICENSE-MARK in the repository above). You may pass this page on\n"
    "  unmodified with the mark in it; a changed page must remove the mark or replace it with your\n"
    "  own. The wider Inkan repository is multi-licence and most of it is NOT Apache-2.0; its NOTICE\n"
    "  and LICENSING.md give the full map.\n"
    "-->\n")
art.write_text(_LIC + title + "\n" + style + "\n" + inner)
print(f"wrote {art}  ({art.stat().st_size/1024:.0f} KB, artifact/body-only)")
bad = [ln for ln in engine.splitlines() if ln.strip().startswith(("import ", "export "))]
print("leftover module statements:", bad if bad else "none")

# ---------------------------------------------------------------- build gate
# The page runs its own known-answer self-test, but only in a BROWSER, and only after it has
# already been written, sealed and (eventually) inscribed. A build that cannot execute its own
# vectors must not produce an artifact: an inscribed page is not correctable. This runs the very
# same checks the page runs, against the very same generated file, and refuses to leave a failing
# artifact on disk.
def _gate(html_path: pathlib.Path) -> None:
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        if os.environ.get("INKAN_SKIP_GATE") == "1":
            print("build gate: SKIPPED (no node, INKAN_SKIP_GATE=1)")
            return
        raise SystemExit(
            "FATAL: node not found, so the generated page cannot be verified before it ships.\n"
            "  The engine IS the product; emitting it unverified is how a green badge over a\n"
            "  broken renderer reaches an inscription. Install node, or set INKAN_SKIP_GATE=1\n"
            "  to build deliberately unverified.")

    checker = pathlib.Path(__file__).resolve().parent / "check_web_verifier.mjs"
    res = subprocess.run([node, str(checker), str(html_path)],
                         capture_output=True, text=True, timeout=300)
    sys.stdout.write(res.stdout)
    if res.returncode != 0:
        sys.stderr.write(res.stderr)
        # The message below PROMISES the artifacts are gone. Swallowing a failed unlink would print
        # that promise over a tree that still holds an unverified verifier — the exact artefact this
        # gate exists to stop shipping, left behind with a line of reassurance on top of it. A missing
        # file is fine (it was never written, or is already cleaned); a file we could not remove is
        # not, and the operator has to be told which one and why.
        stranded = []
        for p in (html_path, html_path.parent / "inkan-verify.artifact.html"):
            try:
                # missing_ok: absent is fine — never written, or already cleaned. Saying that in the
                # call rather than in a swallowing handler keeps the only `except` here for the case
                # that genuinely matters, and leaves no bare `pass` for a reader to have to judge.
                p.unlink(missing_ok=True)
            except OSError as exc:
                stranded.append(f"{p}: {exc}")
        if stranded:
            raise SystemExit(
                "FATAL: build gate failed AND the unverified artifact(s) could NOT be removed — "
                "delete these by hand before publishing anything:\n  " + "\n  ".join(stranded))
        raise SystemExit("FATAL: build gate failed — artifacts removed rather than shipped unverified.")


import os   # noqa: E402
import sys  # noqa: E402
_gate(out)
