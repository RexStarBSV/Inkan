#!/usr/bin/env python3
"""Generate the authoritative, self-contained, illustrated Inkan Standard (HTML).

Every pictured seal is rendered by the REFERENCE ENGINE (inkan_standard.seal) and embedded as a data
URI, so the catalog is canonical, offline, and verifiable — the document is standalone and
inscription-ready. Regenerate after any engine change; never hand-edit the HTML.

Emits standard/inkan-standard.html (full) and standard/inkan-standard.artifact.html (body-only).
"""
import base64
import pathlib
import struct
import sys
import zlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "python"))
from inkan_standard import seal, seal_tables as T
from inkan_standard.seed import CODE_PREFIX, inkan_digest, inkan_short_code

VERSION = "1.0"
DATE = "2026-07-28"


def _revision() -> str:
    """The revision SPEC.md names in its first paragraph (SPEC §0, P2), shown on the page so a reader
    of either form can tell which text it is."""
    import re
    head = (pathlib.Path(__file__).resolve().parents[1] / "SPEC.md").read_text()[:600]
    m = re.search(r"revision (\d+\.\d+\.\d+)", head)
    if not m:
        raise SystemExit("FATAL: SPEC.md does not name its revision in its first paragraph")
    return m.group(1)


REVISION = _revision()


def _png(rgb):
    pal = sorted(set(rgb))
    ix = {c: i for i, c in enumerate(pal)}
    raw = bytearray()
    for y in range(T.CANVAS):
        raw.append(0)
        raw.extend(ix[rgb[y * T.CANVAS + x]] for x in range(T.CANVAS))

    def ch(name, d):
        c = name + d
        return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n"
            + ch(b"IHDR", struct.pack(">IIBBBBB", T.CANVAS, T.CANVAS, 8, 3, 0, 0, 0))
            + ch(b"PLTE", b"".join(bytes(c) for c in pal))
            + ch(b"IDAT", zlib.compress(bytes(raw), 9))
            + ch(b"IEND", b""))


def uri(png):
    return "data:image/png;base64," + base64.b64encode(png).decode()


def seal_uri(data, kind):
    return uri(seal.seal_png(inkan_digest(data, kind), kind))


def fig(u, cap):
    return f'<figure><img src="{u}" alt="{cap}" loading="lazy"><figcaption>{cap}</figcaption></figure>'


TIER_OF = {72: "T1", 48: "T2", 24: "T3"}

# --- kind gallery (all reserved kinds, real seals) -------------------------------------------
KIND_ORDER = ["address", "signer", "vault", "contract", "identity", "account", "",
              "code", "report", "collection", "backup",
              "custom/24", "custom/48", "custom/72"]
kind_gallery = ""
for k in KIND_ORDER:
    cells, ksym, _ = seal.resolve_kind(k)
    kind_gallery += fig(seal_uri(f"demo/{k}", k), f"{k or '(generic)'} · {TIER_OF[cells]} · {cells}c k{ksym}")

# --- open-kind examples ----------------------------------------------------------------------
OPEN = ["acme:vault@t1", "acme:invoice@t3", "receipt", "myapp:thing", "café@t2"]
open_gallery = ""
for k in OPEN:
    cells, ksym, _ = seal.resolve_kind(k)
    open_gallery += fig(seal_uri(f"demo/{k}", k), f"{k} · {cells}c k{ksym}")

# --- tier ladder -----------------------------------------------------------------------------
tier_figs = "".join(fig(seal_uri("same-account", kind), f"{t} · {kind}")
                    for t, kind in [("T1", "address"), ("T2", "identity"), ("T3", "code")])

# --- symmetry axis: SAME 24-cell interior, rendered at k = 1..7 -------------------------------
base = inkan_digest("symmetry-demo", "custom/24")
words, pix, core = seal.seal_fields(base, "custom/24")
sym_axis = ""
for target_k in range(1, 8):
    kind = next((c for c in list(T.KINDS) + [f"ax-{i}@t3" for i in range(2000)]
                 if seal.resolve_kind(c)[:2] == (24, target_k)), None)
    rgb = seal.seal_rgb_from_fields(words, pix, core, kind)
    sym_axis += fig(uri(_png(rgb)), f"k = {target_k}")

# --- palette ---------------------------------------------------------------------------------
swatches = "".join(
    '<div class="cls">' + "".join(f'<i style="background:rgb{tuple(c)}"></i>' for c in cl) + "</div>"
    for cl in T.PALETTE)

ex_code = CODE_PREFIX + inkan_digest("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address").hex()
ex_short = inkan_short_code("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address")

TITLE = "The Inkan Standard"
STYLE = """<style>
:root{--bg:#f5f7f6;--panel:#fff;--line:#dde3e0;--ink:#0f1e18;--dim:#586b62;
 --accent:#003022;--accent2:#0d6b4f;--warn:#8a5a12;--rule:#e3e8e5;--code:#0b3b2a}
@media(prefers-color-scheme:dark){:root{--bg:#080b0a;--panel:#0f1512;--line:#202a25;
 --ink:#e6ede9;--dim:#8ba096;--accent:#b9c8c4;--accent2:#4fbf95;--warn:#d3a04a;--rule:#1c2621;--code:#9fe4c7}}
:root[data-theme=dark]{--bg:#080b0a;--panel:#0f1512;--line:#202a25;--ink:#e6ede9;--dim:#8ba096;
 --accent:#b9c8c4;--accent2:#4fbf95;--warn:#d3a04a;--rule:#1c2621;--code:#9fe4c7}
:root[data-theme=light]{--bg:#f5f7f6;--panel:#fff;--line:#dde3e0;--ink:#0f1e18;--dim:#586b62;
 --accent:#003022;--accent2:#0d6b4f;--warn:#8a5a12;--rule:#e3e8e5;--code:#0b3b2a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);padding:0 20px 100px;
 font:16px/1.65 ui-serif,Georgia,"Times New Roman",serif}
.wrap{max-width:820px;margin:0 auto}
header.hero{padding:72px 0 40px;border-bottom:2px solid var(--accent)}
.kicker{font:600 12px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.22em;
 text-transform:uppercase;color:var(--accent)}
h1{font-size:clamp(34px,6vw,54px);line-height:1.04;margin:16px 0 0;letter-spacing:-.02em;font-weight:600}
.sub{color:var(--dim);font-size:19px;margin-top:14px;max-width:60ch}
.meta{margin-top:24px;font:12px ui-monospace,Menlo,monospace;color:var(--dim);letter-spacing:.03em}
h2{font-size:13px;letter-spacing:.15em;text-transform:uppercase;color:var(--accent2);
 margin:64px 0 4px;font:600 13px/1 ui-monospace,Menlo,monospace}
h2 .n{color:var(--dim)}
h3{font-size:21px;margin:34px 0 8px;font-weight:600;letter-spacing:-.01em}
p{margin:14px 0}
.lead{font-size:18px}
strong{font-weight:640}
em{color:var(--dim);font-style:italic}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em;color:var(--code)}
code{background:color-mix(in srgb,var(--accent) 8%,transparent);padding:1px 5px;border-radius:3px}
table{width:100%;border-collapse:collapse;font:14px/1.5 ui-sans-serif,system-ui,sans-serif;margin:18px 0}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--rule);vertical-align:top}
th{font:600 11px/1.3 ui-monospace,Menlo,monospace;letter-spacing:.06em;text-transform:uppercase;color:var(--dim)}
td.num{font-family:ui-monospace,Menlo,monospace;font-variant-numeric:tabular-nums}
.scroll{overflow-x:auto;margin:18px 0}
.gal{display:grid;grid-template-columns:repeat(auto-fill,minmax(116px,1fr));gap:18px;margin:22px 0}
.row7{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin:20px 0}
.row3{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;max-width:520px;margin:22px 0}
@media(max-width:640px){.row7{grid-template-columns:repeat(4,1fr)}}
figure{margin:0}
figure img{width:100%;aspect-ratio:1;image-rendering:pixelated;display:block;border-radius:8px;
 border:1px solid var(--line);background:#fff}
figcaption{font:11px/1.35 ui-monospace,Menlo,monospace;color:var(--dim);margin-top:7px;text-align:center;word-break:break-word}
.pal{display:grid;grid-template-columns:repeat(auto-fill,minmax(96px,1fr));gap:6px;margin:20px 0}
.cls{display:flex;height:20px;border-radius:3px;overflow:hidden;border:1px solid var(--line)}
.cls i{flex:1}
.callout{border-left:3px solid var(--accent);padding:2px 0 2px 18px;margin:22px 0;color:var(--dim)}
.callout strong{color:var(--ink)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:20px 0}
@media(max-width:640px){.grid2{grid-template-columns:1fr}}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.stat .v{font:700 24px/1 ui-monospace,Menlo,monospace;color:var(--accent2);margin-bottom:6px;font-variant-numeric:tabular-nums}
.stat .l{font-size:13px;color:var(--dim)}
hr{border:0;border-top:1px solid var(--rule);margin:56px 0}
footer{margin-top:70px;padding-top:22px;border-top:1px solid var(--rule);color:var(--dim);
 font:12px ui-monospace,Menlo,monospace;text-align:center}
.tag{display:inline-block;font:600 10px ui-monospace,Menlo,monospace;letter-spacing:.06em;
 padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--dim);margin-left:8px}
</style>"""

def _esc(s: str) -> str:
    s = (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    # markdown inline code, bold and italics, the only three used in the errata section
    import re as _re
    s = _re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = _re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    s = _re.sub(r"(?<![*\w])\*([^*\s][^*]*?)\*(?![*\w])", r"<i>\1</i>", s)
    return s


def _unwrap(cell: str) -> str:
    """Drop the bold markers around a WHOLE cell (`**E10**`), and only then. Stripping `*` from
    both ends of every cell removed the opening `**` of a cell that merely BEGINS in bold and left
    its closing `**` on the page as literal text."""
    cell = cell.strip()
    if cell.startswith("**") and cell.endswith("**") and "**" not in cell[2:-2]:
        return cell[2:-2].strip()
    return cell



def _permanence_html() -> str:
    """SPEC §0 (Permanence), parsed from SPEC.md like the errata so the two forms cannot differ. The
    page is the form most likely to be republished or inscribed, so it carries the rules that say
    what may never change."""
    spec = (pathlib.Path(__file__).resolve().parents[1] / "SPEC.md").read_text()
    if "\n## 0. Permanence" not in spec:
        raise SystemExit("FATAL: SPEC.md has no §0 Permanence section")
    body = spec.split("\n## 0. Permanence", 1)[1].split("\n---", 1)[0].split("\n## ", 1)[0]
    paras = [par.replace("\n", " ").strip() for par in body.split("\n\n") if par.strip()]
    return ('<h2 id="permanence"><span class="n">§0</span> &nbsp;Permanence</h2>\n'
            + "\n".join("<p>%s</p>" % _esc(par) for par in paras))


def _errata_html() -> str:
    """Render the errata table by PARSING SPEC.md, never by restating it.

    The two published forms of this standard - SPEC.md and this page - were independent documents
    with no gate between them. On 2026-08-04 SPEC.md carried eleven errata and this page carried
    none, including E10, which is security-relevant. A reader of the inscribable, self-contained
    form got the frozen text with no corrections at all, and an implementer working from it would
    have inherited a hole the reference had already fixed.

    Parsing means the page cannot fall behind again: add an erratum to SPEC.md and it appears here.
    """
    spec = (pathlib.Path(__file__).resolve().parents[1] / "SPEC.md").read_text()
    if "## Errata" not in spec:
        raise SystemExit("FATAL: SPEC.md has no Errata section - refusing to publish a standard "
                         "page that silently claims there are no corrections")
    body = spec.split("## Errata", 1)[1]
    rows = []
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| # "):
            continue
        cells = [_unwrap(c) for c in line.strip("|").split("|")]
        if len(cells) >= 4 and cells[0]:
            rows.append(cells[:4])
    if not rows:
        raise SystemExit("FATAL: SPEC.md Errata table parsed to zero rows - the format changed")
    intro = body.split("| #", 1)[0].strip()
    intro_html = "".join("<p>%s</p>" % _esc(par.replace("\n", " "))
                         for par in intro.split("\n\n") if par.strip())
    out = ['<h2 id="errata">Errata (v%s)</h2>' % VERSION, intro_html,
           '<table class="errata"><thead><tr><th>#</th><th>Date</th><th>Section</th>'
           '<th>Nature</th></tr></thead><tbody>']
    for num, date, sec, nature in rows:
        out.append("<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td></tr>"
                   % (_esc(num), _esc(date), _esc(sec), _esc(nature)))
    out.append("</tbody></table>")
    return "\n".join(out)


BODY = f"""<header class="hero">
  <div class="kicker">Inkan · trust-signal seal standard <span class="tag">v{VERSION}</span></div>
  <h1>The Inkan Standard</h1>
  <p class="sub">A deterministic visual seal for data you must trust at a glance — an address, a
  signing key, a document. Its one job: <em>a human notices when it changes.</em> This document is
  self-contained and every seal below is rendered by the reference engine.</p>
  <div class="meta">version {VERSION} · frozen {DATE} · revision {REVISION} · extended-Golay coded · SHA-256 anchor ·
  Python/JS/Kotlin byte-identical</div>
</header>

<h2><span class="n">§1</span> &nbsp;What an Inkan is</h2>
<p class="lead">An Inkan is a <strong>permanent anchor</strong> and an open, versioned family of
<strong>deterministic presentations</strong>.</p>
<p>The anchor is <code>SHA-256</code> of a domain-separated seed over <em>(data, kind)</em> — 32
bytes, forever, and what a receipt commits to. The visual seal is a deterministic function of that
anchor: the same anchor draws the same seal on every device, which is exactly what lets a person
compare a wallet's seal against a signer's across an air gap. The digest is the anchor; the picture
is a view. A new renderer is added beside the old one as a new version: it never invalidates an
anchor and never changes an existing seal — that is the property that lets the standard last.</p>
<div class="callout"><strong>Why coded, not hashed-to-pixels.</strong> A naive visual hash bounds
nothing: two seals may be arbitrarily similar. Inkan drives its structure with an error-correcting
code, so any two distinct seals differ in <strong>at least 8 interior cells by construction</strong>
— separation is a theorem, not an accident.</div>

<h2><span class="n">§2</span> &nbsp;Technical profile</h2>
<div class="scroll"><table>
<tr><th>Layer</th><th>Definition</th></tr>
<tr><td><strong>Anchor</strong></td><td>Glyph seed <code>inkan/v1\\0</code> + <code>u8(len(kind))</code> +
  kind + data, all text NFC-normalised, kind ≤ 255 B → <code>SHA-256</code> → 32-byte digest. The
  length prefix makes the kind/data boundary unambiguous for any input.</td></tr>
<tr><td><strong>Code</strong></td><td>Self-identifying <code>ik1</code> + hex (<code>ik</code>=Inkan,
  <code>1</code>=SHA-256/format v1), so a future hash migration (<code>ik2…</code>) is
  unambiguous. Short code = <code>ik1</code> + 16 hex, a verifiable prefix used for filenames.</td></tr>
<tr><td><strong>Structure</strong></td><td>Interior cells hold 2 bits, from bit-interleaved extended
  <strong>Golay [24,12,8]</strong> blocks (24/48/72-cell profiles). Minimum distance: ≥ 8 differing
  cells, tight, every profile.</td></tr>
<tr><td><strong>Symmetry</strong></td><td><em>C<sub>k</sub></em> rotational symmetry, k = 1…7. Free
  cells are fixed per profile; only replication varies, so symmetry carries no entropy cost.</td></tr>
<tr><td><strong>Colour</strong></td><td>32 classes × 5 roles, OKLab, separated by lightness (the
  channel that survives colour-vision deficiency), Brettel–Viénot–Mollon CVD-constrained, gamut-fit.
  Weighted selection down-weights classes resembling disfavoured third-party marks. Constant-weight
  core: exactly 2 of 4 cells inked, never uniform.</td></tr>
<tr><td><strong>Canvas / PNG</strong></td><td>224 × 224 native, integer upscale for any size. 8-bit
  indexed, ≤ 5 flat colours. Canonical PNG carries <em>no</em> metadata; a tagged export embeds the
  <code>ik1</code> code as an untrusted, cross-checked hint.</td></tr>
<tr><td><strong>Kinds</strong></td><td>Open: any UTF-8 string, <code>[namespace:]name[@tier]</code>.
  Reserved kinds use a curated entry; any other string derives its geometry deterministically. No
  registry; third parties assign their own kinds and tiers.</td></tr>
<tr><td><strong>Parity</strong></td><td>Python, JavaScript, Kotlin render byte-identically —
  float-free integer tables, proven over 1500 random cross-port vectors.</td></tr>
</table></div>

<h2><span class="n">§3</span> &nbsp;Use matrix</h2>
<p>The <strong>tier</strong> is chosen by exposure — what a mistaken seal costs — and is bound into
the anchor via the kind, so it is not a user knob for reserved kinds. Higher tier = more cells = more
visible entropy = a costlier forgery.</p>
<div class="scroll"><table>
<tr><th>Tier</th><th>Cells / k</th><th>Reserved kinds</th><th>Use when…</th><th>Visible seals</th>
  <th>Reachable lookalike</th></tr>
<tr><td><strong>T1</strong></td><td class="num">72 · k 1–2</td><td>address, signer, vault, contract</td>
  <td>a wrong seal moves value or trusts a key</td><td class="num">2<sup>79.5</sup> ≈ 8.5×10²³</td>
  <td class="num">~2<sup>40</sup> — infeasible</td></tr>
<tr><td><strong>T2</strong></td><td class="num">48 · k 2–4</td><td>identity, account, (generic)</td>
  <td>confusable but recoverable — identity, accounts</td><td class="num">2<sup>55.5</sup> ≈ 5.1×10¹⁶</td>
  <td class="num">~2<sup>28</sup></td></tr>
<tr><td><strong>T3</strong></td><td class="num">24 · k 4–7</td><td>code, report, collection, backup</td>
  <td>read at a glance, often, low value</td><td class="num">2<sup>31.5</sup> ≈ 3.0×10⁹</td>
  <td class="num">~2<sup>16</sup> — minutes</td></tr>
</table></div>
<div class="row3">{tier_figs}</div>
<p><em>Same account data, three tiers. Left to right the seal grows denser as the security level
rises.</em></p>

<h2><span class="n">§4</span> &nbsp;Security audit</h2>
<p>An adversarial audit was run to <strong>break</strong> the standard, not bless it. Result: no
invariant failure. The measured facts:</p>
<div class="grid2">
  <div class="stat"><div class="v">≥ 8 / cells</div><div class="l">Distance floor — verified tight
    (Golay min-weight 8 over all 4096 words; the floor is achieved, not merely bounded).</div></div>
  <div class="stat"><div class="v">1500 / 1500</div><div class="l">Cross-port vectors reproduced
    byte-for-byte by Python, JS and Kotlin — determinism proven, not assumed.</div></div>
  <div class="stat"><div class="v">0 failures</div><div class="l">Table integrity, avalanche (a
    1-bit flip of the anchor moved ≥ 24 of 48 cells in each of 400 trials), statistics, and
    malformed-input robustness.</div></div>
  <div class="stat"><div class="v">T1 unbroken</div><div class="l">Perceptual lookalike grind:
    12,000 attempts could not push a T1 seal below ΔE 0.063 — clear of the perceptual-identity
    line.</div></div>
</div>
<p><strong>Measured facts, recorded honestly.</strong> Low-tier seals have <em>findable</em> perfect
collisions — a 24-cell collision was ground in ~79,000 tries — because the seal is a deliberately
lossy projection of the anchor (the digest, not the image, is what is trusted). Birthday cost is
~2<sup>16</sup> / 2<sup>28</sup> / 2<sup>40</sup> at 24 / 48 / 72 cells, which is precisely why
value-at-risk kinds are 72-cell and the tier is enforced by the kind.</p>
<div class="callout"><strong>Honest limits.</strong> Every ΔE here is a model of perception, not a
measurement of people — no human-perception study has yet run, and no accessibility or
"phishing-proof" claim is made until it does. The frame motif is 6-bit (14 distinct frames per
config); beyond that, open kinds may share a frame, which is defence-in-depth, not a break, since
different kinds of the same data always differ in the interior.</div>

<h2><span class="n">§5</span> &nbsp;Illustrated catalog</h2>
<h3>Reserved kinds</h3>
<p>Each reserved kind, rendered for sample data. The frame ring encodes the kind; the interior
encodes the data; the tier sets the density.</p>
<div class="gal">{kind_gallery}</div>

<h3>Open kinds — any string, any tier, no registry</h3>
<p>A third party writes its own kind; the renderer derives the geometry deterministically, so the
seal is identical everywhere.</p>
<div class="gal">{open_gallery}</div>

<h3>Symmetry — one interior, k = 1…7</h3>
<p>The same interior information, replicated at each rotational order. Symmetry amplifies the seal
without adding or costing entropy; a flipped cell repaints every wedge.</p>
<div class="row7">{sym_axis}</div>

<h3>The 32 colour classes</h3>
<p>Left to right within each class: ground, three accents, core — separated primarily by lightness
so the seal survives colour-vision deficiency.</p>
<div class="pal">{swatches}</div>

<h2><span class="n">§6</span> &nbsp;Forward provisions</h2>
<p>Because the anchor is permanent and presentations are plural and versioned, the standard absorbs
change without breaking a single existing Inkan: every change arrives as a new version beside the
old ones (a new <code>ik</code> digit, a new <code>SEAL_VERSION</code>, a new canary record version),
and no existing result changes. Reserved for the decades ahead: hash agility (the
<code>ik</code> version digit), post-quantum signature agility (a record version that names its
algorithm inside the signed bytes), extra tiers (<code>@t0</code>, <code>@t4</code>–<code>@t9</code>,
which take effect only in a new seal version; under Seal v3 they are ordinary open kinds), and
non-visual presentations of the
same anchor — <strong>audio</strong> (an identity chime: cells→pitch, palette→timbre, kind→rhythm),
<strong>3D / physical</strong> (a height-map relief → a real stamp face or engraving, closing the
loop on what a seal <em>is</em>), and <strong>haptic</strong> (a vibration pattern for wearables and
accessibility). On-chain permanence, zero-knowledge verification, and a governance registry are
reserved likewise.</p>

<h2><span class="n">§7</span> &nbsp;Verification &amp; reproduction</h2>
<p>Anyone can confirm an Inkan without trusting its source: recompute the canonical seal from the
claimed <em>(data, kind)</em> and compare pixel-for-pixel. A lookalike fails because it is not the
byte-exact render. The full 64-hex code is the anchor; the short code labels it.</p>
<div class="scroll"><table>
<tr><th></th><th>Example</th></tr>
<tr><td>data</td><td class="mono">1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2</td></tr>
<tr><td>kind</td><td class="mono">address</td></tr>
<tr><td>full code</td><td class="mono" style="word-break:break-all">{ex_code}</td></tr>
<tr><td>short code</td><td class="mono">{ex_short}</td></tr>
<tr><td>filename</td><td class="mono">{ex_short}.png</td></tr>
</table></div>
<p>The self-contained verifier (CLI, web, on-chain-ready) recomputes and compares; the reference
engine, conformance vectors, and this document are all reproducible from the same tables.</p>

{_permanence_html()}

{_errata_html()}

<footer>The Inkan Standard v{VERSION} · revision {REVISION} · self-contained, seals rendered by the reference
engine · original work, no third-party lineage · this document is inscription-ready · (c) 2026 RexStarBSV · CC BY 4.0 (LICENSE-SPEC) · requested attribution: \u201cInkan Standard, RexStarBSV\u201d</footer>"""

full = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{TITLE}</title>{STYLE}</head><body><div class=\"wrap\">{BODY}</div></body></html>")
artifact = f"<title>{TITLE}</title>{STYLE}<div class=\"wrap\">{BODY}</div>"

out = pathlib.Path(__file__).parent
(out / "inkan-standard.html").write_text(full)
(out / "inkan-standard.artifact.html").write_text(artifact)
print(f"wrote inkan-standard.html ({len(full)//1024} KB) + artifact variant")
print(f"  {len(KIND_ORDER)} reserved-kind seals, {len(OPEN)} open, 7-step symmetry axis, 32 swatches")
