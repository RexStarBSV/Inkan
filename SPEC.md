# The Inkan Standard — normative specification

**Version 1.0 · frozen 2026-07-28 · revision 1.0.1 (2026-10-10).** This is the frozen normative text
of the Inkan standard: the anchor (§1), the code scheme (§2), the Seal v3 renderer (§3, §5), kinds
(§4), and the fingerprint and canary formats (§7–§8) are locked. §0 states what "frozen" means:
which results can never change, what a revision of this text may do, and how a new version is added
beside the existing ones without redefining anything written here. Each revision is numbered, and
the SHA-256 of each revision of this file is published in `SPEC-REVISIONS.md`.

Language-agnostic and normative. The Python package `inkan_standard` (`python/inkan_standard/`,
distributed as `inkan-standard`) is the reference implementation; the vector files in
`test-vectors/` (§10) let any implementation prove byte-for-byte parity. Illustrated companion:
`standard/inkan-standard.html`.
Forward-looking provisions (audio/3D/haptic presentations, hash agility, governance):
`docs/future-provisions.md`.

Inkan is three independently-verifiable trust signals:

1. **Seal** (§1–§6) — a deterministic visual mark for data you must trust at a glance. *"A human
   notices when it changes."* This is the core of the standard.
2. **Tamper fingerprint** (§7) — *"the artifact is unaltered."*
3. **Warrant / compromise canary** (§8) — *"the operator is uncompromised and un-coerced."*

An Inkan is a **permanent anchor** (a digest) and an open, versioned family of **deterministic
presentations** (the visual seal today; audio/3D/haptic reserved). A new presentation, or a new
version of one, is added beside the existing ones: it never invalidates an anchor and never changes
an existing seal (§0). That is the property that lets the standard last.

---

## 0. Permanence

These rules bind every revision of this text and every implementation that claims Inkan v1 (E17).

**P1 Frozen results.** For every input it accepts, Inkan v1 has exactly one result, forever: the
anchor and its `ik1` code (§1–§2); kind resolution under `SEAL_VERSION` 3 (the 14 reserved kinds and
the suffixes `@t1`, `@t2`, `@t3`, §4); the Seal v3 pixels, fixed by the tables file with SHA-256
`441881915ddf6c213dadac507d714b57068e0f6bb0a6f6070acd3fb924dcdf4b` (§3.0) and by the CC0 vectors;
each fingerprint version (§7); and the v1 canary record bytes and signature rule (§8).

**P2 What an erratum may do.** An erratum MAY clarify wording, add test vectors, or make
implementations reject an input that was malformed or on which conforming implementations already
gave different results. It MUST NOT change the result of any input that the reference
implementation accepts and on which conforming implementations agree. One erratum is an exception,
made in revision 1.0.1 before any canary record had been published: under E23's input rules, these
canary records, on which the reference and the JavaScript verifier had agreed, now read
`MALFORMED`: a record whose `seq` or `block_height` is negative, or is 2^53 or more and held exactly
by a double, and a record read from wire bytes that are not its canonical bytes, all of which both
read `OK`; and a record whose `date` is not a real time in the §8 form, which both read `STALE`.
Every later erratum is bound by this paragraph without exception. Each revision of this text is
numbered (1.0.1, 1.0.2, …), and the SHA-256 of each revision is published in `SPEC-REVISIONS.md`.

**P3 Versions are new names, never edits.** Every result belongs to a version: the anchor version
`ik<v>` (one hash, domain `"inkan/v<v>\0"`), `SEAL_VERSION`, the fingerprint scheme, and the canary
record version. No version name is ever reused or redefined. Where no marker is present, the result
is `ik1`, `SEAL_VERSION` 3, the SHA-256 fingerprint, and record `v1`.

**P4 Additive only.** A new hash is a new anchor version with its own domain. A new seal design is a
new `SEAL_VERSION` beside v3, never a replacement; its tagged PNG carries an `inkan-seal` keyword
(§5), and a seal without one is v3. A product may choose which version it shows, but it labels it,
and both sides of a comparison use the same version. The reserved suffixes (`@t0`, `@t4`–`@t9`) and
new reserved kinds take effect only in a new `SEAL_VERSION`; under v3 they are ordinary open kinds
(§4, E5). A new signature scheme is a new record version whose algorithm is named inside the signed
bytes. An implementation that adds a version keeps generating, verifying and self-testing every
earlier version it claims, and every conforming verifier keeps `SEAL_VERSION` 3.

**P5 Explicit versions.** A verifier treats the version as an explicit part of what it checks,
never infers it from an untrusted tag, and reports an unimplemented version as `UNSUPPORTED`.

**P6 Erosion.** If SHA-256 or secp256k1 weakens, no v1 result changes. Verifiers keep computing v1
results and add a warning; migration adds the new version beside the old one.

---

## 1. The anchor

Given `data` (bytes, or text) and `kind` (a string, §4), the **glyph seed** is:

```
seed = INKAN_DOMAIN || u8(len(kind_utf8)) || kind_utf8 || data
INKAN_DOMAIN = "inkan/v1\0"   (bytes: 69 6e 6b 61 6e 2f 76 31 00)
```

- `kind`, and `data` when it is text, are **NFC-normalised** before UTF-8 encoding, so
  visually-identical strings produce the same Inkan. Raw `bytes` `data` is used verbatim.
- **Text and bytes (E19).** What a person types or pastes is text; only files and binary payloads
  are bytes. A tool that takes `data` from a person (a command-line argument, a form field, the
  string argument of a tool call) MUST pass it as text, so that it is normalised (and the E14 rule
  below applies). It passes bytes only when it reads a file, or an input the person has explicitly marked
  as binary (for example hex or base64). The two can give different anchors for what looks like
  the same input: a decomposed `café` is `ik17288300319e48…` as text and `ik191d9326afef7a…` as
  bytes.
- The kind is **length-prefixed** (`u8`, so `len(kind_utf8) ≤ 255`), making the kind/data boundary
  unambiguous for every possible input.
- **Unassigned code points (E14).** A text input (`data` when it is text, the `kind`, or an adopter
  name, §7) that contains a code point which is unassigned (General_Category `Cn`) in the Unicode
  Character Database the implementation's NFC normaliser uses, other than the 66 noncharacters
  (U+FDD0 to U+FDEF, and the last two code points of each of the 17 planes, U+*n*FFFE and
  U+*n*FFFF), MUST be rejected; it is never normalised or hashed. Each implementation checks with
  the same database, of the same version, that its normaliser uses, and reports that Unicode
  version in its self-test. No minimum Unicode version is required. A kind rejected here is
  rejected everywhere a kind is accepted, including the §4 derivation. Raw `bytes` data is never
  checked.

  This rule is what makes NFC deterministic across Unicode versions. Under Unicode's normalisation
  stability policy, a string whose code points are all assigned in some version has the same NFC
  form in that version and in every later one, so any two implementations that accept a string
  give it the same anchor, now and forever. An implementation whose database does not know a code
  point rejects the string instead of giving a different answer. Noncharacters are permanently
  unassigned and normalise to themselves in every version, so they are accepted.
  `test-vectors/unicode-vectors.json` pins both outcomes: rejected, or exactly the pinned result.

The **anchor** is `SHA-256(seed)` — 32 bytes. It is what a receipt commits to, the input to every
presentation, and the sole basis for trust. **The image is never trusted; the anchor is.**

## 2. Codes

A code is the anchor rendered as a self-identifying string:

```
full  = "ik1" || hex(anchor)              # 3 + 64 chars
short = "ik1" || hex(anchor)[:16]         # 3 + 16 chars, for filenames/display
```

`ik` marks an Inkan code; the digit is the **code-format / hash version** (`1` = SHA-256 over glyph
domain `inkan/v1`). A future hash migration is a new version (`ik2…`), unambiguously distinguishable.
The hex body is a genuine prefix of the anchor, so a short code is auditable by recomputing and
checking. A conforming reader MUST reject a code whose version it does not implement rather than
assume SHA-256.

## 3. The visual seal (Seal v3)

The renderer maps the 32-byte anchor to a `CANVAS × CANVAS` image (`CANVAS = 224`). It is
**float-free**: geometry and palette are precomputed integer tables, so all implementations agree
byte-for-byte. `SEAL_VERSION = 3`.

### 3.0 The tables

Seal v3 is defined by this section together with one data file, `test-vectors/seal-v3-tables.json`
(CC0), whose SHA-256 is

```
441881915ddf6c213dadac507d714b57068e0f6bb0a6f6070acd3fb924dcdf4b
```

The file holds every table and constant the renderer uses, under the names this section uses:
`CANVAS`, `SEAL_VERSION`, `STREAM_DOMAIN_HEX` (`"inkan/seal/v3"`), `KIND_DOMAIN_HEX`
(`"inkan/kind/v1\0"`), `GOLAY_G`, `TIER_CELLS`, `KMAX`, `ORBIT_REPS`, `KINDS` (the reserved table,
§4), `PALETTE`, `SELECT_WEIGHTS`, `CORE_PATTERNS` and `REGION_RLE`. It has one further member,
`FORMAT`, whose value is the string `"inkan-seal-v3-tables"`: it names the file and is not read by
the renderer, but it is part of the encoded object and therefore of the digest. The object has
exactly these fourteen members. It is written in a canonical encoding, so an implementation can
rebuild the exact bytes from its own copy of the tables and compare digests: one JSON object;
members sorted by key in code-point order; no insignificant whitespace (separators `,` and `:`);
integers in shortest decimal form; every string pure ASCII and written without escapes; the whole
followed by a single line feed (`0x0A`). An implementation whose tables do not encode to these
bytes does not implement Seal v3 (E16). The vectors in `test-vectors/seal-v3-coverage-vectors.json`
reach every entry of every table.

### 3.1 Field extraction (normative draw order)

The field stream is the concatenation of the 32-byte blocks
`SHA-256(anchor || "inkan/seal/v3" || ctr_be32)` for `ctr = 0, 1, 2, …`, read one byte at a time in
order. A uniform value in `[0,n)` is drawn by rejection: read a byte, accept if
`< 256 − (256 mod n)`, return `byte mod n`. For a kind resolving to `cells` cells (§4), draw in this
exact order:

1. `cells / 12` **info words**: word `j` is `((b << 8) | b′) & 0xFFF`, where `b` and `b′` are the
   next two stream bytes, for `j = 0, 1, …` in order.
2. the **palette index**, rejection-sampled over the weighted selection table (§3.4).
3. the **core pattern**, rejection-sampled over the 6 constant-weight patterns (§3.5).

Rejections can carry these draws past the first block; the stream simply continues into block
`ctr = 1`. Ordinary inputs do so about once in two billion, and two `second_block` vectors pin it.

### 3.2 Structure — coded cells

Interior cells hold 2 bits each, from **bit-interleaved extended Golay [24,12,8]** blocks. For cell
group `g` (24 cells, `g = 0 … cells/24 − 1`), let `A = golay24(word[2g])`, `B = golay24(word[2g+1])`;
then `cell[24g+i] = (B_i << 1) | A_i` for `i = 0 … 23`, where `X_i` is bit `i` of `X` and bit 0 is the
least significant. `golay24` is non-systematic: `c` is the XOR of the rows `GOLAY_G << b`
(`GOLAY_G = 0xAE3`) over every set info bit `b`, and the codeword is `(c << 1) | (popcount(c) mod 2)`,
so the overall even-parity bit is bit 0.

**Guarantee.** Any two distinct seals differ in ≥ 8 cells: a cell differs iff bit *i* of `A⊕A′` or
`B⊕B′` is set, so cells differing `= popcount((A⊕A′) | (B⊕B′)) ≥ max(|·|,|·|) ≥ 8`, Golay's minimum
weight. The floor is achieved (tight), for every profile.

### 3.3 Symmetry

Each kind renders with *C<sub>k</sub>* rotational symmetry, `k = 1…7`. Free cells are fixed per
profile; only the replication count varies, so symmetry carries no entropy cost — one flipped cell
repaints all `k` wedges. The geometry of each `(cells, k)` is fixed by its region map (§3.6).

### 3.4 Colour

32 classes, each 5 roles `(ground, accent1, accent2, accent3, core)` × RGB, in `PALETTE`: class `i` is
`PALETTE[i]`, its five colours in that role order, each colour `[R, G, B]` with 8-bit channels.
Classes are separated primarily by **lightness** (the channel that survives colour-vision
deficiency), selected under Brettel–Viénot–Mollon CVD simulation with sRGB gamut fitting. Selection
is **weighted**: the draw table is `SELECT_WEIGHTS[0]` copies of `0`, then `SELECT_WEIGHTS[1]` copies
of `1`, and so on through class 31, 173 entries in all (default weight 6; classes resembling a
disfavoured third-party mark are down-weighted). The palette index is `table[u]`, where `u` is the
uniform value in `[0, 173)` drawn in step 2 of §3.1.

### 3.5 Core

The centre disc is **constant-weight**: exactly 2 of its 4 cells inked, chosen from the 6 weight-2
patterns `CORE_PATTERNS = (3, 5, 6, 9, 10, 12)`, in that order: the core pattern is
`CORE_PATTERNS[u]` for the value `u` in `[0, 6)` drawn in step 3 of §3.1. Bit `j` of the pattern
(`j = 0 … 3`) inks core cell `j`. The core is therefore never uniform and the core colour always
appears.

### 3.6 Frame & rendering

The kind selects a 6-bit **frame motif** (§4): bit `j` of the motif (`j = 0 … 5`, bit 0 the least
significant) inks frame bucket `j`. For an open kind the motif is `ORBIT_REPS[kh[1] mod 14]`, with
`ORBIT_REPS = (0, 1, 3, 5, 7, 9, 11, 13, 15, 21, 23, 27, 31, 63)` in that order; a reserved kind takes
the value in its table entry (§4).

Each pixel maps to a region id through the region map of the kind's `(cells, k)`. There are 13
maps, keyed `"24,1"` … `"24,7"`, `"48,1"` … `"48,4"`, `"72,1"` and `"72,2"`. `REGION_RLE[key]` is
standard base64 (RFC 4648 §4, with padding) of a sequence of 3-byte records `(id: u8, run: u16
little-endian)`; expanding each record, in order, to `run` copies of `id` gives exactly `CANVAS²`
region ids, one per pixel in the pixel order of §3.7. A region id selects the pixel's colour:

- `id < cells` → petal cell → `[ground, accent1, accent2, accent3][cell[id]]`
- `100 ≤ id < 200` → core cell `id−100` → `core` if `(core_pattern >> (id−100)) & 1` else `ground`
- `200 ≤ id < 255` → frame bucket `id−200` → `accent1` if `(motif >> (id−200)) & 1` else `ground`
- `id = 255` → `ground`

### 3.7 Pixel order and the RGB digest

Pixel `(x, y)`, column `x` and row `y` both counted from 0 at the top-left corner, is pixel number
`i = y · CANVAS + x`. The seal's **RGB888 string** is, for `i = 0 … CANVAS² − 1` in order, the three
bytes `R, G, B` of pixel `i`: 150,528 bytes. Every vector that pins pixels pins
`rgb_sha256 = SHA-256(RGB888 string)` (in `vectors.json`, the same value is named `rgb888_sha256`).
The PNG (§5) stores the same pixels, scanline `y = 0` first.

## 4. Kinds — open, tier-weighted, third-party assignable

A kind is any string of at most 255 UTF-8 bytes after NFC (§1), conventionally
`[namespace:]name[@tier]`. The anchor treats it as an opaque string. For the seal it resolves to
`(cells, k, motif)`: `cells ∈ {24, 48, 72}` is the tier's cell count, `k ∈ 1…7` the rotational
symmetry order, and `motif` the 6-bit frame code (§3.6).

### 4.1 Reserved kinds

If the kind is exactly one of these 14 strings, its entry is used directly. All 14 entries are
normative (E18); they are `KINDS` in the tables file (§3.0).

| kind | cells | k | motif |
|---|---|---|---|
| `""` (empty, the default) | 48 | 2 | 63 |
| `identity` | 48 | 4 | 56 |
| `account` | 48 | 3 | 36 |
| `address` | 72 | 1 | 51 |
| `vault` | 72 | 1 | 61 |
| `signer` | 72 | 2 | 54 |
| `contract` | 72 | 2 | 60 |
| `code` | 24 | 7 | 42 |
| `report` | 24 | 6 | 44 |
| `collection` | 24 | 5 | 48 |
| `backup` | 24 | 4 | 32 |
| `custom/24` | 24 | 1 | 52 |
| `custom/48` | 48 | 1 | 52 |
| `custom/72` | 72 | 1 | 52 |

The lookup is an exact match on the kind as provided. `address` is reserved; `address@t1` is a
different, derived kind.

### 4.2 Derivation (every other kind)

1. **Tier.** If the kind ends with the literal suffix `@t1`, `@t2` or `@t3` (tested in that order;
   the first match wins), that suffix selects the tier; otherwise the tier is `t2`.
   `cells = TIER_CELLS[tier]`, with `TIER_CELLS = {t1: 72, t2: 48, t3: 24}`.
2. **Kind hash.** `kh = SHA-256("inkan/kind/v1\0" || kind_utf8)`, the UTF-8 of the kind as provided.
3. **Symmetry.** `k = 1 + (kh[0] mod KMAX[cells])`, with `KMAX = {72: 2, 48: 4, 24: 7}`.
4. **Frame motif.** `motif = ORBIT_REPS[kh[1] mod 14]`, where `ORBIT_REPS` are the 14
   rotation-distinct 6-bit frame representatives (§3.6).

Because the tier is part of the kind string and the kind is in the anchor, the same kind renders
identically everywhere, and namespaced kinds never collide between adopters — **no registry**.

**Normalization (E3).** The derivation above hashes `kind_utf8` **as provided** — no NFC step; only
the anchor (§1) normalizes. An implementation MUST NOT insert NFC into this derivation (all pinned
vectors are NFC, so the divergence would pass the gates and surface only in the field). Callers
SHOULD pass kinds already in NFC so anchor and seal agree. A kind containing an unassigned code point
is rejected here as in §1 (E14). A kind that is not encodable as valid
UTF-8 (e.g. a lone surrogate) MUST be rejected, never silently substituted (E4).

**Unrecognized tier suffixes (E5).** In this version an `@t0` or `@t4`–`@t9` suffix is NOT
special-cased: the whole literal string is an ordinary open kind at the default tier (`t2`). An
implementation MUST NOT reject or reinterpret them.

**Cell profiles** are the three extended-Golay tiers: **24** (2 blocks · T3), **48** (4 · T2), **72**
(6 · T1). Higher tier = more cells = more visible entropy = costlier forgery (§9). Reserved motifs are
verified mutually rotation-distinct within each `(cells, k)`. Reserved `@t0` and `@t4`–`@t9`, and
non-visual presentation types, per `docs/future-provisions.md`.

## 5. PNG encoding

The canonical seal is an **8-bit indexed PNG** with chunks exactly `IHDR / PLTE / IDAT / IEND` and
**no ancillary chunks**. It is **pixel-deterministic**: every conforming encoder writes a valid PNG
that decodes to exactly the seal's pixels. Its compressed bytes are not part of the standard, since
they depend on the deflate implementation and its settings (E20); `png_bytes` in
`seal-v3-vectors.json` records one zlib build's output size and is informative only. No
implementation is judged on it, and no vector, comparison or on-chain record may pin compressed PNG
bytes. The palette is the seal's distinct colours sorted ascending by `(R, G, B)`, compared as
unsigned integers; each scanline is a filter-0 byte followed by one index per pixel. `scale` is an
integer nearest-neighbour upscale.

The cross-language invariant is the **RGB pixel content**, not the compressed PNG bytes (deflate
output is per-implementation; all conforming encoders produce valid PNGs decoding to identical
pixels). A **tagged** export additionally embeds `iTXt` chunks `inkan-code` (the full `ik1` code) and
`inkan-kind`, making the image self-describing. Each tag chunk's body is

```
keyword (Latin-1) || 0x00 || 0x00 (compression flag) || 0x00 (compression method)
                  || 0x00 (empty language tag) || 0x00 (empty translated keyword) || utf8(text)
```

and a tagged export writes `inkan-code` and then `inkan-kind` after the last `IDAT` and before
`IEND`. The embedded code is an **untrusted hint** — a
verifier MUST recompute and compare pixels, treating the tag only as a cross-check. The keyword
`inkan-seal` is reserved: a tagged PNG of a later `SEAL_VERSION` names its version in an `iTXt` chunk
with that keyword (§0, P4). A Seal v3 writer never emits it, and a seal without it is Seal v3.

## 6. Verification

To verify a presented seal for a claimed `(data, kind)`: recompute the anchor and canonical seal,
decode the presented file under the verifiable-PNG profile (§6.1) to native RGB (integer-downscaling
an exact multiple; rejecting any other size), and compare pixel-for-pixel. **GENUINE** iff equal.
When the presented image is an integer upscale, the downscale MUST verify that **every** pixel of
each *scale x scale* block is identical before reducing it — sampling one pixel per block leaves the
remaining *scale^2 - 1* pixels unexamined and attacker-controlled (at scale 8, 98.44% of the image).
An implementation that samples MUST report a non-uniform block as a distinct failure, never as a
size error and never as GENUINE (E10). Re-encoding and integer upscales are tolerated; a resampled,
cropped, or different image is rejected. This defeats a phishing lookalike: it is not the
byte-exact render. Verification never trusts embedded metadata.

### 6.1 The verifiable-PNG profile

A verifier accepts a presented file only if it is a PNG that meets every rule below, and rejects it
otherwise (E24). The profile accepts every honest re-encoding of a seal (any deflate settings, any
scanline filters, indexed or truecolour, benign metadata) and nothing whose appearance can differ
from its decoded pixels. The verifier MUST decide on its own decode under these rules; it may use a
platform image decoder to display the image, never to judge it.

1. **Signature and chunks.** The file begins with the PNG signature `89 50 4E 47 0D 0A 1A 0A` and
   continues as a sequence of chunks: a 4-byte big-endian length of at most 2^31 − 1, a 4-byte
   type, the data, and a CRC-32 over the type and the data as PNG defines it. Every CRC MUST be
   correct. The file ends exactly where the `IEND` chunk ends.
2. **Allowed chunks.** Only `IHDR`, `PLTE`, `IDAT`, `IEND`, `tEXt`, `zTXt`, `iTXt`, `pHYs` and
   `tIME` may appear. Any other chunk, critical or ancillary, known or unknown, MUST be rejected:
   among them `tRNS`, `gAMA`, `cHRM`, `sRGB`, `iCCP`, `sBIT`, `bKGD`, `hIST`, `sPLT`, `eXIf`, `cICP`,
   `mDCV`, `cLLI` and the animation chunks `acTL`, `fcTL` and `fdAT`. An allow-list cannot be
   outgrown by chunk types PNG adds later; E12's list of forbidden chunks could.
3. **Order.** `IHDR` comes first and appears once. `IEND` comes last and has no data. `PLTE` appears
   at most once, before the first `IDAT`. The `IDAT` chunks are consecutive. `pHYs` (before the
   first `IDAT`) and `tIME` appear at most once each. Text chunks may appear anywhere between
   `IHDR` and `IEND`.
4. **Header.** Bit depth 8; colour type 2 (truecolour) or 3 (indexed-colour); compression method 0;
   filter method 0; interlace method 0. Width and height are from 1 to 2^31 − 1.
5. **Palette.** Colour type 3 requires a `PLTE` whose length is a multiple of 3, with 1 to 256
   entries, and every pixel's index MUST be less than the number of entries. With colour type 2, a
   `PLTE` (a suggested palette) is allowed and ignored.
6. **Image data.** The data of all `IDAT` chunks, concatenated, is one zlib stream (RFC 1950:
   compression method 8, no preset dictionary, a correct Adler-32) that ends exactly at the end of
   the last `IDAT` and inflates to exactly `height · (1 + width · channels)` bytes, `channels` being
   3 for truecolour and 1 for indexed-colour. Each scanline begins with a filter type from 0 to 4
   and is unfiltered as PNG defines. A verifier SHOULD stop inflating as soon as the output would
   exceed that size.
7. **Metadata.** `pHYs` has 9 bytes of data and `tIME` 7. `tEXt`, `zTXt`, `iTXt`, `pHYs` and `tIME`
   do not change the pixels and are not interpreted, except that a verifier MAY read the
   `inkan-code` and `inkan-kind` tags (§5) as an untrusted cross-check.

`test-vectors/png-profile-vectors.json` pins 35 presented files and the verdict each must get.

## 7. Tamper fingerprint

Per-adopter tamper mark over a payload:

```
domain_prefix = u8(len(adopter_utf8)) || adopter_utf8 || "/inkan/v" || dec(version) || 0x00
fingerprint   = SHA-256(domain_prefix || payload)
```

`adopter_utf8` is the UTF-8 of the NFC-normalised adopter name, at most 255 bytes. `dec(version)`
is the version in ASCII decimal digits, with no sign and no leading zeros. The payload is bytes
(§1, E19). The length prefix makes the adopter/payload boundary unambiguous. Distinct adopters yield
distinct fingerprints for the same payload while sharing the standard. `fingerprint_hex` is the
lower-case hex.

**Adopter names (E6, E21).** An adopter name MUST be printable, which here means exactly: it is
well-formed Unicode text (E4); it contains no unassigned code point (E14, §1); and it contains no
control character, that is, no code point in U+0000–U+001F or U+007F–U+009F (NUL included). After
NFC it MUST NOT begin with `nkan/`. These rules are fixed by code-point ranges, not by Unicode
general categories, so they do not change as Unicode assigns new characters. The `nkan/` rule closes
the one cross-context parse: for a name of the right length the length byte is `0x69` (ASCII `i`),
the fingerprint preimage then opens with the nine bytes of `INKAN_DOMAIN`, and one digest would be
both a valid fingerprint and a valid anchor (§1). An implementation MUST reject a name that breaks
any of these rules, before hashing.

**Versions (E22).** `version` is a positive integer: 1, 2, 3, and so on. Anything else (zero, a
negative number, a fraction, a string, a boolean) MUST be rejected. Version *n* is SHA-256 over
exactly this construction with `dec(n)` in the suffix, forever: no version ever changes its hash or
its layout. A fingerprint over a different hash function is not a new version of this scheme; it
gets its own domain and a text form that names its hash, so it can never be mistaken for, or
compared with, a fingerprint defined here. A verifier takes the version as an explicit input
(§0, P5); the reference default is 1. `test-vectors/fingerprint-vectors.json` pins accepted and
rejected names and versions.

### 7.1 Release provenance

A released file (a build, an archive, a page) is given a provenance seal computed from its bytes
alone (E15):

```
file_hash   = SHA-256(file_bytes)                     # 32 bytes
anchor_data = hex(file_hash)                          # text: 64 lower-case hexadecimal ASCII characters
anchor      = the §1 anchor of (data = anchor_data, kind = "code")
            = SHA-256("inkan/v1\0" || 0x04 || "code" || anchor_data)
code        = "ik1" || hex(anchor)
```

- The provenance seal is the Seal v3 of `anchor` under kind `code` (§3; `code` resolves to
  `(cells, k, motif) = (24, 7, 42)`). Published as a 1-of-1 ordinal (BRC-145 §7.4), the inscription
  content is its **tagged** PNG (§5): the `inkan-code` tag carries `code` and the `inkan-kind` tag
  carries `code`. The reference tooling writes it at scale 8.
- The publisher's §7 fingerprint of the same `file_bytes`, under its adopter name and fingerprint
  version, is published beside the seal. It is a second, independent check of the same bytes. It is
  **not** the inscribed seal, it is not rendered as one, and no `ik` code is formed from it: an `ik`
  code labels only an anchor (§2).
- To verify a release, compute `file_hash` from the bytes you hold, recompute `anchor`, `code` and
  the canonical seal, and compare the inscribed image pixel for pixel (§6). Where the publisher's
  fingerprint is given, recompute it as well and compare all 32 bytes.
- Worked example: `test-vectors/vectors.json`, block `inkan_image_example` (a 14-byte file whose
  bytes are `build-bytes-v1`).

*Informative.* The reference tooling (`tools/emit_sidecar_seal.py`) writes these values to a
sidecar record beside the file, `<file>.inkan.json`, together with the tagged seal,
`<file>.inkan.png`. In that record the field `fingerprint` holds `hex(file_hash)`, the plain file
hash, and the field `adopter_fingerprint` holds the §7 fingerprint.

## 8. Warrant / compromise canary

A signed, freshness-bounded statement that the operator is uncompromised.

- **Record**: `{v, domain, seq, date, block_height, block_hash, statement}` — exactly these seven
  fields (E1). `v` is the record version, `1` for this format. `date` is UTC `YYYY-MM-DDTHH:MM:SSZ`.
  `max_age_days` is a **verifier-side policy parameter** (reference default 35), never a record field.
- **Canonical bytes (E23)**: the record written as one JSON object with no insignificant
  whitespace, encoded in UTF-8: `{`, the seven members in ascending order of key (`block_hash`,
  `block_height`, `date`, `domain`, `seq`, `statement`, `v`) separated by `,`, each written
  `"key":value`, then `}`. An integer is written in decimal digits with no sign, fraction, exponent
  or leading zero. A string is written between `"` characters with exactly these escapes: `"` as
  `\"`, `\` as `\\`, U+0008 as `\b`, U+000C as `\f`, U+000A as `\n`, U+000D as `\r`, U+0009 as
  `\t`, and every other code point below U+0020 as `\u00xx` with two lower-case hexadecimal digits;
  every other code point, U+007F, U+2028, U+2029 and all non-ASCII characters included, is written
  as itself. This is the output of Python's `json.dumps(record, sort_keys=True, separators=(",",
  ":"), ensure_ascii=False)` and of JavaScript's `JSON.stringify` with sorted keys, for any record
  that meets the input rules. The `vectors.json` canary block and `canary-vectors.json` are normative
  for the byte form.
- **Input rules (E23)**: after the version check (E2: a record whose `v` is not the integer 1 is
  `UNSUPPORTED`), a verifier checks the record against these rules before it checks the signature,
  and reports `MALFORMED` for a record that breaks any of them:
  1. `seq` and `block_height` are integers from 0 to 2^53 − 1 inclusive.
  2. `date` is exactly 20 ASCII characters, `YYYY-MM-DDTHH:MM:SSZ`, each letter other than `T` and
     `Z` standing for an ASCII digit 0–9 and `-`, `T`, `:` and an upper-case `Z` appearing
     literally, and it names a real UTC time: year 0001–9999, month 01–12, a day that exists in
     that month of that year (Gregorian calendar), hour 00–23, minute 00–59, second 00–59.
  3. Every string is well-formed Unicode text: a JSON escape that leaves an unpaired surrogate is
     malformed.
  4. A record read from bytes (for example from the on-chain output of §8.1) is malformed unless
     those bytes are exactly its canonical bytes.

  These rules make every conforming verifier give the same verdict for every record; no published
  record breaks them.
- **Key and signature form (E23)**: the public key and the signature are each given as hexadecimal
  text: an even number, at least two, of the ASCII digits `0`–`9`, `a`–`f` and `A`–`F`, with no
  prefix such as `0x` and nothing between the digits. Only these characters are ignored before and
  after the digits: U+0009 to U+000D, U+0020, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029,
  U+202F, U+205F and U+3000. A key or signature in any other form, or one that is not text, is
  `MALFORMED`.
- **Signature**: over `SHA-256(canonical_bytes)`; the reference scheme is secp256k1 ECDSA (RFC 6979,
  low-S). A signature whose `S` is greater than half the group order (the "high-S" twin of a valid
  signature) is not one this scheme produces, and a verifier MUST report it `INVALID` (E23), even
  where a generic ECDSA library would accept it. *A signature-algorithm identifier is reserved for
  post-quantum migration — `docs/future-provisions.md`.*
- **Status**: `OK` iff the signature verifies against the published key **and** the record is fresh
  (`−86400 ≤ now − date ≤ max_age_days · 86400`); else `INVALID` (a signature check RAN and failed)
  or `STALE` (expired, or future-dated by more than one day). A verifier MUST check `v` and MUST
  surface an unknown record version as an explicit error (UNSUPPORTED), never as `INVALID` or `OK`;
  a verifier whose signature backend is unavailable MUST raise, never fabricate a verdict (E2). A key
  or signature that does not parse MUST surface as `MALFORMED` — a check that never RAN — and MUST
  NOT be reported as `INVALID`, which asserts that a check ran and the signature was wrong (E11). A
  record that is not exactly the seven fields with their types (an integer for `v`, `seq` and
  `block_height`; a string for the others) is `MALFORMED` (E13).

### 8.1 On-chain form

A signed record is published on chain as a data output whose locking script is (E18):

```
OP_RETURN (0x6a)
push(MARKER)                  # MARKER = ASCII "INKANC1", 7 bytes: 49 4e 4b 41 4e 43 31
push(canonical_record_bytes)  # §8
push(der_signature)           # secp256k1 ECDSA, DER
push(public_key)              # 33-byte compressed secp256k1 point
```

Each `push(blob)` is minimal Bitcoin script pushdata, for `n = len(blob)`: `n < 0x4C` →
`u8(n) || blob`; `0x4C ≤ n ≤ 0xFF` → `0x4C || u8(n) || blob`; `0x100 ≤ n ≤ 0xFFFF` →
`0x4D || u16le(n) || blob`; otherwise `0x4E || u32le(n) || blob`. A reader matches `OP_RETURN`, then
reads exactly four pushes in order; it MUST reject the output if the first push is not exactly
`MARKER` or if any push is truncated. Everything a verifier needs is in the output, and the reader
MUST NOT trust what it parsed: it verifies the record as above, offline. The chain is trusted only
for immutability and time ordering. *Informative:* the reference publishes this output through a
BRC-100 wallet (`createAction` with one `OP_RETURN` output of 0 satoshis); the wallet funds and
broadcasts but never signs the record. `vectors.json` → `canary` and BRC-145 TV7 are the worked
example.

> The `vectors.json` fingerprint and canary values are examples, not values any publisher has
> issued: the canary is signed with a deliberately public test key, which must never be used for a
> real canary. The formats in §7–§8 are frozen; live fingerprints and canaries are published by each
> publisher, not by this document.

## 9. Security profile (audited)

An adversarial audit found no invariant failure (scope and methods: `docs/audit-abstract.md`;
the full evidence corpus is maintained privately).

| Property | Result |
|---|---|
| Distance floor | ≥ 8 cells, verified tight (Golay min-weight 8 over all 4096 words) |
| Cross-port determinism | 1500 random vectors byte-identical in Python, JS, Kotlin |
| Visible seals / tier | 2^31.5 (T3) · 2^55.5 (T2) · 2^79.5 (T1) |
| Perfect-collision cost | ~2^16 · 2^28 · 2^40 renders (birthday) — why value-at-risk kinds are T1 |
| Perceptual lookalike | T1 not pushed below ΔE 0.063 in 12,000 grinds |
| Avalanche | a 1-bit flip of the anchor moved ≥ 24 of 48 cells in each of 400 trials (mean 36) |

**Honest limits.** Every ΔE is a model of perception, not a measurement of people — no human study
has run, so no accessibility or "phishing-proof" claim is made. The 6-bit frame gives 14 distinct
frames per config; beyond that, open kinds may share a frame (defence-in-depth, not a break, since
different kinds of the same data always differ in the interior). Low-tier seals have *findable*
perfect collisions by design; the digest, not the image, is the anchor.

The cost table above is stated for **2026 classical compute** (E7). Compute growth and quadratic
quantum search erode every visual-forgery figure over decades; the anchor's own security does not
rest on them. Adopters MUST treat visual comparison as a human tamper-notice channel only — never
sufficient authentication for a value-at-risk decision at any tier — and MUST NOT return a GENUINE
verdict from any comparison shorter than the full 32-byte digest (E8; short codes are labels).

## 10. Versioning & parity

- **Anchor** (`inkan/v1`, SHA-256, code `ik1`): permanent. Changing it invalidates every Inkan; a new
  hash is a new version namespace, not a revision.
- **Renderer** (`SEAL_VERSION`): versioned and additive (§0, P4). A new design is a new
  `SEAL_VERSION` added beside v3, never a replacement: v3 is never redefined, every v3 seal keeps its
  pixels, and every conforming verifier keeps v3. Two surfaces comparing seals MUST use the same
  `SEAL_VERSION`, and a product that can show more than one labels which one it shows.
- **Parity**: an implementation conforms iff it reproduces `seal-v3-vectors.json` (sampled fields +
  RGB SHA-256, and constructed minimum-distance pairs), `seal-v3-coverage-vectors.json` (every
  table entry, and the second stream block) and `vectors.json` (fingerprint, canary, glyph,
  release provenance), and its Seal v3 tables encode to the file §3.0 pins. The reference is
  `python/inkan_standard/`; regenerate vectors only via `python/tools/`.

---

## Errata (v1.0)

Corrections and clarifications to the frozen text, each within the limits §0 (P2) sets. **No entry
changes the result of an input that the reference implementation accepts and on which conforming
implementations agree, apart from the one exception P2 names: E23 makes canary records of these
kinds, on which the reference and the JavaScript verifier had agreed, read `MALFORMED`: those with a
negative `seq` or `block_height`, or one of 2^53 or more that a double holds exactly, or read from
wire bytes that are not their canonical bytes, all read `OK` before; and those whose `date` is not a
real time in the §8 form, read `STALE` before. That change was made before any canary record had
been published. No anchor, code, seal pixel, pinned vector result or canonical record byte has
changed.** An entry that makes implementations reject an input that was malformed, or on which they
gave different results, says so.

Most entries here align prose with the bytes the standard already pinned, or add a constraint every
conformant implementation already satisfied. **E4, E10, E11, E12 and E13 do not.** Each adds a requirement no
port met when it was written, and each has since been fixed with a test that fails against the
pre-fix behaviour, **in every port the requirement applies to**. That is not all three in every case,
and the per-erratum rows below are authoritative on which: E4 binds the anchor, the §4 derivation and
adopter names, and is fixed in each of them in every port that has it, while E10 and E12 are
verification rules and only the Python reference carries a verification path at all. An earlier version of this paragraph said "in all three
ports" without qualification. It contradicted its own table two rows down, and it was copied from here
into the body and commit message of a public pull request before anyone noticed.
E4 was the last to close in the anchor, on 2026-08-04: until then Python raised by
accident of its default error handler while JavaScript and Kotlin substituted differently again, so
one malformed input produced three anchors and two ports believed they had succeeded. In the §4
derivation and the JavaScript fingerprint it closed in revision 1.0.1. They are set out here rather than folded silently into §6 and §8 because a reader
of a frozen standard is entitled to know which clarifications describe what always happened and which
describe what should have.

**E14, E21, E22, E23 and E24 add requirements that no port met when they were written.** Each is now
implemented in every port it applies to, and the per-erratum rows say which those are. Their vectors
name the erratum whose behaviour they test (`rule`), so a port that has not implemented one reports
those vectors as skipped, by name, rather than passing them. Every other vector in those files binds
every port.

| # | Date | Section | Nature |
|---|---|---|---|
| E1 | 2026-07-31 | §8 | Record field list corrected to match the pinned canary vector: `{v, domain, seq, date, block_height, block_hash, statement}` (prose previously said `timestamp`/`max_age_days`; the signed bytes never did). `max_age_days` documented as verifier policy. |
| E2 | 2026-07-31 | §8 | Verifier obligations made explicit: unknown record version → UNSUPPORTED (never INVALID/OK); missing signature backend → raise (never a fabricated verdict). Matches reference behaviour. |
| E3 | 2026-07-31 | §4 | Derivation hashes the kind as provided (no NFC) — stated normatively; only the anchor normalizes. Matches all three ports. |
| E4 | 2026-07-31 | §4 | Kinds not encodable as valid UTF-8 MUST be rejected (fail-closed), never substituted. **Enforced in the anchor (§1) of all three ports from 2026-08-04.** Before that Python raised while JS and Kotlin substituted, so one malformed kind yielded three anchors. Since revision 1.0.1 it is enforced everywhere it applies: the §4 derivation in JavaScript and Kotlin, and adopter names and text payloads in the JavaScript fingerprint (§7), substituted until then and now reject, as Python always did in all three places. Substitution is the specific hazard: every unpaired surrogate collapses onto the same replacement bytes, so distinct kinds would share an anchor. |
| E5 | 2026-07-31 | §4 | Unrecognized `@tN` suffixes are ordinary open kinds at default tier — stated normatively; matches reference. |
| E6 | 2026-07-31 | §7 | Adopter-name profile: printable UTF-8, no NUL, no `nkan/` prefix (closes a theoretical cross-context parse). |
| E7 | 2026-07-31 | §9 | Visual-forgery cost table date-stamped 2026-classical; erosion note added. |
| E8 | 2026-07-31 | §9 | GENUINE verdicts require full-digest comparison; short codes are labels only — made testable. |
| E9 | 2026-07-31 | §9 | Audit-evidence pointer retargeted to the shipped `docs/audit-abstract.md` (the private corpus path dangled in the public tree). |
| **E10** | **2026-08-04** | **§6** | **Integer-upscale downscaling MUST verify every pixel of each block, not sample one.** The reference sampled the block's top-left pixel and never checked uniformity, leaving *scale^2 - 1* pixels per block attacker-controlled — 98.44% of the image at scale 8. Demonstrated: an image 98.44% pixel-identical to one entity's genuine seal verified GENUINE as a **different** entity's. §6 already required "compare pixel-for-pixel"; it did not say the *downscale* had to be faithful, so a clean-room implementer would have inherited the hole. A non-uniform block MUST be a distinct failure, never a size error. Fixed in Python and in the built verifier page; JS and Kotlin have no presented-image path. |
| **E11** | **2026-08-04** | **§8** | **A key or signature that does not parse MUST read `MALFORMED`, not `INVALID`.** The reference collapsed both into `INVALID` — the maximum-severity verdict, which asserts a signature check ran and failed — for what is nearly always a truncated paste. This is the same principle E2 applied to unknown record versions: never report a check that did not happen as one that did. `MALFORMED` is fail-closed and is never `OK`. Fixed in Python and JS. |
| **E12** | **2026-08-04** | **§6** | **A presented PNG carrying a rendering-affecting ancillary chunk MUST be rejected.** `tRNS` names colours a conformant viewer must draw as fully transparent; `gAMA`/`iCCP`/`sRGB`/`cHRM`/`sBIT`/`bKGD` alter tone; `acTL`/`fcTL`/`fdAT` make it an animation. None change the decoded RGB, so a genuine seal plus one such chunk verified GENUINE while rendering differently — the same class of defect as E10, and demonstrated with `tRNS`. Benign metadata (`tEXt`, `iTXt`, `pHYs`, `tIME`) stays tolerated, so §6's re-encoding allowance is unaffected. Fixed in Python and in the built verifier page, the latter checking the file bytes rather than the canvas decode. |
| **E13** | **2026-08-04** | **§8** | **A canary record MUST carry exactly the seven fields E1 fixes, with those types.** Nothing validated this in any port, on either side of the wire. A wrong shape cannot be forged — the signature covers whatever fields are present — but a publisher could emit one by mistake and every verifier would still have reported `OK`, while downstream readers disagreed about what they were reading. A record of the wrong shape now reads `MALFORMED`. |
| **E14** | **2026-10-10** | **§1, §4, §7** | **A text input containing a code point that is unassigned in the implementation's Unicode database MUST be rejected, never normalised or hashed.** §1 said only "NFC-normalised", with no Unicode version and no rule for code points a runtime does not know, so each port normalised with its own runtime's tables (Python 3.14: Unicode 16; Node 22: Unicode 17; Java 17: Unicode 13) and the ports already disagreed: data `e U+0897 U+0327 e U+1AD0 U+0327` under kind `""` gave `ik13777f…`, `ik1cc0c4…` and `ik13129b…`. The same split occurs between two releases of one runtime. Rejection is the only rule that cannot change a result conforming implementations agree on, because under Unicode's stability policy implementations that accept a string agree on it forever. The 66 noncharacters are accepted; no minimum Unicode version is set. Text whose code points are all assigned in every current runtime, every reserved kind and every earlier vector are unaffected. New `unicode-vectors.json` pins accepted results and either/or results (rejected, or exactly this). Implemented in all three ports, in the anchor and the §4 derivation, and in the Python and JavaScript fingerprint for adopter names (the Kotlin port has no fingerprint); each port checks with the database its normaliser uses (Python `unicodedata`, JavaScript `\p{Cn}` beside `String.prototype.normalize`, the JVM's `Character.getType` beside `java.text.Normalizer`) and reports that Unicode version. |
| E15 | 2026-10-10 | §7 | Release provenance written down (new §7.1). The provenance anchor of a released file is the §1 anchor of the lower-case hex text of SHA-256(file bytes) under kind `code`; the inscription is that anchor's tagged Seal v3 PNG; the publisher's §7 fingerprint is published beside it and is not the inscribed seal. BRC-145 §7.4 described the ordinal as the seal "of the build's fingerprint (§6)", which admits several readings, none of them the construction the reference tooling has always used. The text now states that construction, so every existing sidecar record keeps its code and seal. Pinned by `vectors.json` → `inkan_image_example`. |
| E16 | 2026-10-10 | §3, §5 | The Seal v3 tables are published as a data file, `test-vectors/seal-v3-tables.json` (CC0), and pinned by its SHA-256 in new §3.0. The orderings that were stated only in the reference source are now normative text: the stream's block sequence, the palette draw-table expansion, the core-pattern order and bit mapping, the motif bit mapping and the order of `ORBIT_REPS`, the region-map encoding, the pixel order, the byte string that `rgb_sha256` hashes (§3.7) and the PNG palette order. Before this, neither BRC-145 nor this document determined a seal pixel on its own, and an engine with one palette value off by one unit passed every vector. New `seal-v3-coverage-vectors.json` reaches all 13 region maps × all 14 open-kind motifs, all 32 palette classes, all 6 core patterns and the second stream block. No pixel changed. |
| E17 | 2026-10-10 | §0, §5, §10 | Permanence rules adopted (new §0, P1–P6): which results are frozen, what an erratum may and may not do, versions as new names, new versions added beside v3 and never in its place, versions checked explicitly, and what happens if SHA-256 or secp256k1 weakens. §10 called the renderer "swappable", and nothing limited what an erratum could change; both are corrected. Revisions of this text are numbered from 1.0.1, and the SHA-256 of each is published in `SPEC-REVISIONS.md`. The `inkan-seal` PNG keyword is reserved for later seal versions (§5). No result changes. |
| E18 | 2026-10-10 | §4, §5, §8 | This document is now complete without BRC-145. It carries the reserved-kind table (new §4.1), stating that all 14 entries are normative, including `signer`, `vault`, `backup`, `account`, `collection`, `report` and `custom/24`, `custom/48`, `custom/72`, which public help text had called an optional example profile; the derivation steps in order, including the suffix test order (§4.2); the `iTXt` tag layout (§5); and the on-chain signed-record layout and reader rules (new §8.1), all of which only BRC-145 stated. §8 also states E13's record shape. The text is copied, not changed: no result differs. |
| E19 | 2026-10-10 | §1 | What a person types or pastes is text; only files and binary payloads are bytes. A tool MUST pass typed input as text, so it is NFC-normalised, and pass bytes only for a file or an input explicitly marked as binary. The reference command-line verifier, its tool-call interface and one Kotlin text entry point took typed text as bytes, so a decomposed `café` gave `ik191d9326afef7a…` there and `ik17288300319e48…` in the libraries and the web verifier, and the command line reported a genuine seal as a mismatch. Those tools did not conform to §1. They now pass typed input as text: the command line reads `--data` as text unless it names a file (`@file`), the tool-call interface's `text` argument is text, and the Kotlin text entry point goes through the text anchor. No library result or vector changes. `unicode-vectors.json` → `decomposed-cafe` pins the text result, and every port's suite runs it. |
| E20 | 2026-10-10 | §5 | The PNG is pixel-deterministic, not byte-deterministic: §5 called the canonical PNG "byte-deterministic across machines", but its compressed bytes depend on the deflate implementation (the JS port, for one, writes stored blocks). `png_bytes` in `seal-v3-vectors.json` is informative only; nothing may pin compressed PNG bytes. No port, gate or vector checked `png_bytes`, so no result changes. |
| **E21** | **2026-10-10** | **§7** | **The adopter-name profile of E6 is defined in terms that never change, and implementations MUST enforce it before hashing.** E6 required a "printable" name with no NUL and no `nkan/` prefix, but did not say what printable means, and no port enforced any of it: the name `nkan/v1` + NUL + 97 × `z` makes the fingerprint preimage begin with exactly `inkan/v1\0`, so one digest is both a valid fingerprint and a valid anchor, the case E6 exists to prevent. Printable now means well-formed (E4), no unassigned code point (E14), and no code point in U+0000–U+001F or U+007F–U+009F. Names that meet the profile keep their fingerprints. Implemented in the Python and JavaScript fingerprints, which refuse such a name before hashing (the Kotlin port has no fingerprint); `fingerprint-vectors.json` pins accepted and rejected names. |
| **E22** | **2026-10-10** | **§7** | **A fingerprint version is a positive integer, and version *n* is SHA-256 over this construction forever.** Any value was accepted: 0 and −1 produced digests, and a fraction was truncated by one port and written out by another (version 1.5 gave the version-1 digest in Python and a different one in JavaScript). Such versions MUST now be rejected. A fingerprint over another hash gets its own domain and a self-labelled text form, never a new version number. Versions 1, 2, 3, … keep their results. Implemented in the Python and JavaScript fingerprints; the Python verifier and command line now take the version as an explicit input (default 1), as the JavaScript port and the web verifier already did. `fingerprint-vectors.json` pins both. |
| **E23** | **2026-10-10** | **§8** | **A canary verifier MUST apply exact input rules, and report `MALFORMED` for a record that breaks one.** The canonical bytes, the integer range, the date and string forms, and high-S were each left to the implementation, and the Python and JavaScript verifiers gave different verdicts on the same signed record: a `seq` above 2^53 that a double cannot hold exactly (2^53 + 1, or a nanosecond timestamp such as 1760112000123456789) read `OK` in Python and `INVALID` in JavaScript, which rounds it; `2026-6-30T0:0:0Z` was fresh in Python and stale in JavaScript, hour 24 and second 60 the reverse; full-width digits were fresh in Python only; a statement holding an unpaired surrogate read `OK` in JavaScript and was mislabelled `UNSUPPORTED` in Python; and a key or signature written with a `0x` prefix was read in JavaScript only, one with spaces between its digit pairs in Python only. §8 now defines the canonical bytes exactly, requires `seq` and `block_height` in 0 to 2^53 − 1, one ASCII date form that must name a real time, well-formed strings and canonical wire bytes, fixes the form of the key and signature as plain hexadecimal text, and requires high-S to read `INVALID` (as every port already reports it, though BRC-145 never said so). Every record that meets the rules keeps its verdict; no canary has been published. Some records on which both verifiers agreed also read `MALFORMED` now, because they break the rules: a `seq` or `block_height` of 2^53 or more that a double does hold exactly (2^53 itself, 10^18, a nanosecond timestamp in whole seconds), or a negative one, which both read `OK`; wire bytes that are not the record's canonical bytes, which both read `OK`; and a `date` that is not a real time in the §8 form (30 February, month 13, year 0000, a space in place of `T`, `+00:00` or a fractional second in place of `Z`, blank space around it), which both read `STALE`. These records are the one exception §0 (P2) names. Implemented in the Python and JavaScript verifiers, which read a record either as an object (rules 1–3) or in its wire form (all four rules), and in the web verifier; the command line and the web verifier take a pasted or filed record as its wire form, ignoring only blank space around it. `canary-vectors.json` pins 33 cases, and both ports give every one its pinned verdict. |
| **E24** | **2026-10-10** | **§6** | **A presented image MUST be a verifiable PNG (new §6.1), and only the chunks listed there are allowed.** E12 listed forbidden chunks, and PNG keeps adding new ones: a genuine seal carrying `cICP` (a colour space) or `eXIf` (an orientation) verified GENUINE in the reference while a browser drew it in other colours or rotated. Nothing fixed which files a verifier accepts, so the reference accepted files browsers do not open as written (bad CRCs, no `IEND`, an unknown critical chunk, bytes after the end), and the web verifier, which let the browser decode the image, read GENUINE for files the reference rejected: an animated GIF named `.png`, RGBA, 16-bit, 4-bit-palette and interlaced images. §6.1 fixes the signature, the CRCs, an allow-list (`IHDR`, `PLTE`, `IDAT`, `IEND`, `tEXt`, `zTXt`, `iTXt`, `pHYs`, `tIME`), chunk order, the header (8-bit, truecolour or indexed, no interlace), the palette and image-data rules, and requires the verifier to decide on its own decode. Every honest re-encoding of a seal still verifies. Implemented in the Python verifier and in the web verifier, which now decodes the presented file itself under these rules, inflate included, and uses the browser only to display the result; `png-profile-vectors.json` pins 35 cases, and both give every one its pinned verdict. |

## Relationship to BRC-145

The anchor, codes, kinds, seal, fingerprint and on-chain provenance defined here were published as
**BRC-145** (*Registry-Free Typed Content Anchor with On-Chain Code Provenance*), merged to
`bsv-blockchain/BRCs` as `apps/0145.md` on **2026-08-02** (PR #187). BRC-145 is the citable public
form.

BRC-145 carries the corrections in its body text; it has no errata section or change note of its own.
The public record of each correction is the pull request to `bsv-blockchain/BRCs` that made it: two
pull requests, each titled as errata to BRC-145 and each stating what it corrects and why. This
document keeps them as dated errata (the table above) rather than folding them into its body.

- **PR #212**, merged **2026-08-10**: **E4** (a kind that cannot be encoded as valid UTF-8 is
  rejected, never substituted; BRC-145 §4), **E10** (an integer downscale checks every pixel of each
  block; §5 and §8) and **E12** (a presented PNG carrying a rendering-affecting chunk is rejected; §5
  and §8).
- **PR #243**, merged **2026-09-18**: **E2** (an unknown record version reads `UNSUPPORTED`; §7.3),
  **E6** (the adopter-name profile; §6), **E7** (the forgery-cost figures are dated to 2026 classical
  compute, with an erosion note; Security Considerations), **E11** (a record, key or signature that
  does not parse reads `MALFORMED`, never `INVALID`; §7.3) and **E13** (a verifier validates the
  record's shape before it reports `OK`; §7.3).

BRC-145 §7.3 therefore defines the same five statuses as §8 here: `OK`, `STALE`, `INVALID`,
`MALFORMED` and `UNSUPPORTED`. The second half of E2, that a verifier whose signature backend is
unavailable raises rather than reports a verdict, was in BRC-145's Security Considerations as merged.
So were E1 (the seven-field record table, §7.2), E3 (the kind derivation hashes the kind as
provided, §4), E5 (an unrecognised suffix leaves the tier at its default, §4) and E8 (trust decisions
use the full 32-byte anchor, §3). E9 retargets this document's own audit-evidence pointer and has no
counterpart in BRC-145; nor has E18, which copies BRC-145 text into this document.

The errata adopted on 2026-10-10 are not yet in BRC-145:

- **E14**: BRC-145 §2 and §6 say only "NFC", with no rule for unassigned code points.
- **E15**: BRC-145 §7.4 describes the code-provenance ordinal as the seal "of the build's
  fingerprint (§6)". Until BRC-145 carries the correction, §7.1 here is the only statement of the
  construction.
- **E16**: BRC-145 §5 leaves the seal's pixel-level construction out of scope and pins no seal
  pixels. §3 here and the tables file it pins are the complete definition.
- **E17**: BRC-145 §9 still calls the presentation "swappable". The permanence rules of §0 here
  govern.
- **E19**: BRC-145 §2 distinguishes text from raw octets without saying which a typed input is.
- **E20**: BRC-145 §5 still heads the PNG paragraph "Byte-deterministic PNG", while stating,
  correctly, that the invariant is the decoded pixels.
- **E21** and **E22**: BRC-145 §6 states E6's profile without defining "printable", and says only
  that `version` defaults to 1.
- **E23**: BRC-145 §7.2 and §7.3 leave the canonical escaping, the integer range, the date form and
  high-S unspecified.
- **E24**: BRC-145 §5 still gives E12's list of forbidden chunks, and no profile of the files a
  verifier accepts.

Every obligation that E1 to E13 add is in the published text, checked against `apps/0145.md` at
`bsv-blockchain/BRCs` master, not against the pull requests. These errata remain unreflected
upstream: E14, E15, E16, E17, E19, E20, E21, E22, E23, E24. Where the two documents differ, **this
document governs**. Apart from the errata just listed, no anchor, code, canonical seal or signature
differs between them.

---

(c) 2026 RexStarBSV. This specification is licensed under CC BY 4.0 (see LICENSE-SPEC).
Requested attribution: "Inkan Standard, RexStarBSV" (with the revision used, e.g. 1.0.1).
