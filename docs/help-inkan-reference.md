# Inkan — Technical Reference

For developers and auditors: the architecture, the trust and threat model, the formats, and how to
verify everything without trusting us. Companion to the plain-language *Quick Start*. It assumes you
are comfortable with SHA-256, secp256k1 ECDSA, and the BSV transaction model.

The register is consistent throughout: **claims come with their limits.** Every mechanism below ends with an
explicit *Boundary:* naming what it does **not** cover.

---

## 1. Architecture

**What Inkan is.** Inkan is a trust-seal toolkit. It provides three independently-verifiable signals:

| Signal | Answers | Module |
|---|---|---|
| **Seal** (visual mark) | *"is this the genuine mark for this data?"* | `inkan_standard.seal` |
| **Tamper fingerprint** | *"is this artifact unaltered vs a committed hash?"* | `inkan_standard.fingerprint` |
| **Warrant / compromise canary** | *"is the operator uncompromised and un-coerced?"* | `inkan_standard.canary` |

**The organising idea: anchor + presentations.** An Inkan is a **permanent anchor** (a digest) plus
an open, versioned family of **deterministic presentations** (the visual seal today; audio/3D/haptic
are *reserved*, not built — see §5). A new presentation, or a new version of one, is added beside
the existing ones: it never invalidates an anchor and never changes an existing seal (SPEC §0). The
image is never trusted; **the anchor is**.

- **Anchor:** `anchor = SHA-256(seed)`, where
  `seed = "inkan/v1\0" || u8(len(kind_utf8)) || kind_utf8 || data`. `kind`, and text `data`, are
  NFC-normalised before UTF-8; raw `bytes` are used verbatim. The kind is length-prefixed (`≤ 255`
  bytes) so the kind/data boundary is unambiguous. (`inkan_standard.seed.inkan_seed`.)
- **Code:** the self-identifying string form. `full = "ik1" + hex(anchor)`;
  `short = "ik1" + hex(anchor)[:16]` (64-bit label for filenames/display). `ik` marks an Inkan code;
  the digit is the hash-version — a future migration is `ik2…`, and a conforming reader must **reject**
  a version it doesn't implement rather than assume SHA-256.

**Implementations.** Python (`python/inkan_standard/`) is the normative reference. A dependency-free JavaScript
port (`js/`, the npm package `inkan-standard`) is proven byte-exact by `npm test` against the
shared vectors. A Kotlin port (`kotlin/`) is proven byte-exact against the same vectors by
`cd kotlin && ./gradlew test` (JDK 17), for the parts it implements. An adopting application can
vendor an in-sync copy under the `inkan/v1` anchor domain so seals render byte-identically offline.
The Python verification path is published on PyPI as `inkan-standard` (import name `inkan_standard`).

**What each port covers, since "three-port parity" is easy to over-read.** Python implements every
layer. JavaScript implements every layer *except* reading an `ik1` code back and presented-image
verification. Kotlin implements the anchor, the `ik1` codes (including `codeToDigestHex`, which
reads a code back to its anchor) and the seal only — no fingerprint and no canary. So the parity
claim is three ports for §1 and §3, two for §2 (Python and Kotlin; JavaScript writes a code into the
seal's PNG tag but has no reader), two for §7 and §8 (Python and JavaScript), and **one** for §6.
An Android or Node integration that must verify a user-supplied seal image has no reference port to
copy and should use the Python reference or the verifier page.

**Provenance (stated plainly).** The anchor, the fingerprint, the canary, and **Seal v3** are original
work. The **legacy v1 seal was LifeHash** (© 2019–2022 Blockchain Commons, BSD-2-Clause-Patent); it was
**deleted outright on 2026-07-09** — no Inkan seal had ever been published, so nothing was lost and no
attribution obligation carries forward. Seal v3 is **not** a clean-room reimplementation of LifeHash
and reproduces none of its code, structure, or output; it is an independent design. Inkan is licensed
by function, mapped file by file in `LICENSING.md` — the spec and public docs CC BY 4.0, the
conformance vectors CC0, the verification path Apache-2.0, the embedded font SIL OFL 1.1, the Gradle
wrapper Gradle's own Apache-2.0, the Inkan mark not licensed at all, and everything else **BSL 1.1**
with Change License **MIT** on **2030-07-09** (that MIT is a future conversion, **not** a grant made
today).

## 2. Trust & threat model

**The seal (visual mark).** Seal v3 (`inkan_standard.seal`, `SEAL_VERSION = 3`) maps the 32-byte anchor to a
224×224 indexed image with integer-only tables, so all ports agree byte-for-byte. Interior cells hold
2 bits each from **bit-interleaved extended Golay [24,12,8]** blocks (cell profiles 24/48/72), which
makes perceptual separation a *theorem*: any two distinct seals differ in **≥ 8 cells** by
construction (Golay minimum weight, verified tight in tests). Every field is drawn from a
domain-separated SHA-256 counter stream, so a one-bit input change re-randomises the mark
(coarse-collision ≈ 2⁻¹⁶). The **kind** selects rotational symmetry and a 6-bit frame motif and is
*never* digest-derived, so a `signer` seal cannot be dressed as an `address` seal. The 32-class
palette is separated primarily by lightness under Brettel–Viénot–Mollon CVD simulation.
*Boundary:* the seal authenticates the binding between `(data, kind)` and an image — nothing about
whether the *data* is trustworthy. Perceptual/CVD separation is modelled (ΔE), **not measured on
humans** — no human study has run, so no "phishing-proof" or accessibility claim is made. Low-tier
(24-cell) seals have **findable perfect collisions by design**; the anchor, not the image, is the
trust root, and value-at-risk kinds must use the high tier.

**The anchor & code.** Identity is `SHA-256` over a domain- and length-separated seed; the code is a
self-identifying, hash-agile presentation of it.
*Boundary:* this gives determinism and integrity only. A code commits to the exact `(data, kind)` —
it makes no statement about that data's truth or authority. The 16-hex short code is a ~64-bit
convenience label, auditable by recomputation, **not** a trust root; compare full anchors for
decisions.

**Tamper fingerprint.** `fingerprint = SHA-256(u8(len(adopter)) || adopter || "/inkan/v1\0" ||
payload)` (`inkan_standard.fingerprint`). The per-adopter, length-prefixed domain namespaces each project so
identical payloads yield distinct fingerprints while sharing one scheme.
*Boundary:* a fingerprint proves an artifact matches **a hash you already hold** — it does not, by
itself, tell you the *published* hash is authentic. That requires an out-of-band trust root (a release
signature, the on-chain reference). A fingerprint that matches a hash an attacker chose proves only
that the attacker is self-consistent.

**Warrant / compromise canary.** A canonical-JSON record `{v, domain, seq, date, block_height,
block_hash, statement}` signed with secp256k1 ECDSA over `SHA-256(canonical_bytes)`
(`inkan_standard.canary`). A recent block height/hash is an anti-backdate freshness proof (the canary can't be
pre-signed before that block existed). `status()` returns `OK` (valid signature **and** fresh,
default window 35 days), `STALE` (valid but expired), `INVALID` (bad signature) or `MALFORMED` (the
record, key or signature is not in the required form, so no check ran); an unknown record version
raises, and the verifier reports it as `UNSUPPORTED`. **Absence, staleness, or a failed signature
is the warning.**
*Boundary:* a canary detects *interruption*, not truth. (The legal treatment of warrant
canaries varies by jurisdiction and is unsettled in some; operators should take local advice
before relying on one.) Silence can mean coercion, censorship, an
operator who was merely slow, or a lost key — the mechanism cannot distinguish these. A sufficiently
coerced operator may be compelled to keep signing; only a refusal or a lapse signals. The trust root is
the binding between the operator and the published key, which Inkan does **not** establish for you. The
freshness window bounds detection latency: a compromise inside the current window is invisible until it
lapses.

**Optional on-chain anchoring.** `inkan_standard.anchor` can broadcast an *already-signed* canary to an
immutable, timestamped BSV output (`OP_RETURN` carrying marker `INKANC1`, the canonical record, the
DER signature, and the pubkey — fully self-verifying off-chain). It goes through a BRC-100 wallet
(loopback `127.0.0.1:3321`) which only *funds* the transaction; **the trust root is
unchanged — Inkan never signs the canary here**, and the parity-tested core has zero dependency on
this module. It runs a first-action handshake and **hard-refuses `createAction` on any network but
testnet unless `allow_mainnet=True`** is passed explicitly. It is **opt-in and off by default**
(record-only posture).
*Boundary:* on-chain anchoring proves *existence-at-or-before-a-time*, not correctness — a committed
falsehood is a timestamped falsehood. It also introduces a liveness dependency on the wallet and a
chain index; verification itself never requires it and works fully offline.

**The verifier's self-test.** `inkan_standard.verify.selftest` reproduces the pinned cross-language vectors
before the engine is allowed to judge anything; the bundled web verifier runs it on load.
*Boundary:* the self-test proves *this engine reproduces the standard's vectors*. It does not prove the
standard is well-designed, and it is only as trustworthy as the vectors it checks against — pin the
vectors (and the verifier) from a source you trust, or from the chain, not from the same party
presenting the seal.

**Fail-loud discipline.** For a verification library the central rule is that **"could not verify" is
not "verified as invalid."** Inkan never swallows an exception to manufacture a verdict: a check that
could not be *performed* (unreadable image, missing crypto backend) is a distinct, typed result from a
check that *failed*. Audited state: **zero silent handlers** (Python and JS, 2026-07-11), enforced by
`tools/check_no_silent_handlers.py`.
*Boundary:* this is a correctness-of-reporting property, not a proof that every verdict is right — it
guarantees the caller can tell "unknown" from "invalid," not that the underlying crypto is unbreakable.

## 3. Protocols & formats

- **Glyph seed / anchor:** `"inkan/v1\0" || u8(len(kind)) || kind || data`; anchor = its SHA-256.
  Permanent (`inkan/v1`, code `ik1`). Changing it is a new namespace, never a revision.
- **Seal v3 render:** field stream `SHA-256(anchor || "inkan/seal/v3" || ctr_be32)`, rejection-sampled;
  Golay-coded interior cells; weighted 32-class CVD palette; constant-weight core (2 of 4 cells);
  6-bit frame motif; `C_k` symmetry (`k = 1…7`). Canonical PNG is 8-bit indexed, chunks exactly
  `IHDR/PLTE/IDAT/IEND`, **no ancillary chunks** (no author/software/time/EXIF — deliberately carries
  nothing identifying). The cross-language invariant is **RGB pixel content**, not compressed bytes.
- **Kinds — open, no registry:** any UTF-8 string, conventionally `[namespace:]name[@tier]`. The 14
  reserved kinds are all part of the standard (SPEC §4.1): `""` (generic), `identity`, `account`,
  `address`, `vault`, `signer`, `contract`, `code`, `report`, `collection`, `backup`, `custom/24`,
  `custom/48` and `custom/72`; every implementation resolves them identically. Unreserved kinds derive
  `(cells, k, motif)` from `SHA-256("inkan/kind/v1\0" || kind)`; the `@t1|@t2|@t3` suffix picks the
  tier (`cells ∈ {72, 48, 24}`, default t2). Because the full kind string is in the anchor, namespaces
  never collide and no registry is needed.
- **Tamper fingerprint:** `SHA-256(u8(len(adopter)) || adopter || "/inkan/v1\0" || payload)`.
- **Canary:** canonical JSON (sorted keys, no whitespace); secp256k1 ECDSA (RFC 6979, low-S) over its
  SHA-256; reference signer uses `bitcoinx`, any secp256k1 library interoperates. A signature-algorithm
  identifier is *reserved* for a future post-quantum migration.
- **On-chain canary output:** `OP_RETURN INKANC1 <canonical-record> <DER-sig> <pubkey>` (self-verifying
  off-chain via `inkan_standard.anchor.parse_canary_script` → `inkan_standard.canary.status`).

## 4. Verifying (don't trust us)

Everything an Inkan asserts is recomputable from public inputs. Three forms, one engine, identical
results:

1. **Self-test first.** `python -m inkan_standard.verify selftest` reproduces the pinned vectors; do this before
   trusting any verdict. The web verifier self-tests on load.
2. **Seal.** `inkan_standard.verify seal --data <d> --kind <k> --seal shown.png` — recomputes the canonical
   seal, decodes the presented PNG (all five scanline filters supported, so a re-encode still passes),
   and compares pixel-for-pixel. Re-encoding and **integer upscales** are tolerated; a resampled,
   cropped, or differently-sized image is **rejected** rather than coerced. Embedded PNG tags
   (`iTXt inkan-code`/`inkan-kind`) are treated as an **untrusted hint**, cross-checked, never believed.
3. **Fingerprint.** `inkan_standard.verify fingerprint --payload @f --adopter <a> --expect <hex>`.
4. **Canary.** `inkan_standard.verify canary --record @c.json --sig <hex> --pubkey <hex>` (signature check
   needs `bitcoinx`; it degrades with a clear message if absent, per the fail-loud rule). The record
   must be its exact published canonical bytes (SPEC §8): a reformatted copy reads `MALFORMED`, and
   only blank space around it is ignored. `--sig` and `--pubkey` are plain hex, with no `0x` prefix
   and nothing between the digits.
5. **Reports.** `--report file.md|.json` writes a deterministic, re-runnable evidence record (inputs,
   verdict, timestamp, standard version, every evidence hash). Exit code `0`/`1` drops into CI.
6. **Web / on-chain.** `web/inkan-verify.html` is one self-contained file (engine, styles, logic
   inlined; **generated** by `js/tools/build_web_verifier.py`, so it cannot drift from the reference).
   It runs offline from `file://`, from a static host, or bundled inside an application. It is also
   inscription-ready (its current size and SHA-256 are in the README); pinning it on-chain makes
   verification permanent and censorship-resistant. **Status: documented, not broadcast** —
   inscribing is a deliberate, funded, operator-initiated action.
7. **Parity.** An implementation conforms iff it reproduces `test-vectors/seal-v3-vectors.json`
   (sampled fields + RGB SHA-256 + constructed minimum-distance pairs) and `test-vectors/vectors.json`
   (fingerprint, canary, glyph). Regenerate vectors only via `python/tools/`.

## 5. Shipped state (honest)

- **Shipped & tested:** the anchor/code, Seal v3 render + verify, fingerprint, canary sign/verify/
  status, the CLI and generated web verifier, and the optional on-chain **anchor** module (testnet-
  guarded). Python reference + JS port are byte-parity-proven.
- **Verified:** the Kotlin port's parity, by its Gradle test suite on JDK 17 against the shared
  vectors.
- **Example values, frozen formats:** `test-vectors/vectors.json`'s fingerprint/canary values are
  **examples**, not issued values. Its canary is signed with a deliberately public test key
  (`privkey_hex` is the byte `01` repeated 32 times) so anyone can reproduce the signature; never
  use that key, or any key published in a vector file, for a real canary. No live canary has been
  published yet; the first will be signed with the publisher's own key. The verifier page's own
  fingerprint and `ik1` code are published in the README and in its sidecar file. The §3–§4 formats
  are frozen.
- **On-chain verifier inscription:** inscription-ready, **not broadcast**.
- **Issuance catalog:** not built and not published. No catalog of issued Inkans exists in this
  distribution, and all on-chain writes are gated on explicit operator action.
- **Reserved, not built:** audio/3D/haptic/physical presentations, and the post-quantum signature-
  algorithm identifier, are reserved in `docs/future-provisions.md` — anchors are forward-compatible
  with them, but no such presentation exists today.

## 6. Reading the source

- `python/inkan_standard/seed.py` — the glyph seed, anchor, and `ik1` codes (start here).
- `python/inkan_standard/seal.py` + `seal_tables.py` — Seal v3 renderer (Golay coding, palette, region tables);
  The design evidence, measurements and adversarial audit behind the seal are retained privately.
- `python/inkan_standard/fingerprint.py` — tamper fingerprint + the clean-metadata PNG writer.
- `python/inkan_standard/canary.py` — warrant/compromise canary (record, sign, verify, freshness, status).
- `python/inkan_standard/anchor.py` — optional BRC-100 on-chain anchoring (testnet-guarded, opt-in).
- `python/inkan_standard/verify.py` — the independent verifier + CLI + self-test + savable reports.
- `js/src/` (npm `inkan`) — byte-parity JS port; `web/inkan-verify.html` — the generated verifier.
- `SPEC.md` — the normative, language-agnostic standard; `standard/inkan-standard.html` — illustrated.
- `test-vectors/` — cross-language parity vectors. `docs/` in this distribution is the public
  documentation set (see `LICENSE-SPEC` for the exact list); design and lineage material is
  maintained privately by the Licensor.
