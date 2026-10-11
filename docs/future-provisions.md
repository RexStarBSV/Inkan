# Inkan — forward provisions (10 / 15 / 20 / 100 years)

The standard is meant to outlive its tools, its formats, its hardware, and its authors. This document
records the architecture that makes that possible, the few irreversible decisions taken now to keep
the door open, and concrete reservations for presentations that do not exist yet — **audio, 3D,
haptic, and physical Inkans** among them.

## 0. The organizing principle

> **An Inkan is a permanent anchor and an open, versioned family of deterministic presentations.**

- The **anchor** is `SHA-256(glyph seed)` — 32 bytes, forever. It is what a receipt commits to and
  what every presentation is derived from. It never depends on how the Inkan is shown.
- A **presentation** is any deterministic function of the anchor: the visual seal today; audio, 3D,
  haptic, physical, or spatial seals tomorrow. Each carries a `presentation-type` and a version.

Everything that ages — displays, codecs, art direction, tiers, verification methods, even the hash —
lives in the presentation/extension layer and evolves by adding new versions beside the old ones,
without invalidating a single existing anchor or changing a single existing result (SPEC §0).
Getting the anchor right, and keeping the presentation layer open, is the whole game.

## 1. Irreversible decisions taken now (so 2045 stays open)

These are baked in before first publication because they cannot be changed afterward.

### 1.1 Self-identifying codes (hash agility)

A code is no longer bare hex. The canonical form is:

```
ik<v><hex>        e.g.  ik1a08e2d0f24b9f547...        (full)
ik<v><hex[:16]>   e.g.  ik1a08e2d0f24b9f547           (short, 16 hex)
```

- `ik` marks it as an Inkan code (human- and machine-recognisable).
- `<v>` is the **code format / hash version**. `1` = SHA-256 with glyph domain `inkan/v1`.
- When SHA-256 is eventually retired (post-quantum, or simply stronger), `ik2…` codes are
  **unambiguously distinguishable** from `ik1…` — the flaw that would otherwise cap Inkan at SHA-256
  forever. The raw 32-byte digest still drives v1 rendering; the prefix lives on the *string*.

**100-year note:** the single version digit gives 9 in-band generations — likely a century's worth.
Multi-digit extension is NOT `ik10…` as previously written: the hex body alphabet contains digits,
so `ik10…` is ambiguous between v1-with-leading-0-body and v10. If a tenth generation is ever
needed it MUST introduce a separator or a non-hex body alphabet (e.g. `ik10_<hex>` or a base32
body), defined at that time; v1-v9 parsers are unaffected either way.

### 1.2 Seed canonicalisation

- **Length-prefixed kind:** `INKAN_DOMAIN + u8(len(kind)) + kind + data`. Unambiguous for every kind
  and payload.
- **Unicode NFC normalisation:** string inputs (kind, and `str` data) are NFC-normalised before
  UTF-8 encoding, so "café" typed as `é` or as `e`+◌́ produce the *same* Inkan. Raw `bytes` data is
  never normalised (it is not text). Without this, visually-identical identifiers would fork.
- **Fingerprint domain** is likewise length-prefixed (`u8(len(adopter)) + adopter + "/inkan/v1\0"`),
  closing the same ambiguity in the per-adopter namespace.

### 1.3 Reserved extension grammar

Reserved now, additive forever. Each can only arrive with a new version (a new `SEAL_VERSION`, a new
record version, a new presentation type), so introducing it changes no existing result (SPEC §0):

- **Tiers:** `@t1 @t2 @t3` are defined; **`@t0` and `@t4`–`@t9` are reserved** for future security
  levels (e.g. a `@t0` "throwaway" tier, a `@t4` "sovereign" tier beyond 72 cells). They take
  effect only in a new `SEAL_VERSION`. Under Seal v3 they are ordinary open kinds at the default
  tier (SPEC §4, E5): the seal that `acme:vault@t4` draws today is a v3 seal, and it stays exactly
  that seal.
- **Presentation types:** `visual` is defined; **`audio`, `haptic`, `physical`, `spatial`, `motion`
  are reserved** (§3). A presentation is addressed as `<type>/v<n>` (e.g. `audio/v1`).
- **Signature agility:** the frozen v1 canary record carries NO `alg` field — `v: 1` DEFINES the
  algorithm as secp256k1-ecdsa (RFC 6979, low-S). The migration path is the record version: **v2
  introduces a mandatory `alg` field inside the signed bytes** (a post-quantum scheme — lattice or hash-based — slots in
  when Shor makes ECDSA untrustworthy; the more urgent migration, since Grover leaves SHA-256 usable
  but Shor breaks ECDSA outright). SPEC §8 (E2) already obliges every v1 verifier to surface an
  unknown `v` as UNSUPPORTED, so v2 records degrade loudly, never as false INVALID.
- **Record-format discipline (all future signed-record versions):** every field MUST be an
  integer or a string — never a float, boolean, or nested structure. Sorted-key compact-JSON
  canonicalisation is byte-deterministic across languages ONLY under that discipline; a single
  float field would fork signatures between implementations.

## 2. Evolvable layers (design the door, build later)

- **Renderer generations:** a new renderer is a new `SEAL_VERSION` (v4, v5, …) added beside v3, never
  a replacement for it. Every v3 seal keeps its pixels, every conforming verifier keeps v3, and a
  tagged PNG of a later version names it with an `inkan-seal` keyword (SPEC §0, P4). Rule: two
  surfaces comparing seals must use the same `SEAL_VERSION`; a mismatch must refuse or renegotiate,
  never silently show different pixels.
- **On-chain permanence:** inscribe the spec, the conformance vectors, and the verifier on BSV,
  versioned, so in 2125 the standard verifies itself from the chain with no company, server, or domain
  required to survive. This is the most durable form of the standard.
- **Zero-knowledge verification:** the digest-anchor is ZK-friendly. Reserve a proof path to show
  "this seal's code is in an approved set" *without revealing which* — serving selective-disclosure
  use cases.
- **Interoperability:** Inkan seals any opaque payload, so it is the visual/sensory layer for whatever
  identity primitives dominate later — DIDs, verifiable credentials, AI-agent keys, IoT device
  identities, real-world-asset tokens, C2PA provenance. A mapping convention (`did:…` → Inkan) is
  reserved.
- **Governance & succession:** a maintenance and namespace-registration process that survives any one
  company — ideally an **on-chain registry** for reserved kinds and versions.
- **Format-agnostic tagging:** the self-describing tag (`inkan-code` + `inkan-kind`) is defined
  abstractly; each carrier format (PNG `iTXt` today; a future image/audio/3D container tomorrow)
  binds the code by its own native metadata mechanism.

## 3. Concrete presentation reservations

All of these are deterministic functions of the **same 32-byte anchor**, so they are cross-verifiable
against each other and against the visual seal. None is built yet; each has a reserved type and a
sketch precise enough to implement without re-litigating the architecture.

### 3.1 Audio Inkan — `audio/v1`

**Why:** verification by ear — voice assistants, phone-based confirmation, the blind and low-vision,
and ambient "identity chimes" when a payment or a signer connects.

**Sketch:** the anchor drives a short (~1.5 s) deterministic motif.
- **Structure → pitch sequence.** The interior cells map to notes on a fixed scale (a pentatonic
  scale avoids dissonance and is culture-neutral); the tier sets the number of notes (t3 short, t1
  long/rich), mirroring the visual entropy tiers.
- **Palette class → timbre.** The 32 colour classes map to 32 instrument/timbre presets, so the
  "colour" of a seal is audible as its tone.
- **Kind/symmetry → rhythm.** The frame motif and symmetry order `k` set the rhythmic pattern, so a
  `signer` chime is rhythmically distinct from an `address` chime.
- **Determinism:** rendered from integer tables to a canonical PCM/OGG, byte-stable like the PNG.
- **Comparison:** two audio Inkans are "the same" iff their anchors match; a human compares by ear as
  they compare seals by eye across the air gap.

### 3.2 3D / physical Inkan — `physical/v1` (relief) and `spatial/v1` (full mesh)

**Why:** this closes the loop — an *inkan* is literally a physical seal stamp. A 3D Inkan is a
real object: a stamp face, a signet, an engraved token, a keepsake for a vault or an inheritance.

**`physical/v1` — a height-map relief (stamp face / engraving):**
- Take the visual seal's cell grid; map each cell state to a **height** (ground = base plane,
  accents = raised tiers, core = deepest or highest). The result is a radial relief.
- Emit **STL / 3MF** for 3D printing, or a depth map for CNC / laser engraving. A red-ink physical
  stamp uses only the binary ink/no-ink layer (accent-1 vs ground) — the classic *hanko* look.
- **Determinism:** integer height table → mesh; the same anchor prints the same object anywhere.

**`spatial/v1` — a full 3D structure (AR / VR / display):**
- Extrude the radial rings into concentric 3D bands; symmetry order `k` becomes rotational geometry;
  the core becomes a central solid. Viewable/rotatable in a headset; verifiable by matching the
  anchor.
- Reserve for spatial computing platforms; the anchor and tier semantics carry over unchanged.

### 3.3 Haptic Inkan — `haptic/v1`

**Why:** confirm identity by touch on a watch or phone in a pocket, and accessibility for deaf-blind
users.

**Sketch:** the anchor drives a vibration pattern — cells → a sequence of pulse
lengths/intensities (a richer Morse), tier → pattern length, kind → a leading/trailing signature
pulse. Short enough to feel in ~1 s, deterministic, comparable by repetition.

### 3.4 Motion Inkan — `motion/v1` (reserved)

An animated reveal for screens/anti-screenshot: the seal assembles along a deterministic path derived
from the anchor. Reserved; low priority, listed so the type isn't reused.

## 4. What is implemented now vs reserved

| Item | Status |
|---|---|
| Self-identifying `ik1` code | **implemented** (v1.0) |
| Length-prefixed kind + Unicode NFC | **implemented** (v1.0) |
| Length-prefixed fingerprint domain | **implemented** (v1.0) |
| Reserved tiers `@t0`,`@t4`–`@t9`; presentation types; `alg` field | **reserved / documented** |
| Visual seal `visual/v3` | shipped |
| Audio / 3D / physical / haptic / spatial / motion | **reserved, specced here; not built** |
| On-chain spec+verifier, ZK path, governance registry, interop mappings | **reserved / roadmap** |

Nothing in §2–§3 requires an anchor change to add later — that is the point of §0–§1. Build any of it
when the need is real; the standard already accommodates it.
