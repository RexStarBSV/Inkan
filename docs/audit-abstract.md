# Audit abstract — the evidence behind SPEC §9

Public summary of the adversarial evidence the Inkan Standard's security profile rests on. The
full corpora (fuzz inputs, grind logs, brand-distance sweeps, per-run artifacts) are maintained
privately by the Licensor; every *claim* they support is stated in SPEC §9, and every *number*
below is reproducible from the shipped code and vectors.

## Seal v3 renderer audit (pre-freeze)

- **Distance floor:** any two distinct seals differ in ≥ 8 interior cells — proven from the
  extended-Golay [24,12,8] minimum weight and verified exhaustively over all 4096 code words per
  block; the floor is achieved (tight) in every cell profile.
- **Cross-port determinism:** 1500 randomized vectors rendered byte-identically (RGB level)
  across the Python, JavaScript, and Kotlin implementations; the pinned conformance suite
  (`test-vectors/seal-v3-vectors.json`, 95 sampled + constructed minimum-distance pairs) is the
  standing, re-runnable form of that evidence.
- **Perceptual floor:** in 12,000 adversarial "grind" attempts, T1 seals were never pushed below
  a ΔE 0.063 nearest-lookalike distance. ΔE figures are model outputs, not human measurements —
  SPEC §9's Honest Limits paragraph governs how much weight they may carry.
- **Avalanche:** in 400 trials, a 1-bit flip of the anchor moved ≥ 24 of the 48 cells every time
  (mean 36).
- **Brand distance:** palette selection is weighted (SPEC §3.4) after a colour-space sweep
  against a disfavoured third-party mark; avoidance is statistical, not a ban, and §9 states the
  consequence honestly.

## Standard-wide stability audit (2026-07-31, post-freeze)

Five adversarial review lenses (cryptographic longevity; specification semantics;
cross-implementation conformance drift; dependency and operational durability; a completeness
critic) reviewed the frozen standard end to end. Result: **no finding challenged the frozen
bytes** — the anchor construction, code format, and seal determinism survived all lenses. All
findings concerned prose, process, or logistics and were resolved as SPEC errata E1–E8, code
hardening in the reference implementation (fail-loud canary semantics, a dependency-free
signature-verification fallback differentially tested against the primary backend with zero
divergences over 1,270 cases), and operational fixes.

## How to check any of this yourself

Run the shipped gates: `python3 -m inkan_standard.verify selftest` (95/95 pinned vectors), `npm test`
under `js/`, `./gradlew test` under `kotlin/`. A conforming implementation reproduces the pinned
vectors; nothing in the audit asks for trust beyond that.
