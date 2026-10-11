# Inkan — Kotlin port

The Kotlin port of the Inkan Standard: the anchor, the `ik1` codes and the Seal v3 renderer, with no
fingerprint and no canary. Python is the reference implementation; this port and the JavaScript
port reproduce its output byte for byte for everything they implement. It lives here so the
standard is **self-contained**: every implementation and every conformance gate is in this
repository, provable from this repository alone.

## Run the conformance gate

```sh
cd kotlin && ./gradlew test       # the committed wrapper; resolves ../test-vectors/*.json
```

Each suite reads its vector files from `../test-vectors/`; the seal and anchor suites can be pointed
elsewhere with an environment variable (see the test sources). Needs a JDK 17; the wrapper fetches
Gradle 8.7 on first use (`--offline` once it is cached).

The gate passes only if this port reproduces, byte for byte, every pinned vector for what it
implements, including the constructed minimum-distance worst-case pairs; Gradle's exit status is the
result.

## Files, and which are normative

| File | Normative? | What |
|---|---|---|
| `SealV3.kt` | **yes** | the seal renderer (`SEAL_VERSION = 3`, Golay [24,12,8], integer-only) |
| `SealTables.kt` | **yes** | the frozen integer tables (palette, regions, orbits, core patterns) |
| `Inkan.kt` | **yes** | the anchor: domain `inkan/v1\0`, length-prefixed kind, NFC, SHA-256; the `ik1` codes (`code`, `shortCode`, `codeToDigestHex`) |
| `Encoding.kt` | no | shared `Hex`/`Base64Url` helpers, carried verbatim (see below) |
| `SealV3ConformanceTest.kt` | — | the seal parity gate (`seal-v3-vectors.json`) |
| `SealV3CoverageTest.kt` | — | the tables file and the coverage vectors (`seal-v3-tables.json`, `seal-v3-coverage-vectors.json`) |
| `AnchorConformanceTest.kt` | — | the anchor and kind parity gate (`vectors.json`) |
| `NormalizationVectorsTest.kt` | — | text normalisation in the anchor (`normalization-vectors.json`, `unicode-vectors.json`) |
| `UnicodeVectorsTest.kt` | — | refusal of unassigned code points (`unicode-vectors.json`) |
| `ProvenanceTest.kt` | — | the release provenance example (`vectors.json`, `inkan_image_example`) |

The engine has **no third-party runtime dependencies** — only the JDK standard library. The test-only
dependencies exist solely to read the vector JSON. Keep it that way: a 100-year reference
implementation must not be able to rot because a dependency did.

## The anti-drift invariant

**This copy is canonical.** An application that vendors these files changes exactly one thing: the
`package` declaration. (The four engine files are Apache-2.0, part of the verification path named in
../NOTICE, so vendoring them into any product is permitted; the tests and build files are BSL 1.1,
and the Gradle wrapper is Gradle's own Apache-2.0 — see ../LICENSING.md.) That line is the only
permitted divergence — if a vendored copy disagrees on anything else, this one wins, and the
vendored copy is the one that must be re-synced.

One exception is permitted, for a platform reason: a product that runs on Android before 8.0 (API
26) cannot load `java.util.Base64`, so its copy may replace that codec with the Kotlin standard
library's, in `Encoding.kt` (the `Base64Url` object, plus a standard-alphabet `Base64Std`) and in the
one `SealV3.kt` line that decodes the region maps. Its output is the same. Nothing else may differ.

Check a vendored copy for drift (everything except the `package` line must match byte-for-byte,
including the licence header above it):

```sh
for f in SealV3 SealTables Inkan Encoding; do
  diff <(grep -v '^package ' /path/to/vendored/$f.kt) \
       <(grep -v '^package ' kotlin/src/main/kotlin/inkan/$f.kt) \
    && echo "$f.kt OK" || echo "$f.kt DRIFTED"
done
```

The check is intentionally strict about comments as well as code: a comment that describes a retired
code path is how a reader is misled a decade from now, and the vectors cannot catch that.

## Provenance

Vectors are generated **only** by the Python reference implementation
(`python/tools/gen_seal_v3_vectors.py`); no port ever regenerates them. The engine is original work
and shares no code, structure, or output with LifeHash.
