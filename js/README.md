# inkan (JavaScript port)

Dependency-free, synchronous, browser + node (ESM). Implements **[../SPEC.md](../SPEC.md)**, held to
the shared vectors in `../test-vectors/`:

```
npm test        # every suite in test/, against the shared vectors
```

## What's here

| Module | Feature | Parity |
|---|---|---|
| `src/seed.js` | glyph seed + anchor (`inkan/v1` domain, NFC, length-prefixed kind; text with an unassigned code point is refused) | `vectors.json`, `normalization-vectors.json`, `unicode-vectors.json` |
| `src/seal.js` | **Seal v3** renderer (float-free, Golay-coded, weighted palette) | `seal-v3-vectors.json` RGB SHA-256, `seal-v3-coverage-vectors.json` |
| `src/seal_tables.js` | the frozen integer tables (palette, regions, kinds, weights) | `seal-v3-tables.json` |
| `src/fingerprint.js` | per-adopter tamper fingerprint (`SHA256(domain_prefix ‖ payload)`) | `vectors.json`, `fingerprint-vectors.json` |
| `src/canary.js` | warrant-canary verification: the record's input rules, the signature and freshness | `vectors.json`, `canary-vectors.json` |
| `src/secp256k1.js` | pure-JS secp256k1 ECDSA signature verification, used by the canary | the canary vectors |
| `src/sha256.js` | pure-JS synchronous SHA-256 | FIPS 180-4 vectors |
| `src/index.js`, `src/index.d.ts` | the entry points, and their TypeScript declarations | — |

All of it is original work implementing the Inkan Standard; there is no third-party code in this
directory. Licensing: everything in `js/src/` (the `.js` modules and `index.d.ts`) is **Apache-2.0**
(see ../NOTICE and ../LICENSE-VERIFY) — verify Inkan codes and seals, and generate your own, in any
product, forever. The rest of the repository is multi-licence and most of it is not Apache-2.0; see
../LICENSING.md.

Canary verification is exported as `canaryVerify` / `canaryStatus` / `canaryIsFresh` (`src/index.js`,
or the unprefixed API at `inkan/canary`), and Seal v3 as `sealRgb` / `sealPng` / `sealFields`.

**Not in this port:** reading an `ik1` code back to its anchor, and checking a presented seal image
(SPEC §6). This package writes the `ik1` code into a seal's PNG tag but has no reader for it, and
there is no JS equivalent of `python/inkan_standard/verify.py`: no PNG decoder, no `verify_seal`,
no `canonical_seal`. A JS caller can produce and check an anchor, but cannot verify a seal image it
was handed; use the Python reference or the web verifier for that.
