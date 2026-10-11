<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 RexStarBSV -->
# inkan-standard

The JavaScript port of the [Inkan Standard](https://github.com/RexStarBSV/Inkan)
([BRC-145](https://github.com/bsv-blockchain/BRCs/blob/master/apps/0145.md)): dependency-free,
synchronous ES modules for Node and the browser. It computes Inkan anchors and `ik1` codes, draws
Seal v3 seals, computes tamper fingerprints and verifies warrant canaries, held to the standard's
shared conformance vectors.

```sh
npm install inkan-standard
```

```js
import { inkanSeed, sha256, bytesToHex, sealPng, fingerprintHex, canaryStatus } from 'inkan-standard'

const digest = sha256(inkanSeed('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 'address'))
const code = 'ik1' + bytesToHex(digest)          // the ik1 code
const png = sealPng(digest, 'address')            // the canonical seal, as PNG bytes
const fp = fingerprintHex(fileBytes, 'myapp', 1)  // tamper fingerprint
const state = canaryStatus(recordText, signatureHex, publicKeyHex)  // "OK", "STALE", "INVALID" or "MALFORMED"
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

The vectors are in the repository's [`test-vectors/`](https://github.com/RexStarBSV/Inkan/tree/master/test-vectors),
and the normative text is [`SPEC.md`](https://github.com/RexStarBSV/Inkan/blob/master/SPEC.md). In a
checkout of the repository, `npm test` in `js/` runs every suite against them.

Canary verification is exported as `canaryVerify` / `canaryStatus` / `canaryIsFresh` (from
`inkan-standard`, or the unprefixed API at `inkan-standard/canary`), and Seal v3 as `sealRgb` / `sealPng` / `sealFields`.

**Not in this port:** reading an `ik1` code back to its anchor, and checking a presented seal image
(SPEC §6). This package writes the `ik1` code into a seal's PNG tag but has no reader for it, and
there is no JavaScript equivalent of the Python reference's `verify.py`: no PNG decoder, no
`verify_seal`, no `canonical_seal`. A JavaScript caller can produce and check an anchor, but cannot
verify a seal image it was handed; use the Python reference (`pip install inkan-standard`) or the
[web verifier](https://github.com/RexStarBSV/Inkan#check-an-inkan-in-your-browser) for that.

## Licence

All of it is original work implementing the Inkan Standard; there is no third-party code in this
package. Everything in it (the `src/` modules, `index.d.ts`, this README and `package.json`) is
**Apache-2.0**, as `NOTICE` and `LICENSE-VERIFY` state: verify Inkan codes and seals, and generate
your own, in any product, forever. The rest of the Inkan repository is multi-licence and most of it
is not Apache-2.0; see [LICENSING.md](https://github.com/RexStarBSV/Inkan/blob/master/LICENSING.md).
