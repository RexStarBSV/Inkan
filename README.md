# Inkan

An **Inkan** is a short code and a small picture, called a seal, computed from a piece of data such
as a payment address, a public key or a downloaded file. Anyone can recompute both from the data,
and the same data always gives the same seal, so a swapped-in lookalike is easy to notice and the
verifier can confirm the genuine one exactly. This repository contains the Inkan Standard, which
defines how they are computed; a web page that checks and creates Inkans in your browser; and
libraries in Python, JavaScript and Kotlin for developers.

The Inkan Standard is published as
[BRC-145: Registry-Free Typed Content Anchor with On-Chain Code Provenance](https://github.com/bsv-blockchain/BRCs/blob/master/apps/0145.md),
in the BSV Blockchain BRCs repository. This repository holds its current text, test vectors and
reference implementations; [The standard](#the-standard) explains how the two texts relate.

<table>
  <tr>
    <td align="center" width="33%"><img src="examples/seals/bitcoin.png" width="140" alt="The Inkan seal of the word Bitcoin"><br><b>Bitcoin</b><br><sub>the word "Bitcoin", generic kind</sub><br><code>ik102cc6b509344e5f6</code></td>
    <td align="center" width="33%"><img src="examples/seals/bsv.png" width="140" alt="The Inkan seal of the word BSV"><br><b>BSV</b><br><sub>the word "BSV", generic kind</sub><br><code>ik1338e1374d010cc78</code></td>
    <td align="center" width="33%"><img src="examples/seals/inkan.png" width="140" alt="The Inkan seal of the word Inkan"><br><b>Inkan</b><br><sub>the word "Inkan", generic kind</sub><br><code>ik12f16016e5dd60785</code></td>
  </tr>
  <tr>
    <td align="center"><img src="examples/seals/address.png" width="140" alt="The Inkan seal of a payment address"><br><b>Payment address</b><br><sub>a BSV address, kind <code>address</code></sub><br><code>ik112cf1aaca7ef5079</code></td>
    <td align="center"><img src="examples/seals/identity.png" width="140" alt="The Inkan seal of an identity key"><br><b>Identity key</b><br><sub>a public key, kind <code>identity</code></sub><br><code>ik143fa06e1de2c970b</code></td>
    <td align="center"><img src="web/inkan-verify.html.inkan.png" width="140" alt="The Inkan seal of this repository's verifier page"><br><b>This verifier page</b><br><sub>its SHA-256, kind <code>code</code></sub><br><code>ik1a99ce448c3f0b47e</code></td>
  </tr>
</table>

Each seal above is computed from the data named under it, and the verifier draws exactly the same
seal and `ik1` code from the same data and kind, on every device. The three words share one kind,
so what tells their seals apart comes from the data alone.

<details>
<summary>The data behind each seal, to check them yourself</summary>

| Example | Data | Kind | Full `ik1` code |
|---|---|---|---|
| Bitcoin | `Bitcoin` | (generic) | `ik102cc6b509344e5f63e188469db640fb98cd6f58e63f3465423c1b4f22fecbe53` |
| BSV | `BSV` | (generic) | `ik1338e1374d010cc788890f95fc8802f2352b43510a33981f9938c2f8d126cf7f6` |
| Inkan | `Inkan` | (generic) | `ik12f16016e5dd60785570b64c1438c213b1467d0f9a085727fe78391484ad586e2` |
| Payment address | `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` | `address` | `ik112cf1aaca7ef50793d990e94c9ae889af6f9e8fdfc28b2f9a72d4028bde05dcd` |
| Identity key | `031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f` | `identity` | `ik143fa06e1de2c970bee94cb96cc269d3831d76fa80f5f8ce5cf68f5b9acf723e7` |
| This verifier page | `9e1d24a23fdfc875acf22f8190fff83f5e9b605ed38a274f00174aae4e5520a7` | `code` | `ik1a99ce448c3f0b47ef4a66385776550a52f9441342ad0db8a7b6333214b7a4e55` |

In the verifier, enter the data, choose the kind ("(generic)" is the empty default kind) and
compare the code; or download a seal image and choose it under "Seal image to compare". The
identity key is the standard's published test key (private key `0x01` repeated 32 times), never a
production key, and the last row's data is the SHA-256 of `web/inkan-verify.html`.
`tools/emit_readme_seals.py` renders these images and checks them against this table.

</details>

## Check an Inkan in your browser

The verifier is a single file, `inkan-verify.html`. It runs entirely in your browser, works offline,
and needs no account and no installation. It never asks for a password, seed phrase or private key:
anything that does is not the Inkan verifier.

### Get the verifier

The same file is available three ways:

1. **Download it from the latest release:**
   <https://github.com/RexStarBSV/Inkan/releases/latest/download/inkan-verify.html>
2. **Open the hosted copy**, served by GitHub Pages from this repository:
   <https://rexstarbsv.github.io/Inkan/web/inkan-verify.html>. This is the quickest way to try it.
   For a copy to keep, use link 1 or 3: saving a page from the browser can change the file, and a
   changed file no longer matches the values below.
3. **Take it from this repository:** open
   [web/inkan-verify.html](https://github.com/RexStarBSV/Inkan/blob/master/web/inkan-verify.html)
   and click **Download raw file** (the download button above the file).

### Use it

1. **Open the file** in a current web browser. Every time it loads, the page checks itself against
   the standard's published examples and shows the result at the top: **self-test ✓** means it is
   working. If it reports a failure, do not rely on it.
2. **Check a seal.** In the first section, enter the data (for example an address) and choose its
   kind; the page draws the genuine seal and shows its `ik1` code. To check a seal image someone
   showed you, choose it under "Seal image to compare" and press **Compare seal image**. GENUINE
   means the image is exactly the seal for that data; MISMATCH means it is not.
3. **Check a file or a warrant canary.** To check a downloaded file against the fingerprint its
   publisher gave, use "Code fingerprint": enter the publisher's adopter name and the version they
   state, choose the file, paste their fingerprint and press **Compute fingerprint**. To check a
   warrant canary (a statement a service operator signs regularly to say they have not been
   compromised or coerced), paste the record, the operator's public key and the signature into
   "Warrant canary" and press **Check canary**.

A GENUINE result proves that the picture belongs to the data. It does not prove that the data
itself can be trusted: whether to send money to an address, for example, is still your decision.
The [quick start](docs/help-inkan-quickstart.md) explains every result in plain language.

### Confirm your copy is genuine

Before you rely on a copy of the verifier, confirm that it is exactly the published file. These
values describe `inkan-verify.html` as published in this release, Inkan Standard v1.0:

| | |
|---|---|
| File size | 405,784 bytes |
| SHA-256 | `9e1d24a23fdfc875acf22f8190fff83f5e9b605ed38a274f00174aae4e5520a7` |
| Adopter fingerprint (adopter `inkan`, version 1) | `a302dbd1d90e9d2bb5cf93c883885801e124cea1a009eba23d3d3d1f1bc44654` |
| `ik1` code | `ik1a99ce448c3f0b47ef4a66385776550a52f9441342ad0db8a7b6333214b7a4e55` |

**With your computer's own tools.** This is the strongest check, because it does not rely on the
file you are checking. Compute the file's SHA-256 and compare it with the value above:

- Linux: `sha256sum inkan-verify.html`
- macOS: `shasum -a 256 inkan-verify.html`
- Windows (PowerShell): `Get-FileHash inkan-verify.html` (it shows the same value in capital
  letters; compare it letter for letter, ignoring case)

**With the page itself.** In the page's "Code fingerprint" section, enter adopter `inkan` and
version `1`, choose the `inkan-verify.html` file itself, paste the adopter fingerprint above as the
claimed fingerprint and press **Compute fingerprint**: the result must match. Use the adopter
fingerprint here, not the SHA-256: the two are computed differently, so they do not match. This
catches a damaged or carelessly edited copy, but a deliberately altered page could report anything
about itself. For a copy someone else gave you, use your computer's tools, or check the file in a
second copy of the verifier that you downloaded yourself from one of the links above.

**The `ik1` code** is the Inkan of the SHA-256 above. In the page's first section, enter the SHA-256
(the 64 lowercase characters) as the data and `code` as the kind: the page shows the `ik1` code
above and draws this release's seal, the picture published beside the page as
[web/inkan-verify.html.inkan.png](web/inkan-verify.html.inkan.png). Copy the SHA-256 from the table
above, not from PowerShell's output: the same characters in capitals are different data, so they
give a different code.

The same values are in [web/inkan-verify.html.inkan.json](web/inkan-verify.html.inkan.json) beside
the page and in the release notes, and they will also be recorded on the BSV blockchain; this
section will link to that record once it exists. A later release of the page has new values,
published the same way.

## For developers

Inkan is three signals, each checkable by anyone with no network connection and no secret key:

| Signal | Answers |
|---|---|
| **Content anchor and seal** | Is this the genuine seal, or `ik1` code, for this data and kind? |
| **Tamper fingerprint** | Is this file the one its publisher released? |
| **Warrant canary** | Is the operator's signed "all clear" valid and recent? A missing or stale one is the warning. |

### Install

| | Package | Install |
|---|---|---|
| **Python** 3.9 or later | [`inkan-standard` on PyPI](https://pypi.org/project/inkan-standard/), imported as `inkan_standard` | `pip install inkan-standard` |
| **JavaScript** (ES modules, Node or browser) | [`inkan-standard` on npm](https://www.npmjs.com/package/inkan-standard) | `npm install inkan-standard` |
| **Kotlin** (JVM, JDK 17) | no published artifact | copy the four engine files in `kotlin/src/main/kotlin/inkan/` into your project |

Both packages are the Apache-2.0 verification path and need nothing else installed. Signing your
own warrant canary in Python needs `bitcoinx`: `pip install "inkan-standard[sign]"`. The bare PyPI
name `inkan` belongs to an unrelated project; this project publishes only `inkan-standard`.

```sh
pip install inkan-standard
python3 -m inkan_standard.verify selftest     # reproduces the 95 pinned vectors; no dependencies
```

To work from a checkout instead, run Python from `python/` (or put `python/` on `PYTHONPATH`), and
in JavaScript import from `js/src/index.js`.

### Command line (Python)

```sh
# after `pip install inkan-standard` (or from `python/` in a checkout)
# the genuine seal and ik1 code for some data, and a check of a seal image you were shown
python3 -m inkan_standard.verify seal --data 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 --kind address --render seal.png --scale 8
python3 -m inkan_standard.verify seal --data 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 --kind address --seal shown.png
# a file against its publisher's fingerprint (here, a downloaded verifier page against its own record)
python3 -m inkan_standard.verify fingerprint --payload @inkan-verify.html --adopter inkan --version 1 \
    --expect a302dbd1d90e9d2bb5cf93c883885801e124cea1a009eba23d3d3d1f1bc44654
# a warrant canary: the record exactly as published, and the key and signature as plain hex
python3 -m inkan_standard.verify canary --record @canary.json --sig <hex> --pubkey <hex>
```

### Python

```python
from inkan_standard import verify, fingerprint, canary

seal = verify.canonical_seal("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address")
print(seal["code"])                         # ik112cf1aaca7ef5079...
open("seal.png", "wb").write(seal["png"])   # the canonical seal

result = verify.verify_seal("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address",
                            open("shown.png", "rb").read())
print(result.ok, result.summary)            # GENUINE or MISMATCH, with the reason

# Tamper fingerprint of a release file, under your own adopter name
fp = fingerprint.fingerprint_hex(open("MyApp.AppImage", "rb").read(), "myapp", 1)

# Warrant canary: the operator signs (needs bitcoinx), any client checks
rec = canary.build_record("myapp", seq=7,
        statement="No warrant, gag order, key or infrastructure compromise, or coercion.",
        block_height=870000, block_hash="<hash of block 870000>")
sig = canary.sign(rec, private_key)                # a bitcoinx PrivateKey or a WIF string
state = canary.status(rec, sig, public_key_hex)   # "OK", "STALE", "INVALID" or "MALFORMED"
```

### JavaScript

```js
// after `npm install inkan-standard`; in a checkout, import from './js/src/index.js' instead
import { inkanSeed, sha256, bytesToHex, sealPng, fingerprintHex, canaryStatus } from 'inkan-standard'

const digest = sha256(inkanSeed('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', 'address'))
const code = 'ik1' + bytesToHex(digest)          // the ik1 code
const png = sealPng(digest, 'address')            // the canonical seal
const fp = fingerprintHex(fileBytes, 'myapp', 1)  // tamper fingerprint
const state = canaryStatus(recordText, signatureHex, publicKeyHex)
```

The JavaScript port computes anchors, seals, fingerprints and canary verdicts. Checking a seal
image someone presents is done by the Python reference and the web verifier.

### Kotlin

The Kotlin port covers the anchor, the `ik1` codes and the seal renderer, using only the JDK. Copy
the four engine files from `kotlin/src/main/kotlin/inkan/` into your project; only the `package`
line may change. [kotlin/README.md](kotlin/README.md) explains how to check a copy for drift.

### Check everything yourself

```sh
(cd python && python3 -m inkan_standard.verify selftest)   # Python reference, no dependencies
(cd js && npm test)                                          # JavaScript port, no dependencies
(cd kotlin && ./gradlew test)                                # Kotlin port (JDK 17)
node js/tools/check_web_verifier.mjs web/inkan-verify.html   # the built verifier page
python3 tools/emit_sidecar_seal.py --check web/inkan-verify.html
```

Each implementation reproduces, byte for byte, the pinned vectors for everything it implements. An
application may bundle a copy of the verification path so that it works offline; if a copy and this
repository disagree, this repository is the reference.

### How it works

- **The anchor** is SHA-256 over a domain-separated input (`inkan/v1`), the kind and the data. The
  kind is part of the hash, so an address and a contract with identical bytes never share an
  anchor. The `ik1` code is `ik1` followed by the anchor's 64 hex characters, and needs no registry.
- **The seal** is a deterministic 224 × 224 pixel image drawn from the anchor. Its cells are filled
  from extended Golay [24,12,8] codewords, so any two different seals differ in at least 8 cells by
  construction, and a one-bit change in the input redraws the seal (in 400 measured one-bit changes
  to the anchor of a default 48-cell seal, every one changed at least 24 cells). The kind sets the
  seal's symmetry and frame, and the palette was chosen to stay distinguishable under simulated
  colour-vision deficiency (a model result, not a study of people). Because the drawing is
  deterministic, an on-chain Inkan needs only the 32-byte anchor and its kind: anyone can redraw
  the seal and compare it pixel for pixel.
- **The tamper fingerprint** is SHA-256 over the file, prefixed with the adopter's name and a
  version, so the same bytes give a different fingerprint for each publisher and no coordination is
  needed.
- **The warrant canary** is a short record, with a recent block height and hash, signed with
  secp256k1 ECDSA. Verifiers report OK, STALE, INVALID, MALFORMED or UNSUPPORTED, and never report
  a check that could not run as one that failed.

Design evidence and stated limits: [docs/audit-abstract.md](docs/audit-abstract.md). Technical
reference: [docs/help-inkan-reference.md](docs/help-inkan-reference.md).

**Provenance.** The anchor, the fingerprint, the canary and the Seal v3 renderer are original work.
An early version of the seal (v1), never published, was based on LifeHash (© 2019-2022 Blockchain
Commons, LLC, BSD-2-Clause-Patent). It was deleted on 2026-07-09, before any Inkan seal was
published, and no LifeHash code remains in this repository. Seal v3 reproduces none of LifeHash's
code, structure or output.

## The standard

- [SPEC.md](SPEC.md) is the normative, language-agnostic specification. Version 1.0 was frozen on
  2026-07-28; this is revision 1.0.2 (2026-10-16). Its §0 states which results can never change.
  [SPEC-REVISIONS.md](SPEC-REVISIONS.md) gives the SHA-256 of every revision, so you can cite the
  exact text you relied on.
- [standard/inkan-standard.html](standard/inkan-standard.html) is the illustrated, self-contained
  form of the specification.
- [test-vectors/](test-vectors/) holds the conformance vectors. An implementation conforms if it
  reproduces them; with the specification, they are everything an independent implementation
  needs.
- The standard is published as
  [BRC-145](https://github.com/bsv-blockchain/BRCs/blob/master/apps/0145.md). Revision 1.0.1 adds
  errata E14 to E24. E18 only copies text from BRC-145 into SPEC.md; BRC-145 carries the other ten
  since its Errata 3, [bsv-blockchain/BRCs#314](https://github.com/bsv-blockchain/BRCs/pull/314),
  merged on 2026-10-12. BRC-145 now reflects every erratum of revision 1.0.1, cites that revision
  by its SHA-256, and links this repository.

## Licensing

Inkan is licensed by function: verification is open, products are protected.
[LICENSING.md](LICENSING.md) is the full map and governs; in summary:

| What | Licence |
|---|---|
| The specification and public documentation (listed in `LICENSE-SPEC`) | CC BY 4.0 |
| The test vectors, the Seal v3 tables file, the verifier pages' sidecar files and the example seals (listed in `LICENSE-VECTORS`) | CC0, public domain |
| The verification path: the Python reference, the JavaScript and Kotlin ports and the built verifier pages, apart from the font and mark embedded in them (listed in `NOTICE` and `LICENSE-VERIFY`) | Apache-2.0 |
| The font embedded in the verifier pages (Inkan Sans, a renamed subset of IBM Plex Sans) | SIL Open Font License 1.1 (`LICENSE-FONTS`) |
| The Gradle wrapper in `kotlin/` | Apache-2.0, Gradle's own (`LICENSE-GRADLE`) |
| The Inkan mark | Not licensed, all rights reserved (`LICENSE-MARK`) |
| Everything else | Business Source License 1.1 (`LICENSE`) |

You may verify Inkans, and create your own, in any product, commercial or not; implement the
standard independently from the specification and vectors; read and audit everything; and use the
rest of the code to seal, fingerprint and sign your own releases and canaries, under the Additional
Use Grant in `LICENSE`. Anyone may copy, modify and share the Business Source License tier with its
licence intact, but before its Change Date, 2030-07-09, it may not be used in production to offer
it, or anything derived from it, to others as a product, as part of one, or as a hosted service. On
that date it converts to MIT. MIT is what that tier becomes on that date, not a grant made today,
and the conversion never reaches the mark, the font or the Gradle wrapper. None of these licences
grants rights in the Inkan name or mark. For a commercial licence, open an issue with the
**Licensing inquiry** form.

## Security

Please report vulnerabilities privately through GitHub, under Security ▸ Report a vulnerability,
not in a public issue. [SECURITY.md](SECURITY.md) describes the scope, response times and
disclosure policy.
