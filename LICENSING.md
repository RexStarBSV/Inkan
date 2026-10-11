# Licensing — the map

One repository, split by function. Principle: **enable as much adoption as possible; keep under
BSL what logically and reasonably belongs there** — verification open, products protected. Every
file falls under exactly one row, apart from the licence and notice documents themselves (see
Precedence), and `tools/check_licence_map.py` fails the build if one does not.

| What | Files | Licence | In plain terms |
|---|---|---|---|
| **The standard + public docs** | the files listed in [LICENSE-SPEC](LICENSE-SPEC) | [CC BY 4.0](LICENSE-SPEC) | Copy it, translate it, teach it, implement from it — credit "Inkan Standard, RexStarBSV" with the revision you used (see LICENSE-SPEC). |
| **Conformance vectors, Seal v3 tables, sidecar records and example seals** | the files listed in [LICENSE-VECTORS](LICENSE-VECTORS): every file in `test-vectors/` (the vectors and the Seal v3 tables file), the `.inkan.json` / `.inkan.png` sidecars the verifier pages are published with, and the example seals at the top of the README (`examples/seals/`) | [CC0](LICENSE-VECTORS) | Public domain. Reproducing the vectors is what conformance *means*, and the tables are the data a renderer is built from; a sidecar record is a fact anyone can recompute from its page, and an example seal one anyone can recompute from its data and kind. |
| **Verification path** | the files listed in [NOTICE](NOTICE) — the Python reference, its **JavaScript and Kotlin ports**, and the **built verifier page** | [Apache-2.0](LICENSE-VERIFY) | Verify Inkan seals, fingerprints, canaries, and codes in any product, forever, patent grant included. Once published, `inkan-standard` on PyPI (import name `inkan_standard`) and `inkan` on npm will carry this grant; the PyPI wheel also bundles three of the conformance vector files, under CC0 with `LICENSE-VECTORS`. **Neither is published yet**; until they are, the grant applies to the source you already hold. |
| **Third-party font** | the material listed in [LICENSE-FONTS](LICENSE-FONTS): the Inkan Sans font embedded in the built web verifier (a renamed subset of IBM Plex Sans), and the subset files it is built from | [SIL OFL 1.1](LICENSE-FONTS) | IBM's work, not ours to license. Excluded from the Licensed Work, so it cannot be swept into the 2030 MIT conversion, and carved out of the page's Apache-2.0 grant. |
| **Third-party build tooling** | the Gradle wrapper files listed in [LICENSE-GRADLE](LICENSE-GRADLE) | [Apache-2.0](LICENSE-GRADLE), Gradle's | Gradle's own work, committed so the Kotlin gate runs from a clean checkout. Not ours, not BSL, never MIT. |
| **The Inkan mark** | the material listed in [LICENSE-MARK](LICENSE-MARK): the mark embedded in the built web verifier, and its source artwork | **Not licensed — all rights reserved** ([LICENSE-MARK](LICENSE-MARK)) | Pass the verifier page on unmodified, mark and all; put the mark on nothing else. It is not Apache-2.0, not BSL, and never converts to MIT. |
| **Everything else** | all other files | [BSL 1.1](LICENSE) | Read, audit, modify, run for yourself, use internally, and share the source with the licence intact. Seal, fingerprint, sign and anchor your own releases and canaries with it. Do **not** use it in production to offer it, or anything derived from it, to others as a product, as part of one, or as a service before the Change Date (2030-07-09), when it converts to MIT. |

## What third parties can do today

- **Verify anywhere.** Check any seal, fingerprint, canary, or code, in any app, commercial or
  not. That is the point of a trust mark.
- **Generate their own Inkans with the verification path.** Verification mathematically contains
  the canonical render, and Apache-2.0 carries no field-of-use limits — so sealing your own
  canary (with your own key, under your own domain), fingerprinting your own releases (under
  your own adopter namespace), or sealing addresses is permitted **by design, not by loophole**.
  Every honest Inkan in the wild strengthens the standard.
- **Implement independently.** Build a creator, a renderer, a whole competing toolkit from scratch,
  with no permission needed and no code from this repository: the CC BY specification plus the CC0
  data (the conformance vectors, and the Seal v3 tables file `test-vectors/seal-v3-tables.json`,
  whose SHA-256 the specification pins) are everything a conforming implementation needs. A
  standard only one vendor may implement is not a standard.

## What BSL still protects (until 2030-07-09)

The product tier: the on-chain anchoring/broadcast module, ordinal-minting and tagged-export
workflows, application surfaces and GUIs, and the release and packaging tooling — including
`js/tools/build_web_verifier.py`, the builder, as distinct from the page it emits. (The mark is not
in this tier: it is not licensed at all, so it does not convert in 2030.)

The Additional Use Grant in `LICENSE` is written for what this tier does: you may use it in
production to create, seal, fingerprint, sign, publish and anchor on-chain the Inkan codes, seals,
fingerprints and canaries of **your own** content, releases and operations, under your own adopter
name, domain and keys, or for your internal operations. Doing those things **for others**, as a
hosted service, and using this code in production by offering it to others as a product or as part
of one, are what the BSL reserves; copying, modifying and redistributing the source with the
licence intact are not restricted. What permitted use produces (codes, seals, fingerprints,
sidecar records, signatures, on-chain records) is not the Licensed Work and is yours to publish.

**The JavaScript and Kotlin engines are Apache-2.0**, like the Python verification path they port.
BSL over them would protect a transcription rather than an idea, while blocking the npm and PyPI
distribution a verification library needs in order to be adopted at all. Verification is open in
every language the standard ships, or it is not open. What stays protected is the BSL tier above,
and concretely that means: no production use of it, or of a fork of it, to offer a product or part
of one to others, and no seals-as-a-service hosted on it — until the Change Date, when that tier
converts to MIT automatically.

## Precedence

Where a file is named by LICENSE-SPEC, LICENSE-VECTORS, NOTICE (LICENSE-VERIFY), LICENSE-FONTS,
LICENSE-GRADLE or LICENSE-MARK, those terms govern that file; LICENSE (BSL 1.1) governs everything
else. No file is named by two of them. Two pieces of material inside an Apache-2.0 file are carved
out of it and marked in place as SPDX snippets: the embedded font (OFL-1.1) and the embedded mark
(LicenseRef-Inkan-Mark), both in the two web verifier pages. The BSL body text is byte-faithful to
the canonical (SPDX) BUSL-1.1 text; the designated files are excluded in the Licensed Work
parameter, where scope belongs.

**The licence and notice documents themselves** (`LICENSE`, every `LICENSE-*` file and `NOTICE`,
and their copies under `js/`) are not rows of the map: they are the map. The licence texts they
reproduce stay under their own authors' terms (the Business Source License text is MariaDB's, the
Apache-2.0 text the Apache Software Foundation's, the CC BY 4.0 and CC0 texts Creative Commons',
and the OFL SIL International's, with IBM's notice), and nothing here relicenses them.

**Wire formats are free to implement.** The on-chain record layouts (e.g. the `INKANC1`
`OP_RETURN` carrier) are published in BRC-145 and may be implemented by anyone; the BSL protects
this repository's code, never the formats.

**BRC-145 and SPEC.md are two texts under two licences.** BRC-145 (`apps/0145.md` in
`bsv-blockchain/BRCs`) is distributed under that repository's own terms: its README states that
everything in it is subject to the Open BSV License. `SPEC.md` is the Licensor's own text and stays
under CC BY 4.0 (`LICENSE-SPEC`); submitting BRC-145 granted nothing in `SPEC.md` beyond that, and
nothing in BRC-145 narrows it. Where the two differ, `SPEC.md` governs (its "Relationship to
BRC-145" section). To cite the exact text you relied on, cite its revision number together with the
SHA-256 of the `SPEC.md` file you read; `SPEC-REVISIONS.md` lists both for every revision.

**Build tooling note.** `kotlin/` ships the standard Gradle wrapper (upstream Gradle,
Apache-2.0, `LICENSE-GRADLE`) so the conformance gate stays reproducible; it is third-party build
tooling, not part of the standard's implementations.

**No upstream codebase.** Inkan is not derived from another codebase, so there is no upstream
residual to measure and no upstream licence to inherit. Every file under `python/`, `js/`,
`kotlin/src/` and `web/` is original work, apart from the embedded font named above; the only other
third-party material in the tree is the Gradle wrapper. The one earlier dependency on third-party
code, the LifeHash-based v1 seal, was deleted before anything was published (README, "Provenance").

**Patents.** The Licensor has filed no patent application and holds no patent covering the Inkan
standard (statement of fact, 2026), **and does not intend to seek one** (the Licensor's decision,
2026-08-03). Independent implementations of the specification are welcome; the verification path
additionally carries Apache-2.0's express patent grant.

Note the boundary honestly: that Apache-2.0 grant reaches implementations built *from the code in
NOTICE*. The specification is CC BY 4.0, whose §2(b)(2) states plainly that "patent and trademark
rights are not licensed under this Public License" — so a clean-room implementation written from
SPEC.md alone receives no patent licence from this project. Given that no patents are held or sought,
nothing is being withheld; the statement above is the whole assurance available today. A formal
non-assertion covenant would be a stronger, binding assurance and has deliberately not been made.

**Commercial licensing.** For production use of the BSL tier beyond the Additional Use Grant
before the Change Date, open an issue on this repository with the **Licensing inquiry** form
(Issues ▸ New issue), which files it under the `licensing` label; you cannot add labels yourself, so
please use the form. Issues are public, so put nothing confidential in one. The Licensor responds
pseudonymously.

**Trademarks.** "Inkan" and "Inkan Standard" are used as source identifiers by the Licensor.
None of the licences above grants trademark rights (see Apache-2.0 Section 6 and CC BY 4.0
Section 2(b)(2)). Describing a product as implementing or conforming to the Inkan Standard is
welcome; naming a product or service in a way that implies it IS the Licensor's offering is not.

The Inkan mark also appears inside the distributed web verifier (`web/inkan-verify.html` and its
body-only variant `web/inkan-verify.artifact.html`), embedded as an inline vector so the page
identifies its origin when served from a local file, a static host, or an on-chain inscription. That
inclusion is deliberate and grants nothing beyond `LICENSE-MARK`: the mark is all rights reserved,
carved out of the page's Apache-2.0 grant (it sits in a `LicenseRef-Inkan-Mark` SPDX snippet), and
redistributing the verifier verbatim conveys no permission to use the mark on another product or
service. A derivative that changes the page must remove the mark or replace it with its own.

**Embedded font.** The web verifier embeds **Inkan Sans**, a subset of IBM Plex Sans (Copyright 2017
IBM Corp., SIL OFL 1.1). IBM reserves the font name "Plex", and a subset is a Modified Version, so
the subset is renamed. Apart from the subsetting itself, only its name table and vendor ID differ
from IBM's files. See NOTICE and `LICENSE-FONTS` for the full attribution.

Licensor, and copyright holder of everything except the font, the Gradle wrapper and the
reproduced licence texts: **RexStarBSV**.
