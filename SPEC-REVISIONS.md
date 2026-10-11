# Revisions of the Inkan Standard text

Each revision of `SPEC.md` is numbered, and it is identified by the SHA-256 of the file's exact
bytes (SPEC §0, P2). The revision number is written in the file itself; its SHA-256 cannot be, so it
is published here. To cite the text you relied on, give its revision number and this digest.

A revision may only do what §0 (P2) allows: clarify wording, add test vectors, or make
implementations reject an input that was malformed or on which conforming implementations already
gave different results. No revision changes the result of an input that the reference
implementation accepts and on which conforming implementations agree, with the one exception P2
names: in revision 1.0.1, made before any canary record had been published, erratum E23 makes some
canary records on which the reference and the JavaScript verifier had agreed read `MALFORMED` (a
negative `seq` or `block_height`, or one of 2^53 or more that a double holds exactly, and wire bytes
that are not the record's canonical bytes, all read `OK` before; and a `date` that is not a real
time, read `STALE` before).

| Revision | Date | SHA-256 of `SPEC.md` | Changes |
|---|---|---|---|
| 1.0 | 2026-07-28 | `12cd41e98822ecdc47663910bbeda6018f235062f5a06d67db316ff8a4fefa30` | The frozen text, with errata E1–E13 (2026-07-31 and 2026-08-04). |
| 1.0.1 | 2026-10-10 | `5ef0baafc83b1c6e5d80664c889df06a4b22d4e4d6450e81e24bd36983d5e53c` | §0 Permanence, which names the one exception E23 makes to P2; errata E14–E24; the Python reference package is named `inkan_standard`. |
