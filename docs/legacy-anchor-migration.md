# Legacy-anchor migration playbook — what happens to `ik1` when SHA-256 weakens

Status: standing playbook, 2026-07-31. Non-normative; changes no frozen byte.
Companion to SPEC §2/§10 and `docs/future-provisions.md` §1.1.

## The threat, stated precisely

The realistic 50–100-year failure path for the anchor is **collision** erosion of SHA-256
(cryptanalytic, like SHA-1's arc), not preimage (Grover's 2^128 is a non-threat). Hash agility
(`ik2…`) rescues every anchor minted *after* a migration. This playbook covers the part agility
alone cannot: anchors and receipts already minted under `ik1`.

## What collision erosion does and does not break

- **Does not break:** second-preimage trust of an existing anchor over honest content. An attacker
  who did not choose the original content cannot retro-fit a substitute even with a collision
  attack; they need a second preimage, which stays out of reach far longer.
- **Does break:** commitments where the *adversary authored the original bytes*. A collision
  attacker prepares two documents with the same anchor **before** minting, then swaps. On-chain
  timestamps bound *when* the anchor existed, not *which* twin was intended.

So the exposed class is: anchors over adversary-supplied content, minted after collision attacks
became feasible but before the holder migrated. Everything timestamped **before** credible
weakening retains full trust in the honest-content case.

## The playbook

1. **Tripwire.** The signal to act is a published theoretical collision attack materially below
   2^128 on SHA-256 (the SHA-1 precedent gave ~12 years between first break and practical
   collision). No panic threshold: begin at *credible theory*, not demonstrated collision.
2. **Dual-anchor immediately.** For every artifact that must stay trustworthy, compute the `ik2`
   anchor (successor hash, same seed layout, new domain `inkan/v2`) of the SAME bytes and publish
   it — on-chain where the original was on-chain. The pair `(ik1, ik2, timestamp)` proves the bytes
   predate the break: a forger would need a simultaneous collision in both hashes.
3. **Timestamp is the ratchet.** An `ik1` anchor whose on-chain timestamp precedes the tripwire
   date, or which is bound into a dual-anchor record, keeps full evidentiary weight. An `ik1`
   anchor floating with no timestamp and no dual-anchor decays to "consistent with" rather than
   "proves".
4. **Verifiers stay honest.** `ik1` verification never turns off — codes remain auditable forever —
   but post-tripwire verifiers SHOULD annotate `ik1`-only results with the erosion caveat rather
   than refusing them. Refusal would destroy the archive; annotation preserves honest reading.
5. **New mints switch.** From the tripwire forward, new anchors mint as `ik2` only. The reserved
   version digit and the reject-unknown-version rule (SPEC §2) make the cutover loud on old
   software instead of silent.

## Why this works

The scheme's three durable properties compose: (a) versioned codes make old and new anchors
unambiguous side by side; (b) the chain supplies ordering that no collision attack can rewrite;
(c) dual-anchoring is additive — no frozen byte changes, no re-freeze, no flag day. The cost of
full protection is one extra 32-byte digest per artifact, paid only by holders who still care
about the artifact at migration time.
