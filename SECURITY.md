# Security Policy — Inkan

Inkan is a cryptographic sealing/verification system: the highest-severity reports are anything enabling seal forgery, verification bypass, canary spoofing, or collision/second-preimage weaknesses in the fingerprint pipeline.

## Reporting a vulnerability

**Please report privately first.** We follow coordinated disclosure.

- **GitHub private vulnerability reporting** — the primary channel. Open a private advisory on the
  repository (Security ▸ Report a vulnerability). It is private to the maintainer until published,
  needs no key exchange from you, and cannot be lost to a domain or mail-host failure.
- **Censorship-resilient fallback (planned):** a project onion service whose address will be
  published in an **on-chain reachability manifest**. Until both are live, GitHub private
  vulnerability reporting is the sole channel; once published, the manifest resolves from the
  chain, so a takedown cannot silence a report.

We deliberately run **no security email address and no PGP key**. An address that quietly stops
receiving is worse than none: a reporter believes they have reached us while the report goes
nowhere. The GitHub channel above is one we can prove is live; the onion service is marked planned
and is not yet standing, so it is not a channel you should rely on today.

Include: the affected component (Python reference, JS or Kotlin port, web verifier page, tools)
and version, reproduction steps or a PoC, and impact as you understand it. You will get an
acknowledgement **within 3 days**, and a status update at least weekly until resolution. Anything
that makes a verifier report `GENUINE` or `OK` for something it should not is treated as critical.

## Scope

In scope: anything that enables **seal forgery or a lookalike that verifies, a verification bypass,
canary spoofing or a wrong canary verdict, a collision or second preimage in the anchor or
fingerprint construction, divergence between the ports or from the pinned vectors, key or signature
mishandling in the canary signing tools, an unguarded spend in the optional on-chain anchoring
module, or identifying metadata leaking into a seal**. Out of scope: volumetric DoS, social
engineering, issues requiring a compromised OS, and third-party services we do not operate.

## Disclosure

- Coordinated window: **90 days** from acknowledgement, or earlier once a fix ships — whichever
  comes first. We may ask for a short extension for a fix that must reach inscribed or vendored
  copies of the verifier; you may decline.
- You will be **credited** in the advisory unless you ask not to be.
- **Safe harbor:** good-faith research within this policy will not be met with legal action.
  Do not access, modify, or exfiltrate data that is not yours; use testnet where possible.
- No bug bounty is offered **yet** (deliberately — an unfunded promise is worse than none).
  Researcher credit is permanent and public.

## Supported versions

Inkan **1.0.0** is the current release, and security fixes target the current release. A fix
ships as a new version, never as a moved tag: a published version always verifies against the
bytes it was published with.

Each release of the web verifier carries a sidecar reference beside it
(`web/inkan-verify.html.inkan.json` and `.inkan.png`): check a copy you were handed against that
fingerprint before trusting it. An on-chain Code Inkan for releases is planned and **not yet
inscribed**; until it is, the sidecar in this repository is the reference.
