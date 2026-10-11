# Inkan — Quick Start

Inkan gives a piece of data — a Bitcoin address, an identity, a downloaded app — a small **picture
seal** that a person can recognise at a glance, plus a short code, so you can tell whether the thing
in front of you is genuine or a swapped-in lookalike. It also carries a **warrant canary**: a
regularly re-signed "all clear" note whose *silence* is the warning.

This guide is for the person who wants to **check** an Inkan (you need no account and no keys), and
for anyone making their first seal. Plain language, no jargon. The deep version is the *Technical
Reference*.

---

## 1. First, the reassuring part: checking needs no keys

To verify an Inkan you don't sign in, you don't install a wallet, and you never enter a password,
seed phrase, or private key **anywhere**. The verifier trusts nothing you show it — it recomputes
the answer from scratch and compares. That's the whole idea.

So if any page, form, or "support agent" ever asks you to type a seed phrase or a private key to
"verify an Inkan," stop — that is not how Inkan works, and it is how people get robbed. (The only
key involved anywhere in Inkan belongs to an *operator* who publishes a canary — see step 6 — and it
stays on their machine, never yours.)

## 2. Get the verifier — and check it's genuine

You verify with a small, self-contained tool. There are two forms, and they give the same answer:

- **The web verifier** — a single file, `inkan-verify.html`. Open it in any browser, even offline.
  It also ships bundled inside adopting applications, so it works with no network at all.
- **The command line** — `python -m inkan_standard.verify`, using only Python's standard library.

Before you trust a verifier to judge anything, have it **check itself** first:

```
python -m inkan_standard.verify selftest
```

The web page does this automatically when it loads. A verifier that can't reproduce the known-good
examples shouldn't be believed about anything else.

## 3. Check a seal someone showed you

Say someone gives you an address and its seal picture, and claims the picture is the genuine seal for
that address. You confirm it like this:

```
python -m inkan_standard.verify seal --data <the-address> --kind address --seal shown.png
```

(In the web verifier: enter the data, choose the kind, choose the image under "Seal image to
compare", and press **Compare seal image**.)

You'll get one of two clear verdicts:

- **GENUINE** — the picture is the exact seal for that data. A phishing lookalike can't reach this;
  it would have to be pixel-for-pixel identical, which only the real one is.
- **MISMATCH** — the picture is *not* the genuine seal. Treat it as suspicious.

The **kind** (address, identity, code, and so on) is part of what's checked and is visible in the
seal itself, so a "signer" seal can never be passed off as an "address" seal.

## 4. "GENUINE" is not the same as "safe"

This is the one thing to internalise. A GENUINE result proves the *picture matches the data* — that
the seal really belongs to that address. It says **nothing** about whether the address itself is
trustworthy or whether you should send it money. Inkan authenticates the link between data and image;
judging the data is a separate act, and still yours.

And a third outcome exists: the verifier may tell you it **couldn't check** — the image was unreadable,
or wasn't a proper seal image at all. "Couldn't check" is not "verified as fake." It means *try again
with a proper file*, not *this is a forgery*.

## 5. Make your own seal

You can generate the canonical seal for any data yourself — that's often how you *get* the genuine
image to compare against:

```
python -m inkan_standard.verify seal --data "npub1..." --kind identity --render mine.png --scale 8
```

Because the drawing is fully determined by the data and kind, your render and everyone else's are
identical, everywhere, forever. That's what makes side-by-side comparison meaningful.

## 6. Check a warrant canary (silence is the alarm)

A **warrant canary** is a short, signed statement an operator publishes on a schedule — roughly "no
warrant, gag order, key or infrastructure compromise, or coercion; releases are clean." You check one
with:

```
python -m inkan_standard.verify canary --record @canary.json --sig <hex> --pubkey <hex>
```

The file must hold the record exactly as it was published, byte for byte: a copy that has been
reformatted, for example pretty-printed with spaces and line breaks, reads MALFORMED, because the
signature covers the exact bytes (blank space around the record, such as the line break at the end
of a file, is ignored). The key and signature are plain hex, with no `0x` prefix and no spaces
between the digits.

The result is one of five words:

- **OK** — the statement is validly signed by the published key and is fresh.
- **STALE** — the signature is fine but the note is old (past its freshness window). Pay attention.
- **INVALID** — the signature doesn't check out. A check ran and it failed.
- **MALFORMED** — the record, the key or the signature is not in the form the standard requires,
  so no check ran at all. This is deliberately not the same answer as INVALID: one says the
  signature is wrong, the other says nobody managed to ask.
- **UNSUPPORTED** — the record uses a newer version of the canary format than this verifier
  knows, so it could not be checked. Get a newer verifier; this is not a verdict on the operator.

The important habit: **a canary that stops appearing, or goes stale and stays stale, is itself the
signal.** You don't wait to be told something is wrong; the absence of a fresh "all clear" is the
message. (What it means is a judgement call — an operator could also simply be slow, or have lost the
key — so read it as a prompt to ask questions, not proof of a raid.)

## 7. On-chain is optional

Inkan can anchor a canary onto the BSV blockchain so it can't be quietly retracted — an immutable,
timestamped copy. This is **opt-in and off by default**, it goes through your own wallet, and it
refuses to touch real (mainnet) funds unless you deliberately override a testnet guard. You never
need it to verify anything; verification works fully offline.

---

## What to do next

- **Keep a copy of the web verifier** (`inkan-verify.html`) somewhere of your own. It's one file,
  needs no internet, and lets you check any Inkan without depending on anyone's website staying up.
- **Learn the verdicts** — GENUINE vs MISMATCH (step 3), and OK/STALE/INVALID/MALFORMED/UNSUPPORTED
  (step 6) — until they're second nature.
- **If you *publish* Inkans or a canary** (you're an operator, not just a checker), read the
  *Technical Reference* — especially the part about protecting the one signing key, ideally on an
  air-gapped signer, and never letting it touch a networked machine.

## Common questions

- **The seal I was shown says MISMATCH — is my money gone?** No. It means the *picture* doesn't match
  the data. Don't act on the thing that showed it to you; get the data from a source you already trust
  and re-check.
- **It says it "couldn't check" the image.** That's not a forgery verdict — the file was unreadable or
  wasn't a real seal image (a screenshot, a cropped or resized copy). Re-export or re-download the
  actual seal and try again.
- **The canary is STALE / I can't find this month's canary.** That is the alarm working as designed.
  Slow down, verify through another channel, and don't push sensitive actions through that operator
  until there's a fresh OK.
- **Someone wants my seed phrase or private key to "verify an Inkan."** It's a scam, every time.
  Verifying an Inkan never involves your keys. Stop.
- **Do I have to trust Inkan's servers?** No. Everything is recomputed on your device from public
  inputs; the verifier is a single self-contained file and can even be pinned permanently on-chain.
