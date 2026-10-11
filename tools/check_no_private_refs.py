#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Gate: no PUBLIC file may name a PRIVATE path.

The share manifest decides what is withheld. But withholding a file is only half the job — a public
that *cites* it still discloses that it exists, what it is called, and roughly what it covers. Enough
of those and the public tree carries an index of the private one, which is the thing the manifest was
written to prevent.

Found live on 2026-08-03, before any publication. Three classes, all fixed:

  * The manifest did not exclude itself, so the complete map of the withheld tree was in the public
    set — despite the manifest's own third line declaring itself private.
  * The generated seal tables, which ship in the PyPI wheel and the npm tarball, named their private
    generator and a private measurement tool in their headers, in all three languages.
  * Shipping engine sources cited private design documents a reader would never receive.

This module names no private path itself, deliberately: it is a public file, and it is subject to the
rule it enforces. The gate flagged an earlier draft of this very docstring, which is the intended
behaviour and the reason the examples above are described rather than cited.

A dangling reference to a private document is also just bad work: the reader follows it and gets
nothing. Removing the citation and stating the fact inline is better on both counts.

    python3 tools/check_no_private_refs.py          # exit 1 on any leak
"""
from __future__ import annotations

import fnmatch
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = {".png", ".jpg", ".jpeg", ".gif", ".ttf", ".otf", ".woff", ".woff2", ".jar", ".zip", ".ico"}

# The manifest's own filename is exempt from the disclosure rule. Tooling that reads it must name it,
# and the name discloses only that a manifest exists — every project with private paths has one. What
# needs protecting is its CONTENTS, which are what this gate stops from leaking by other routes.
MANIFEST = ".sharegate"


def wholly_private_dirs(deny: list[str], allow: list[str]) -> list[str]:
    """Top-level trees the manifest withholds entirely: naming the directory at all is a disclosure,
    not just naming a file in it. Read from the manifest rather than listed here, because this file
    ships and a list here would itself name them. A tree is wholly private when the manifest denies
    `<dir>/**` and re-includes nothing beneath it."""
    out = []
    for d in deny:
        top = d[:-3] if d.endswith("/**") else ""
        if top and "/" not in top and not any(c in top for c in "*?[") \
                and not any(a.startswith(top + "/") for a in allow):
            out.append(top)
    return sorted(set(out))


def rules() -> tuple[list[str], list[str]]:
    lines = [l.split("#")[0].strip() for l in (ROOT / ".sharegate").read_text().splitlines()]
    lines = [l for l in lines if l]
    return ([l for l in lines if not l.startswith("!")], [l[1:] for l in lines if l.startswith("!")])


def is_private(rel: str, deny: list[str], allow: list[str]) -> bool:
    if any(fnmatch.fnmatch(rel, a) for a in allow):
        return False
    for d in deny:
        pat = d[:-3] + "/*" if d.endswith("/**") else d
        if fnmatch.fnmatch(rel, pat) or rel == d:
            return True
        if d.endswith("/**") and rel.startswith(d[:-3] + "/"):
            return True
    return False


def main() -> int:
    # A published tree carries no manifest: it is itself the private file this gate protects, so the
    # release cut withholds it. Without it there is nothing to check AGAINST, and the honest answer
    # is to say so and exit non-zero -- not to crash on the missing file, and not to report a clean
    # tree it never examined (a gate that passes by not running is the failure this repo names first).
    if not (ROOT / MANIFEST).is_file():
        print(f"check_no_private_refs: NOT RUN -- no {MANIFEST} manifest in {ROOT}.\n"
              "  This gate checks a source repository's public files against its private ones, and a\n"
              "  published tree has no private files: the manifest is withheld from it by design. Run\n"
              "  it in the Licensor's source repository; in a published tree it has nothing to check.",
              file=sys.stderr)
        return 2
    deny, allow = rules()
    wholly_private = wholly_private_dirs(deny, allow)
    tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                             capture_output=True, text=True).stdout.split()
    if not tracked:
        print("FATAL: no tracked files — not a git repository?", file=sys.stderr)
        return 2
    public = [f for f in tracked if not is_private(f, deny, allow)]
    private = [f for f in tracked if is_private(f, deny, allow)]

    leaks: list[tuple[str, str]] = []
    for rel in public:
        p = ROOT / rel
        if p.suffix.lower() in BINARY or not p.is_file():
            continue
        try:
            text = p.read_text(errors="ignore")
        except OSError:
            continue
        for priv in private:
            if priv == MANIFEST:
                continue
            if priv in text:
                leaks.append((rel, priv))
        for d in wholly_private:
            # The lookbehind stops a nested `foo/<dir>/` matching a private TOP-LEVEL directory of
            # the same name. But a bare `(?<![\w/.-])` also refuses a leading `../` chain, because
            # the slash of `../` sits exactly where it looks. Those are relative references to the
            # very directory being guarded: a shipping module in python/ pointed two levels up at a
            # private tree, in a docstring, and this gate exited 0 on it. So: not preceded by a path
            # character, OR preceded by `../`, which only ever walks up toward the repo root.
            # (Stated without a literal example — this file is itself scanned.)
            if re.search(r"(?:(?<![\w/.-])|(?<=\.\./))" + re.escape(d) + r"/", text):
                leaks.append((rel, d + "/…"))

    if leaks:
        print("PUBLIC FILES DISCLOSE PRIVATE PATHS:", file=sys.stderr)
        for rel, priv in sorted(set(leaks)):
            print(f"  {rel}  ->  {priv}", file=sys.stderr)
        print("\nEither withhold the citing file, make the cited file public, or state the fact "
              "inline instead of pointing at a document the reader will never receive.",
              file=sys.stderr)
        return 1

    print(f"  no private-path disclosures: {len(public)} public files checked against "
          f"{len(private)} private paths and {len(wholly_private)} wholly private trees")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
