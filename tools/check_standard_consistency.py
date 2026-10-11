#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Gate: the two published forms of the standard must say the same thing, and SPEC.md must be the
revision SPEC-REVISIONS.md publishes.

The standard exists twice - `SPEC.md` and the self-contained `standard/inkan-standard*.html` - and
they were independent documents with nothing between them. On 2026-08-04 SPEC.md carried eleven
errata and the HTML carried none, including E10, which is security-relevant: an implementer working
from the inscribable form would have inherited a hole the reference had already fixed. The HTML is
the copy most likely to be republished, inscribed, or read a decade from now with no repository
around it, so it is the worse of the two to leave stale.

    python3 tools/check_standard_consistency.py       # exit 1 on divergence
"""
from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PAGES = ["standard/inkan-standard.html", "standard/inkan-standard.artifact.html"]


def spec_errata() -> list[str]:
    spec = (ROOT / "SPEC.md").read_text()
    if "## Errata" not in spec:
        print("FATAL: SPEC.md has no Errata section", file=sys.stderr)
        raise SystemExit(2)
    body = spec.split("## Errata", 1)[1]
    return re.findall(r"^\|\s*\**(E\d+)\**\s*\|", body, re.M)


REVISIONS = "SPEC-REVISIONS.md"
_ROW = re.compile(r"^\|\s*(\d+\.\d+(?:\.\d+)?)\s*\|[^|]*\|\s*`([0-9a-f]{64})`\s*\|", re.M)


def revision_problems() -> list[str]:
    """SPEC §0 (P2): every revision of SPEC.md is numbered and its SHA-256 published. The number the
    file names must be the newest row of SPEC-REVISIONS.md, and that row must carry the SHA-256 of
    SPEC.md as it stands, so the text cannot change without the published record changing with it."""
    import hashlib
    spec = (ROOT / "SPEC.md").read_bytes()
    m = re.search(r"revision (\d+\.\d+\.\d+)", spec[:600].decode("utf-8", "replace"))
    if not m:
        return ["SPEC.md does not name its revision in its first paragraph"]
    if not (ROOT / REVISIONS).is_file():
        return [f"{REVISIONS} is missing: SPEC §0 promises a published SHA-256 for every revision"]
    rows = _ROW.findall((ROOT / REVISIONS).read_text(encoding="utf-8"))
    if not rows:
        return [f"{REVISIONS} lists no revisions"]
    out = []
    nums = [tuple(int(x) for x in r.split(".")) for r, _ in rows]
    if nums != sorted(set(nums)):
        out.append(f"{REVISIONS}: revision numbers are not strictly increasing: {[r for r, _ in rows]}")
    newest, digest = rows[-1]
    if newest != m.group(1):
        out.append(f"SPEC.md says revision {m.group(1)}, but the newest row of {REVISIONS} is {newest}")
    actual = hashlib.sha256(spec).hexdigest()
    if digest != actual:
        out.append(f"{REVISIONS} records SHA-256 {digest[:16]}… for revision {newest}, but SPEC.md "
                   f"is {actual}: the text changed without its published record")
    return out


def main() -> int:
    ids = spec_errata()
    if not ids:
        print("FATAL: SPEC.md errata table parsed to zero entries", file=sys.stderr)
        return 2
    fail = []
    for rel in PAGES:
        p = ROOT / rel
        if not p.is_file():
            fail.append(f"{rel} is missing")
            continue
        html = p.read_text(errors="ignore")
        missing = [e for e in ids if f"<b>{e}</b>" not in html]
        if missing:
            fail.append(f"{rel} omits errata {missing} that SPEC.md publishes")
    fail += revision_problems()
    if fail:
        print("STANDARD FORMS DISAGREE:", file=sys.stderr)
        for f in fail:
            print("  " + f, file=sys.stderr)
        print("\nRegenerate with: python3 standard/build_standard.py", file=sys.stderr)
        return 1
    print(f"  standard consistent: {len(ids)} errata ({', '.join(ids)}) present in both forms; "
          f"SPEC.md is the published revision it names")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
