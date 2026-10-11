#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Render, or check, the six example seals at the top of README.md.

Each example is a (data, kind) pair shown with the image of its canonical seal, so a reader can
enter the data in the verifier, choose the kind, and get the same seal and the same ik1 code. The
first five images are written here, by the reference implementation, into examples/seals/. The
sixth is the verifier page's own published seal, its sidecar web/inkan-verify.html.inkan.png,
which tools/emit_sidecar_seal.py writes; this tool only checks it.

--check confirms that every image is exactly the seal of its data and kind (pixel for pixel, as the
verifier compares) and that README.md shows each image, its short code, and a row naming its data,
kind and full code. It writes nothing; python/tests/test_verify.py runs it.

Usage:
    python3 tools/emit_readme_seals.py            # render the five example images
    python3 tools/emit_readme_seals.py --check    # verify the images and the README, write nothing
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "python"))

from inkan_standard import seal as inkan_seal                                   # noqa: E402
from inkan_standard.seed import inkan_digest                                    # noqa: E402
from inkan_standard.verify import canonical_seal, verify_seal                    # noqa: E402

PAGE = "web/inkan-verify.html"
SCALE = 4       # 896 x 896 pixels: sharp at the README's display width on high-density screens


def _page_sha256() -> str:
    with open(os.path.join(ROOT, PAGE), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def examples() -> list[tuple[str, str, str, str]]:
    """(image, title, data, kind), in the README's order. The empty kind is the standard's default,
    which the verifier lists as "(generic)". The identity key is the published test key of
    test-vectors/canary-vectors.json (private key 0x01 x 32), never a production key."""
    return [
        ("examples/seals/bitcoin.png", "Bitcoin", "Bitcoin", ""),
        ("examples/seals/bsv.png", "BSV", "BSV", ""),
        ("examples/seals/inkan.png", "Inkan", "Inkan", ""),
        ("examples/seals/address.png", "Payment address", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address"),
        ("examples/seals/identity.png", "Identity key",
         "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", "identity"),
        (PAGE + ".inkan.png", "This verifier page", _page_sha256(), "code"),
    ]


def readme_row(title: str, data: str, kind: str) -> str:
    """The row of the README's table that names an example's data, kind and full code."""
    label = "(generic)" if kind == "" else "`%s`" % kind
    return "| %s | `%s` | %s | `%s` |" % (title, data, label, canonical_seal(data, kind)["code"])


def render() -> None:
    for image, _title, data, kind in examples():
        if not image.startswith("examples/"):
            continue                                     # the page's sidecar is not ours to write
        png = inkan_seal.seal_png(inkan_digest(data, kind), kind=kind, scale=SCALE, tag=True)
        path = os.path.join(ROOT, image)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(png)
        print("wrote", image)


def check() -> list[str]:
    """Every problem found, as text. An empty list means the images and the README agree."""
    problems = []
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        readme = f.read()
    for image, title, data, kind in examples():
        path = os.path.join(ROOT, image)
        if not os.path.isfile(path):
            problems.append("%s: missing" % image)
            continue
        with open(path, "rb") as f:
            result = verify_seal(data, kind, f.read())
        if not result.ok:
            problems.append("%s is not the seal of %r under kind %r: %s" % (image, data, kind, result.summary))
        for want, what in (('src="%s"' % image, "the image"),
                           (canonical_seal(data, kind)["short_code"], "the short code"),
                           (readme_row(title, data, kind), "the row naming its data, kind and code")):
            if want not in readme:
                problems.append("README.md does not show %s for %s: %s" % (what, title, want))
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Render or check the README's example seals.")
    ap.add_argument("--check", action="store_true", help="verify only; exit 1 on any problem")
    args = ap.parse_args(argv)
    if not args.check:
        render()
    problems = check()
    for p in problems:
        print("PROBLEM:", p, file=sys.stderr)
    if problems:
        return 1
    print("README seals: %d examples, each the exact seal of its data and kind" % len(examples()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
