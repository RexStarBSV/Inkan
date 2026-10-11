#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Gate: the licence map, the SPDX headers and the shipped manifests must all agree.

Inkan is deliberately multi-licence (LICENSING.md). Three separate artifacts assert which files are
Apache-2.0 — NOTICE, the per-file SPDX headers, and the package manifests — and nothing until now
checked that they said the same thing. They had already drifted twice:

  * `python/inkan_standard/seal_tables.py` is generated, and the generator emitted no SPDX header. The header
    was added by hand afterwards, so the next regeneration would have silently stripped it and left
    a file NOTICE calls Apache-2.0 carrying no grant at all.
  * The JS and Kotlin engines carried no headers whatsoever while LICENSING.md placed them under BSL
    and their own docstrings described them as ports of Apache-2.0 code.

A licence is a claim made to other people. A claim nobody verifies is one that quietly stops being
true. This runs in CI and before any release cut.

THE MAP MUST BE COMPLETE, NOT ONLY CONSISTENT (2026-10-10). A readiness review found four files the
map never placed where it meant to: LICENSE-VERIFY named only the Python files, so the JS, Kotlin and
web files NOTICE lists never received the Apache grant the documents describe; `index.d.ts` declared
Apache-2.0 but sat outside NOTICE, because this gate never looked at `.ts`; a third vector file was
CC0 in the README and BSL in fact; and the Gradle wrapper was swept into BSL, which would have
"converted" Gradle's code to MIT in 2030. Each was a list nobody compared with another list. So every
designation document is now parsed and held to the others:

  * LICENSE-VERIFY lists exactly the files NOTICE lists;
  * no file is named by two designations (LICENSE-SPEC, LICENSE-VECTORS, NOTICE, LICENSE-GRADLE);
  * every file a designation names exists, every file in test-vectors/ is CC0, every Gradle
    wrapper file is Gradle's, and every sidecar record (`*.inkan.json`, `*.inkan.png`) is CC0:
    LICENSE's Additional Use Grant says sidecar records are not the Licensed Work, so the
    Licensor's own must not fall through to BSL either;
  * no font file falls through to BSL, and no embedded font still uses the Reserved Font Name;
  * the mark (LicenseRef-Inkan-Mark) and the embedded font (OFL-1.1) are carved out of the Apache
    pages as SPDX snippets that contain all of that material, and nothing outside them;
  * LICENSE's Licensed Work parameter excludes every designation document by name.

    python3 tools/check_licence_map.py          # exit 1 on any disagreement
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
APACHE = "SPDX-License-Identifier: Apache-2.0"

# Files that must NOT claim Apache-2.0 — the product tier, per LICENSING.md.
MUST_NOT_BE_APACHE = ["python/inkan_standard/anchor.py"]

# Trees whose sources are either wholly in NOTICE or wholly BSL; a stray Apache header inside one is
# a false public claim, which is worse than a missing one.
SOURCE_TREES = [("python/inkan_standard", "*.py"), ("js/src", "*.js"), ("js/src", "*.ts"),
                ("kotlin/src/main/kotlin/inkan", "*.kt")]

# npm cannot include files above the package root, so these are copies. Copies drift.
MIRRORED = [("LICENSE-VERIFY", "js/LICENSE-VERIFY"), ("NOTICE", "js/NOTICE")]


_FILE_LINE = r"^\s+((?:python|js|kotlin|web)/\S+\.(?:py|js|ts|kt|html))\s*$"


def notice_covered() -> set[str]:
    text = (ROOT / "NOTICE").read_text()
    body = text.split("--------")[0]           # stop before the third-party sections
    return set(re.findall(_FILE_LINE, body, re.M))


def _preamble(name: str) -> str:
    """The designation part of a licence document: everything before the licence text itself."""
    return (ROOT / name).read_text().split("=" * 20)[0]


def _licence_text(name: str) -> str:
    """The licence text of a designation document: everything below its rule line of '='."""
    parts = re.split(r"^=+$", (ROOT / name).read_text(encoding="utf-8"), maxsplit=1, flags=re.M)
    return parts[1].strip("\n") if len(parts) == 2 else ""


def listed(name: str) -> list[str]:
    """Repo-relative paths a designation document names, one per indented line."""
    return re.findall(r"^\s+([\w.-]+(?:/[\w.-]+)+|[\w-]+\.\w+)\s*$", _preamble(name), re.M)


DESIGNATIONS = ("LICENSE-SPEC", "LICENSE-VECTORS", "LICENSE-VERIFY", "LICENSE-FONTS",
                "LICENSE-GRADLE", "LICENSE-MARK")
MARK_ID = "SPDX-License-Identifier: LicenseRef-Inkan-Mark"
FONT_SUFFIXES = (".ttf", ".otf", ".woff", ".woff2")
GRADLE_WRAPPER = ("kotlin/gradlew", "kotlin/gradlew.bat")
GRADLE_WRAPPER_DIR = "kotlin/gradle/wrapper/"
SIDECAR_SUFFIXES = (".inkan.json", ".inkan.png")
RESERVED_FONT_NAME = "Plex"
WALK_SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist", ".gradle",
             ".pytest_cache"}


def all_files() -> list[str]:
    """Every file that would ship from this tree: tracked plus untracked-but-not-ignored when git is
    available (the release cut copies the WORKING TREE, so an untracked file ships too), else a walk
    of the tree with the cut's own skip set."""
    import subprocess
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-co", "--exclude-standard"],
                             capture_output=True, text=True).stdout.split("\n")
    except OSError:
        out = []
    files = [f for f in out if f and (ROOT / f).is_file()]
    if files:
        return sorted(files)
    found = []
    for q in ROOT.rglob("*"):
        if q.is_file() and not any(part in WALK_SKIP for part in q.relative_to(ROOT).parts):
            found.append(str(q.relative_to(ROOT)))
    return sorted(found)


def _header(rel: str) -> str:
    try:
        return "\n".join((ROOT / rel).read_text(errors="ignore").split("\n")[:24])
    except OSError:
        return ""


def _font_names(font: bytes) -> list[str]:
    """Family, unique, full and PostScript names (nameIDs 1, 3, 4, 6, 16, 17) of a TrueType font."""
    import struct
    names = []
    count = struct.unpack(">H", font[4:6])[0]
    for i in range(count):
        tag, _cs, off, _ln = struct.unpack(">4sIII", font[12 + 16 * i:28 + 16 * i])
        if tag != b"name":
            continue
        _fmt, n, base = struct.unpack(">HHH", font[off:off + 6])
        for j in range(n):
            pid, _eid, _lid, nid, ln, so = struct.unpack(">HHHHHH", font[off + 6 + 12 * j:off + 18 + 12 * j])
            raw = font[off + base + so:off + base + so + ln]
            if nid in (1, 3, 4, 6, 16, 17):
                names.append(raw.decode("utf-16-be" if pid in (0, 3) else "latin-1", "replace"))
    return names


def _snippets(text: str) -> list[tuple[str, str]]:
    """(licence identifier, body) for every SPDX snippet in a page."""
    out = []
    for m in re.finditer(r"SPDX-SnippetBegin(.*?)SPDX-SnippetEnd", text, re.S):
        ident = re.search(r"SPDX-License-Identifier:\s*([\w.+-]+)", m.group(1))
        out.append((ident.group(1) if ident else "", m.group(1)))
    return out


def check_complete(covered: set[str], fail: list[str]) -> dict:
    files = set(all_files())
    for d in DESIGNATIONS:
        if not (ROOT / d).is_file():
            fail.append(f"{d} is missing: the map in LICENSING.md names it")
    if any(not (ROOT / d).is_file() for d in DESIGNATIONS):
        return {}

    verify = set(listed("LICENSE-VERIFY"))
    if verify != covered:
        fail.append("LICENSE-VERIFY and NOTICE disagree about the Apache-2.0 files: "
                    f"only in NOTICE {sorted(covered - verify)}, only in LICENSE-VERIFY "
                    f"{sorted(verify - covered)}. LICENSE-VERIFY is the grant; NOTICE is its index.")

    lists = {"LICENSE-SPEC": set(listed("LICENSE-SPEC")),
             "LICENSE-VECTORS": {f for f in listed("LICENSE-VECTORS") if "/" in f
                                 and not f.startswith("inkan_standard/")},
             "NOTICE": covered,
             "LICENSE-GRADLE": set(listed("LICENSE-GRADLE"))}
    seen: dict[str, str] = {}
    for name, entries in lists.items():
        for f in sorted(entries):
            if f in seen:
                fail.append(f"{f} is designated twice, by {seen[f]} and by {name}: every file "
                            f"must fall under exactly one licence")
            seen[f] = name
            if not (ROOT / f).is_file():
                fail.append(f"{name} names {f}, which does not exist")

    for f in sorted(files):
        if f.startswith("test-vectors/") and f.endswith(".json") and f not in lists["LICENSE-VECTORS"]:
            fail.append(f"{f} is a conformance vector file but LICENSE-VECTORS does not list it, so "
                        f"it is BSL by default; the map promises every vector is CC0")
        if f.endswith(SIDECAR_SUFFIXES) and f not in lists["LICENSE-VECTORS"]:
            fail.append(f"{f} is a sidecar record but LICENSE-VECTORS does not list it, so it is BSL "
                        f"by default, while LICENSE says sidecar records are not the Licensed Work")
        if (f in GRADLE_WRAPPER or f.startswith(GRADLE_WRAPPER_DIR)) and f not in lists["LICENSE-GRADLE"]:
            fail.append(f"{f} is Gradle's wrapper but LICENSE-GRADLE does not list it, so it falls "
                        f"under BSL and would 'convert' Gradle's code to MIT")

    font_names = set(re.findall(r"[\w.-]+\.(?:ttf|otf|woff2?)\b", _preamble("LICENSE-FONTS")))
    marks = []
    for f in sorted(files):
        base = f.rsplit("/", 1)[-1]
        if f.endswith(FONT_SUFFIXES):
            if base not in font_names:
                fail.append(f"{f} is a font file LICENSE-FONTS does not designate: it would fall "
                            f"under BSL, and the 2030 conversion cannot relicense someone else's font")
            elif any(RESERVED_FONT_NAME in n for n in _font_names((ROOT / f).read_bytes())):
                fail.append(f"{f} still names itself with the Reserved Font Name "
                            f"{RESERVED_FONT_NAME!r}; a Modified Version may not (OFL section 3)")
        # The licence documents themselves are not artwork, even LICENSE-MARK, whose header names
        # the identifier it defines.
        is_doc = f in DESIGNATIONS or f in ("LICENSE", "NOTICE") or f.startswith("js/LICENSE")
        head = "" if is_doc or f.endswith(FONT_SUFFIXES + (".png", ".jar")) else _header(f)
        if MARK_ID in head:
            marks.append(f)
            if f in seen:
                fail.append(f"{f} declares itself the Inkan mark but {seen[f]} also designates it")
        elif f.endswith(".svg"):
            fail.append(f"{f} is vector artwork with no LicenseRef-Inkan-Mark header; the only "
                        f"artwork in this repository is the mark, which is all rights reserved")

    pages = sorted(c for c in covered if c.endswith(".html"))
    ofl_text = _licence_text("LICENSE-FONTS")
    if "SIL OPEN FONT LICENSE Version 1.1" not in ofl_text:
        fail.append("LICENSE-FONTS does not hold the SIL OFL 1.1 text below its rule line")
    for rel in pages:
        text = (ROOT / rel).read_text(errors="ignore")
        snips = _snippets(text)
        ofl = [b for i, b in snips if i == "OFL-1.1"]
        mark = [b for i, b in snips if i == "LicenseRef-Inkan-Mark"]
        outside = re.sub(r"SPDX-SnippetBegin.*?SPDX-SnippetEnd", "", text, flags=re.S)
        if len(ofl) != 1 or "data:font/" not in ofl[0]:
            fail.append(f"{rel}: expected one OFL-1.1 SPDX snippet holding the embedded font, "
                        f"found {len(ofl)}")
        elif not ofl_text or ofl_text not in ofl[0]:
            # OFL condition 2: every copy of the font contains IBM's notice and the licence. A page
            # is copied on its own, so the text must travel inside it, not only in LICENSE-FONTS.
            fail.append(f"{rel}: the OFL-1.1 snippet does not reproduce IBM's notice and the full "
                        f"licence text from LICENSE-FONTS, which OFL condition 2 requires of every "
                        f"copy of the font")
        if len(mark) != 1 or "<svg" not in mark[0]:
            fail.append(f"{rel}: expected one LicenseRef-Inkan-Mark SPDX snippet holding the mark, "
                        f"found {len(mark)}")
        if "data:font/" in outside:
            fail.append(f"{rel}: embedded font data outside the OFL-1.1 snippet would read as Apache-2.0")
        if 'class="mark"><svg' in outside or 'class="mark"><svg' in text:
            fail.append(f"{rel}: the mark is embedded outside its LicenseRef-Inkan-Mark snippet")
        for decl in re.findall(r"font-family\s*:\s*([^;}]+)", text) + re.findall(r"font:[^;}]*", text):
            if RESERVED_FONT_NAME in decl:
                fail.append(f"{rel}: CSS still names the Reserved Font Name: {decl.strip()[:60]}")
                break
        import base64
        for b64 in re.findall(r"data:font/\w+;base64,([A-Za-z0-9+/=]+)", text):
            if any(RESERVED_FONT_NAME in n for n in _font_names(base64.b64decode(b64))):
                fail.append(f"{rel}: an embedded font still names itself with the Reserved Font "
                            f"Name {RESERVED_FONT_NAME!r}")
                break

    params = (ROOT / "LICENSE").read_text().split("Additional Use Grant:")[0]
    for d in DESIGNATIONS:
        if d not in params:
            fail.append(f"LICENSE's Licensed Work parameter does not exclude {d}; whatever {d} "
                        f"designates would also be BSL, and so MIT in 2030")

    pypi = (ROOT / "tools" / "build_pypi.py")
    if pypi.is_file() and "vectors" in pypi.read_text():
        lf = re.search(r"license-files\s*=\s*\[([^\]]*)\]", pypi.read_text())
        if not lf or "LICENSE-VECTORS" not in lf.group(1):
            fail.append("tools/build_pypi.py packages the conformance vectors but its license-files "
                        "omit LICENSE-VECTORS, so the wheel would carry CC0 files with no CC0 text")
    return {"designated": len(seen), "marks": len(marks), "pages": len(pages)}


def main() -> int:
    fail: list[str] = []
    covered = notice_covered()
    if not covered:
        print("FATAL: NOTICE lists no covered files — its format changed", file=sys.stderr)
        return 2

    for rel in sorted(covered):
        p = ROOT / rel
        if not p.is_file():
            fail.append(f"NOTICE lists {rel}, which does not exist")
        elif APACHE not in p.read_text():
            fail.append(f"{rel} is in NOTICE as Apache-2.0 but carries no matching SPDX header")

    for rel in MUST_NOT_BE_APACHE:
        p = ROOT / rel
        if rel in covered:
            fail.append(f"{rel} is BSL per LICENSING.md but appears in NOTICE")
        elif p.is_file() and APACHE in p.read_text():
            fail.append(f"{rel} is BSL per LICENSING.md but declares Apache-2.0 in its header")

    # Every tracked source file, not just the three engine trees. The audit found five files under
    # tools/ claiming Apache-2.0 over code NOTICE places under BSL — an unintended perpetual patent
    # grant over exactly the tier BSL was retained to protect. Only the HEADER is inspected: several
    # generators legitimately contain the SPDX string as a literal they emit into their output.
    # Discovery must not depend on git. `release_cut.py` builds the public tree WITHOUT a .git
    # directory — that is the whole point of the cut — so `git ls-files` returns nothing there,
    # `tracked` comes back empty, and this loop inspects zero files. Identical bytes, exit 1 in the
    # working repo and exit 0 in the cut: the one place a wrong Apache-2.0 header stops being a typo
    # and becomes a published patent grant nobody can retract. A gate that passes by not running is
    # this repository's named first failure mode. Git stays the fast path; the walk answers when it is
    # unavailable or yields nothing.
    import subprocess
    SUFFIXES = (".py", ".js", ".mjs", ".ts", ".kt", ".html")
    SKIP = {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist", ".gradle"}
    try:
        tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files",
                                  "*.py", "*.js", "*.mjs", "*.ts", "*.kt", "web/*.html"],
                                 capture_output=True, text=True).stdout.split()
    except OSError:
        tracked = []
    if not tracked:
        for p in ROOT.rglob("*"):
            if p.suffix not in SUFFIXES or not p.is_file():
                continue
            rel_parts = p.relative_to(ROOT).parts
            if any(part in SKIP for part in rel_parts):
                continue
            # "web/*.html" was the git pathspec; keep HTML scoped identically so the two discovery
            # paths inspect the same set and cannot disagree about what is in scope.
            if p.suffix == ".html" and rel_parts[0] != "web":
                continue
            tracked.append(str(p.relative_to(ROOT)))
    for rel in sorted(tracked):
        p = ROOT / rel
        if p.is_file():
            head = "\n".join(p.read_text(errors="ignore").split("\n")[:24])
            # Line-anchored: a comment line DECLARING the tag, not prose mentioning it.
            # build_pypi.py documents the tag in its docstring and is not Apache-2.0 itself.
            has = bool(re.search(r"^\s*(?:#|//|\*|<!--)?\s*" + re.escape(APACHE), head, re.M))
            if has and rel not in covered:
                fail.append(f"{rel} declares Apache-2.0 in its header but is not named in NOTICE — "
                            f"a file cannot grant a licence the project has not published")
            if not has and rel in covered:
                fail.append(f"{rel} is named in NOTICE but declares no licence in its header")

    for tree, glob in SOURCE_TREES:
        for p in sorted((ROOT / tree).glob(glob)):
            rel = str(p.relative_to(ROOT))
            has = APACHE in p.read_text()
            if has and rel not in covered:
                fail.append(f"{rel} declares Apache-2.0 but is not named in NOTICE — a file cannot "
                            f"grant a licence the project has not published")
            if not has and rel in covered:
                fail.append(f"{rel} is named in NOTICE but declares no licence")

    for src, dst in MIRRORED:
        a, b = ROOT / src, ROOT / dst
        if not b.is_file():
            fail.append(f"{dst} is missing — the npm tarball would ship without its licence text")
        elif a.read_bytes() != b.read_bytes():
            fail.append(f"{dst} has drifted from {src}; re-copy it")

    pkg = json.loads((ROOT / "js" / "package.json").read_text())
    if pkg.get("license") != "Apache-2.0":
        fail.append(f"js/package.json declares license {pkg.get('license')!r}, expected Apache-2.0")
    if pkg.get("private"):
        fail.append("js/package.json still has private:true and cannot be published")
    if pkg.get("publishConfig", {}).get("access") != "public":
        fail.append("js/package.json lacks publishConfig.access=public; a scoped package would "
                    "default to restricted and the publish would fail")
    for f in ("LICENSE-VERIFY", "NOTICE"):
        if f not in pkg.get("files", []):
            fail.append(f"js/package.json 'files' omits {f}; Apache-2.0 s.4 requires shipping it")

    stats = check_complete(covered, fail)

    if fail:
        print("LICENCE MAP IS INCONSISTENT:", file=sys.stderr)
        for f in fail:
            print("  " + f, file=sys.stderr)
        return 1

    print(f"  licence map consistent: {len(covered)} files Apache-2.0 "
          f"({sum(1 for c in covered if c.startswith('python'))} py, "
          f"{sum(1 for c in covered if c.startswith('js'))} js, "
          f"{sum(1 for c in covered if c.startswith('kotlin'))} kt); "
          f"{len(MUST_NOT_BE_APACHE)} held under BSL; manifests and mirrors agree; "
          f"{stats.get('designated', 0)} files designated exactly once, "
          f"{stats.get('marks', 0)} mark file(s), font and mark carved out of "
          f"{stats.get('pages', 0)} page(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
