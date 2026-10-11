#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# SPDX-FileCopyrightText: 2026 RexStarBSV
"""Build the PyPI distribution `inkan-standard` — the Apache-2.0 verification path, and nothing else.

The DISTRIBUTION is `inkan-standard`, and the IMPORT package inside it is `inkan_standard`. The bare
PyPI name `inkan` has belonged to an unrelated project since 2026-09-03, so `pip install inkan` would
install someone else's code, and that project's import package is also called `inkan`; naming ours
`inkan_standard` lets both be installed in one environment without one shadowing the other. Every
install instruction this tool emits says `inkan-standard`.

This repository is deliberately multi-licence (see LICENSING.md). Only the files named in NOTICE
are Apache-2.0; everything else, `python/inkan_standard/anchor.py` included, is BSL 1.1 and MUST NOT ship in
a package that declares itself Apache-2.0. Getting that wrong publishes a false licence claim to an
index where **version numbers can never be reused** — there is no taking it back.

So the file list is not written here. It is READ OUT OF NOTICE at build time, and every staged file
must carry an `SPDX-License-Identifier: Apache-2.0` header to be included. If NOTICE and the headers
ever disagree, the build stops rather than guessing which one is right.

The wheel is then re-opened and checked against the same list before it is offered for upload, so a
staging bug cannot slip a BSL file into a published artifact.

    python3 tools/build_pypi.py                  # build into dist/
    python3 tools/build_pypi.py --check          # verify only, write nothing
    python3 tools/build_pypi.py --upload-test    # rehearse on TestPyPI
    python3 tools/build_pypi.py --upload         # publish to PyPI (permanent)

Build tooling lives in `.venv/` inside this repository and is created on first run. It is
deliberately NOT a throwaway in /tmp: publishing is a recurring act, and a release procedure whose
commands stop existing when a temp directory is cleaned is not a procedure. `.venv` is gitignored,
so it never enters the repository or a release cut.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
VENV = ROOT / ".venv"

# Named in LICENSING.md as BSL 1.1 — the on-chain anchoring/broadcast module. Never packaged here.
FORBIDDEN = {"anchor.py"}

VERSION = "1.0.0"

# The PyPI distribution name, and the stem setuptools gives its files (PEP 625 / wheel naming:
# hyphens become underscores). The import package has the same name, `inkan_standard`.
DIST_NAME = "inkan-standard"
DIST_STEM = "inkan_standard"

PYPROJECT = '''\
[build-system]
# 77 is the first setuptools that accepts `license` as an SPDX expression and `license-files` in
# [project] (PEP 639); an older one rejects this file instead of building it.
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[project]
name = "{dist_name}"
version = "{version}"
description = "Verify Inkan seals, code fingerprints and warrant canaries — the Apache-2.0 verification path of the Inkan Standard (BRC-145)"
readme = "README.md"
requires-python = ">=3.9"
# The code is Apache-2.0; the conformance vectors packaged for the self-test are CC0.
license = "Apache-2.0 AND CC0-1.0"
license-files = ["LICENSE-VERIFY", "NOTICE", "LICENSE-VECTORS"]
authors = [{{ name = "RexStarBSV", email = "RexStarBSV@protonmail.com" }}]
keywords = ["inkan", "brc-145", "provenance", "verification", "canary", "fingerprint", "bsv"]
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "Intended Audience :: Developers",
    "Programming Language :: Python :: 3",
    "Topic :: Security :: Cryptography",
    "Topic :: Software Development :: Libraries",
]

# NO REQUIRED DEPENDENCIES, deliberately. Verification falls back to the bundled pure-Python
# secp256k1 (differentially tested against bitcoinx, 0 divergences over 1270 cases) when bitcoinx
# is absent, so a verifier never goes dark because an install failed. Signing is operator-side.
dependencies = []

[project.optional-dependencies]
sign = ["bitcoinx>=0.6"]

[project.urls]
Homepage = "https://github.com/RexStarBSV/Inkan"
Specification = "https://github.com/bsv-blockchain/BRCs/blob/master/apps/0145.md"

[tool.setuptools]
packages = ["inkan_standard"]

# The conformance vectors ship INSIDE the wheel. Without them `python -m inkan_standard.verify selftest`
# cannot run in an installed environment, and the module docstring's promise that "the verifier
# verifies ITSELF" held only for people with the source checkout.
[tool.setuptools.package-data]
inkan_standard = ["vectors/*.json"]
'''

README = '''\
# inkan-standard

The **verification path** of the Inkan Standard — [BRC-145](https://github.com/bsv-blockchain/BRCs/blob/master/apps/0145.md),
a registry-free typed content anchor with on-chain code provenance.

This package verifies three things, offline, with no network and no keys:

| | |
|---|---|
| **Content anchors and seals** | that an `ik1` code and its rendered seal are the canonical pair for a given `(data, kind)` |
| **Code fingerprints** | that a release binary matches the fingerprint its publisher claims |
| **Warrant canaries** | that a signed, freshness-proofed operator statement is valid, stale, or forged |

```python
from inkan_standard import verify

r = verify.canonical_seal("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address")
print(r["code"])        # ik112cf1aaca7ef5079...
```

## No required dependencies

Verification never goes dark because an install failed. `bitcoinx` is used for ECDSA when present;
otherwise the bundled pure-Python `_secp256k1` takes over — differentially tested against bitcoinx
across 1270 cases with zero divergences. Signing a canary is operator-side and needs the extra:

```sh
pip install inkan-standard            # verify
pip install "inkan-standard[sign]"    # verify + sign your own canary
```

The distribution is `inkan-standard`, and the package you import is `inkan_standard`. An unrelated
PyPI project named `inkan` installs an import package called `inkan`; the two names do not collide.

## Licence

The code in this distribution is **Apache-2.0** — the verification path only, with a patent grant.
You may verify Inkan codes and seals, and generate your own, in any product, commercial or not,
forever.

The wider Inkan repository is multi-licence: the specification is CC BY 4.0, the conformance
vectors are CC0, and the product tier (on-chain anchoring, minting workflows, application surfaces)
is BSL 1.1 until 2030-07-09. **None of the BSL-licensed code is in this package.** See `NOTICE` for
the exact file list this Apache-2.0 grant covers. The conformance vectors bundled for the self-test
(`inkan_standard/vectors/*.json`) are CC0, per the included `LICENSE-VECTORS`.
'''


def tooling_python() -> str:
    """Path to the interpreter that owns `build` and `twine`, creating it on first use."""
    py = VENV / "bin" / "python"
    if not py.is_file():
        print(f"  creating build environment in {VENV.relative_to(ROOT)}/ (first run)")
        subprocess.run([sys.executable, "-m", "venv", str(VENV)], check=True)
    have = subprocess.run([str(py), "-c", "import build, twine"], capture_output=True)
    if have.returncode != 0:
        print("  installing build + twine")
        r = subprocess.run([str(py), "-m", "pip", "install", "-q", "--upgrade",
                            "pip", "build", "twine"], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("FATAL: could not install build tooling\n" + r.stderr[-2000:])
    return str(py)


def check_urls(whl: pathlib.Path) -> None:
    """Every Project-URL in the wheel must resolve before it is published.

    METADATA bakes `Homepage` in permanently, and an index version number can never be reused. On
    2026-08-04 that Homepage pointed at a GitHub repository that returns 404 -- publishing before the
    repo went public would have shipped a dead link to real users, forever, at 1.0.0. This is purely
    a SEQUENCING hazard: nothing is wrong with the URL except that it does not exist yet.
    """
    import urllib.request
    import zipfile
    with zipfile.ZipFile(whl) as z:
        meta = z.read([n for n in z.namelist() if n.endswith("METADATA")][0]).decode()
    urls = [l.split(",", 1)[1].strip() for l in meta.splitlines() if l.startswith("Project-URL:")]
    dead = []
    for u in urls:
        try:
            req = urllib.request.Request(u, method="HEAD", headers={"User-Agent": "inkan-release"})
            with urllib.request.urlopen(req, timeout=15) as r:
                if r.status >= 400:
                    dead.append((u, r.status))
        except Exception as e:
            dead.append((u, getattr(e, "code", type(e).__name__)))
    if dead:
        raise SystemExit("FATAL: the wheel bakes in URL(s) that do not resolve:\n" +
                         "\n".join("  %s -> %s" % d for d in dead) +
                         "\n\nA published version number can never be reused, so a dead link ships "
                         "permanently. Make the URL live, or remove it from pyproject, then rebuild.")
    print("  project URLs: %d checked, all resolve" % len(urls))


def upload(py: str, test: bool) -> int:
    """Hand off to twine. The token is typed at twine's own prompt and never passed as an argument,
    so it stays out of shell history and out of the process list."""
    files = sorted(DIST.glob("%s-%s*" % (DIST_STEM, VERSION)))
    if not files:
        raise SystemExit("FATAL: nothing in dist/ to upload — run without --upload first")
    check_urls([f for f in files if f.suffix == ".whl"][0])
    cmd = [str(pathlib.Path(py).with_name("twine")), "upload"]
    if test:
        cmd += ["--repository", "testpypi"]
    cmd += [str(f) for f in files]
    print("  %s\n  username is __token__; the password prompt takes your API token"
          % " ".join(cmd))
    return subprocess.run(cmd).returncode


def notice_files() -> list[str]:
    """The Apache-2.0 file list, read from NOTICE rather than restated here."""
    text = (ROOT / "NOTICE").read_text()
    names = re.findall(r"^\s+python/inkan_standard/(\S+\.py)\s*$", text, re.M)
    if not names:
        raise SystemExit("FATAL: no python/inkan_standard/*.py entries found in NOTICE — its format changed, "
                         "and guessing the licensed file set is exactly what this script exists to "
                         "avoid")
    bad = sorted(set(names) & FORBIDDEN)
    if bad:
        raise SystemExit(f"FATAL: NOTICE lists {bad} as Apache-2.0, but LICENSING.md places it under "
                         f"BSL 1.1. Resolve the contradiction before publishing anything.")
    return sorted(set(names))


def verify_headers(names: list[str]) -> None:
    for n in names:
        p = ROOT / "python" / "inkan_standard" / n
        if not p.is_file():
            raise SystemExit(f"FATAL: NOTICE lists {n} but the file does not exist")
        if "SPDX-License-Identifier: Apache-2.0" not in p.read_text():
            raise SystemExit(f"FATAL: {n} is listed in NOTICE as Apache-2.0 but carries no matching "
                             f"SPDX header. NOTICE and the source disagree; do not publish.")
    for p in (ROOT / "python" / "inkan_standard").glob("*.py"):
        if p.name in names or p.name in FORBIDDEN:
            continue
        raise SystemExit(f"FATAL: {p.name} exists in the package directory but is in neither NOTICE "
                         f"nor the forbidden list. Classify it before publishing.")


def stage(names: list[str], into: pathlib.Path) -> pathlib.Path:
    pkg = into / "inkan_standard"
    pkg.mkdir(parents=True)
    for n in names:
        shutil.copy2(ROOT / "python" / "inkan_standard" / n, pkg / n)
    (into / "pyproject.toml").write_text(PYPROJECT.format(version=VERSION, dist_name=DIST_NAME))
    (into / "README.md").write_text(README)
    for f in ("LICENSE-VERIFY", "NOTICE", "LICENSE-VECTORS"):
        shutil.copy2(ROOT / f, into / f)
    vec = pkg / "vectors"
    vec.mkdir()
    for v in ("seal-v3-vectors.json", "vectors.json", "normalization-vectors.json"):
        src = ROOT / "test-vectors" / v
        if src.is_file():
            shutil.copy2(src, vec / v)
    if not (vec / "seal-v3-vectors.json").is_file():
        raise SystemExit("FATAL: seal-v3-vectors.json missing -- the wheel would ship a selftest "
                         "that cannot run, which is the exact defect this staging step exists to "
                         "prevent")
    return into


def audit_wheel(whl: pathlib.Path, names: list[str]) -> None:
    """Re-open the built artifact. Staging bugs are exactly what a published wheel must not carry."""
    with zipfile.ZipFile(whl) as z:
        members = {m for m in z.namelist() if m.startswith("inkan_standard/") and m.endswith(".py")}
    got = {m.split("/", 1)[1] for m in members}
    want = set(names)
    if got != want:
        raise SystemExit(f"FATAL: wheel contents do not match NOTICE.\n  missing: {sorted(want - got)}"
                         f"\n  unexpected: {sorted(got - want)}")
    for f in FORBIDDEN:
        if f in got:
            raise SystemExit(f"FATAL: BSL-licensed {f} is inside an Apache-2.0 wheel — do not upload")
    print(f"  wheel audited: {len(got)} modules, exactly the NOTICE set, no BSL files")


def smoke_test(whl: pathlib.Path) -> None:
    """Install the wheel in a throwaway venv and make it verify ITSELF.

    audit_wheel() only ever checked licence membership. Nothing checked that the artifact FUNCTIONS,
    so a 1.0.0 wheel shipped a module docstring promising "the verifier verifies ITSELF" while being
    unable to execute that promise -- the vectors were not packaged, and the failure was visible only
    to someone who installed it and tried. A licence-correct wheel that does not work is still a bad
    wheel, and on an index the version number cannot be reused.
    """
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        venv = pathlib.Path(tmp) / "v"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True)
        py = venv / "bin" / "python"
        r = subprocess.run([str(py), "-m", "pip", "install", "-q", str(whl)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("FATAL: the built wheel does not install\n" + r.stderr[-1500:])
        r = subprocess.run([str(py), "-m", "inkan_standard.verify", "selftest"],
                           capture_output=True, text=True)
        if r.returncode != 0 or "95/95" not in (r.stdout + r.stderr):
            raise SystemExit("FATAL: the installed wheel cannot verify itself -- it must not be "
                             "published.\n" + (r.stdout + r.stderr)[-1500:])
        # a dependency-free install must stay dependency-free
        r2 = subprocess.run([str(py), "-m", "pip", "list", "--format=freeze"],
                            capture_output=True, text=True)
        extra = [l.split("==")[0] for l in r2.stdout.split()
                 if l and l.split("==")[0].lower().replace("_", "-")
                 not in (DIST_NAME, "pip", "setuptools", "wheel")]
        if extra:
            raise SystemExit("FATAL: the wheel pulled in %s; it claims no required dependencies"
                             % extra)
        print("  smoke test: installs clean, self-verifies 95/95, pulls in nothing else")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="verify only; build nothing")
    ap.add_argument("--upload", action="store_true", help="publish to PyPI — permanent, unrepeatable")
    ap.add_argument("--upload-test", action="store_true", help="publish to TestPyPI as a rehearsal")
    args = ap.parse_args()

    names = notice_files()
    verify_headers(names)
    print(f"  NOTICE lists {len(names)} Apache-2.0 modules: {', '.join(names)}")
    print(f"  excluded as BSL 1.1: {', '.join(sorted(FORBIDDEN))}")
    if args.check:
        print("  --check: source and NOTICE agree; nothing written")
        return 0

    py = tooling_python()
    with tempfile.TemporaryDirectory() as tmp:
        src = stage(names, pathlib.Path(tmp) / "pkg")
        r = subprocess.run([py, "-m", "build", "--outdir", str(DIST), str(src)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("FATAL: build failed\n" + r.stdout[-3000:] + r.stderr[-3000:])

    whls = sorted(DIST.glob("%s-%s-*.whl" % (DIST_STEM, VERSION)))
    if not whls:
        raise SystemExit("FATAL: no wheel produced")
    audit_wheel(whls[-1], names)
    smoke_test(whls[-1])
    chk = subprocess.run([str(pathlib.Path(py).with_name("twine")), "check", *map(str, DIST.iterdir())],
                         capture_output=True, text=True)
    print("  twine check: %s" % ("PASSED" if chk.returncode == 0 else "FAILED\n" + chk.stdout))
    if chk.returncode != 0:
        return 1
    for f in sorted(DIST.iterdir()):
        print("  %-44s %7.1f KB" % (f.name, f.stat().st_size / 1024))

    if args.upload or args.upload_test:
        return upload(py, test=args.upload_test)
    print("\n  to publish:  python3 tools/build_pypi.py --upload-test   (rehearsal)")
    print("               python3 tools/build_pypi.py --upload        (permanent)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
