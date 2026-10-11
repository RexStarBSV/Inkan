#!/usr/bin/env python3
"""Fail-loud doctrine guard (rule 8).

Inkan is a LIBRARY, and that sharpens rule 1: a library must never swallow on the caller's
behalf. The distinction the doctrine turns on —

    "could not verify"  is NOT  "verified as invalid"

— is exactly what a seal-verification library must never blur. A verification that could not be
PERFORMED and a verification that FAILED are different results, and a caller must be able to
tell them apart. Swallowing an exception collapses them into one.

Checks both implementations (Python and JS) for handlers whose body does nothing.

    python3 tools/check_no_silent_handlers.py
"""
import ast
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# `.venv`/`site-packages` sit beside `node_modules` for the same reason: this gate measures whether
# THIS project swallows failures, and a vendored dependency's handlers are not ours to answer for.
# Left out, the run reported nine `except: pass` sites inside urllib3 and one of our own — which is
# how a fail-loud gate teaches people to skim past it. Both trees are gitignored; neither ships.
SKIP = ("node_modules", "/dist/", "/test/", "test_", ".min.", "/.venv/", "site-packages")


def python_offenders():
    for path in sorted(ROOT.rglob("*.py")):
        if any(k in str(path) for k in SKIP) or path.name == "check_no_silent_handlers.py":
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                body = [s for s in node.body if not isinstance(s, ast.Pass)]
                if not body:
                    yield f"{path.relative_to(ROOT)}:{node.lineno}  except: pass"


def js_offenders():
    for path in sorted(ROOT.rglob("*.js")):
        if any(k in str(path) for k in SKIP):
            continue
        text = path.read_text(errors="ignore")
        for m in re.finditer(r"catch\s*(?:\([^)]*\))?\s*\{", text):
            depth, j = 1, m.end()
            while j < len(text) and depth:
                depth += (text[j] == "{") - (text[j] == "}")
                j += 1
            body = re.sub(r"//[^\n]*|/\*.*?\*/", "", text[m.end():j - 1], flags=re.S).strip()
            if not body:
                yield f"{path.relative_to(ROOT)}:{text[:m.start()].count(chr(10)) + 1}  empty catch"


def main() -> int:
    offenders = list(python_offenders()) + list(js_offenders())

    # self-test: the guard must not rot into a no-op
    probe = ROOT / "tools" / ".probe.py"
    probe.write_text("try:\n    f()\nexcept Exception:\n    pass  # nothing\n")
    try:
        tree = ast.parse(probe.read_text())
        handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)]
        assert handlers and not [s for s in handlers[0].body if not isinstance(s, ast.Pass)], \
            "the guard no longer detects a silent handler"
    finally:
        probe.unlink()

    if offenders:
        print("SILENT HANDLERS (fail-loud doctrine rule 1):", file=sys.stderr)
        for o in offenders:
            print(f"  {o}", file=sys.stderr)
        print("\nA verification that could not be PERFORMED is not a verification that FAILED.",
              file=sys.stderr)
        return 1
    print("fail-loud: no silent handlers in Inkan")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
