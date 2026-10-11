"""Regenerate the `inkan` glyph block of test-vectors/vectors.json.

Self-contained: uses this package's own `inkan_standard.seed` + `inkan_standard.seal`, and needs no other checkout.

    python3 python/tools/gen_inkan_vectors.py
"""
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from inkan_standard import seal
from inkan_standard.seed import inkan_seed

VECTORS = pathlib.Path(__file__).resolve().parents[2] / "test-vectors" / "vectors.json"

CASES = [("Hello", ""), ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address"),
         ("npub1example", "identity"), ("acct-0", "account"), ("signer-01", "signer")]


def main():
    out = []
    for data, kind in CASES:
        seed = inkan_seed(data, kind)
        digest = hashlib.sha256(seed).digest()
        rgb = bytes(c for px in seal.seal_rgb(digest, kind) for c in px)
        out.append({
            "data_utf8": data,
            "kind": kind,
            "seed_hex": seed.hex(),
            "width": seal.CANVAS,
            "height": seal.CANVAS,
            "rgb888_sha256": hashlib.sha256(rgb).hexdigest(),
        })

    doc = json.loads(VECTORS.read_text())
    doc["inkan"] = {
        "comment": (f"Inkan Seal v{seal.SEAL_VERSION} (original engine), "
                    f"{seal.CANVAS}x{seal.CANVAS} RGB888. "
                    "seed = inkan/v1 glyph domain; the engine takes sha256(seed). "
                    "Renderer version is independent of the seed domain."),
        "seal_version": seal.SEAL_VERSION,
        "vectors": out,
    }
    VECTORS.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(out)} inkan glyph vectors -> {VECTORS}")


if __name__ == "__main__":
    main()
