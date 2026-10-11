# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 RexStarBSV
# Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
"""
inkan_standard — the Inkan Standard's verification path: two complementary, verifiable trust
signals for any app, and the seal:

  • Tamper fingerprint  — "the code / asset is unaltered"  (inkan_standard.fingerprint)
  • Warrant canary      — "the operator is uncompromised & un-coerced"  (inkan_standard.canary)

Both are designed to be published to an immutable anchor (e.g. a BSV 1Sat Ordinal / OP_RETURN) and
verified by any client. Neutral + per-adopter namespaced; reference implementation in Python, with a
language-agnostic SPEC.md and test vectors so other languages (JS/TS, …) verify identically.
"""
from .fingerprint import (domain_prefix, fingerprint_digest, fingerprint_hex,
    digest_to_inkan_png, digest_to_lifehash_png_v1, fingerprint_image_png, png_chunk_tags)
from .seal import seal_rgb, seal_png, seal_fields, KINDS, SEAL_VERSION
from .canary import (canonical_bytes, message_hash, build_record, sign, is_fresh, status)
# NOTE: canary.verify() is intentionally NOT re-exported bare -- it would shadow the
# `inkan_standard.verify` verification module. Call canary.verify(...) explicitly.

__all__ = [
    "domain_prefix", "fingerprint_digest", "fingerprint_hex", "digest_to_inkan_png",
    "digest_to_lifehash_png_v1", "fingerprint_image_png", "png_chunk_tags",
    "seal_rgb", "seal_png", "seal_fields", "KINDS", "SEAL_VERSION",
    "canonical_bytes", "message_hash", "build_record",
    "sign", "is_fresh", "status",
]
__version__ = "1.0.0"
