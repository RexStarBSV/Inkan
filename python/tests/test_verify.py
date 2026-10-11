"""Tests for inkan_standard.verify -- the independent verifier. The verifier is only useful if it
correctly says GENUINE for the real render and MISMATCH for anything else."""
import hashlib
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from inkan_standard import seal, verify
from inkan_standard.seed import inkan_seed


class TestVerify(unittest.TestCase):
    def _png(self, data, kind, scale=1):
        d = hashlib.sha256(inkan_seed(data, kind)).digest()
        return seal.seal_png(d, kind, scale=scale)

    def test_selftest_passes(self):
        self.assertTrue(verify.selftest().ok)

    def test_genuine_seal_verifies(self):
        png = self._png("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address")
        r = verify.verify_seal("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "address", png)
        self.assertTrue(r.ok, r.summary)

    def test_open_kind_verifies(self):
        # SPEC §4: any kind string is valid; non-reserved kinds derive deterministically.
        png = self._png("Inkan", "wallet:inkan@t1")
        r = verify.verify_seal("Inkan", "wallet:inkan@t1", png)
        self.assertTrue(r.ok, r.summary)
        self.assertFalse(r.detail["reserved_kind"])
        self.assertFalse(verify.verify_seal("Inkan", "wallet:inkan@t2", png).ok,
                         "same data under a different derived kind must mismatch")

    def test_different_data_is_mismatch(self):
        genuine = self._png("addr-A", "address")
        r = verify.verify_seal("addr-B", "address", genuine)
        self.assertFalse(r.ok, "a different address must not verify against A's seal")

    def test_wrong_kind_is_mismatch(self):
        genuine = self._png("payload", "address")
        r = verify.verify_seal("payload", "signer", genuine)
        self.assertFalse(r.ok, "same data, wrong kind, must mismatch")

    def test_integer_upscale_still_verifies(self):
        png8 = self._png("hello", "identity", scale=8)
        r = verify.verify_seal("hello", "identity", png8)
        self.assertTrue(r.ok, "an 8x nearest-neighbour upscale is still the genuine seal")

    def test_tampered_upscale_blocks_rejected(self):
        """REGRESSION (2026-08-03). The verifier sampled one pixel per upscale block and never
        checked the block was uniform, leaving scale**2 - 1 pixels per block attacker-controlled --
        98.44% of the image at scale 8. An attacker could publish a picture 98.44% pixel-identical
        to one entity's genuine seal that verified GENUINE as a DIFFERENT entity's: exactly the
        substitution a trust mark exists to prevent.

        The old code passed `test_integer_upscale_still_verifies` because that test only ever built
        an HONEST upscale. Nothing in any suite built a dishonest one, which is why this shipped.
        """
        import hashlib, struct, zlib
        from inkan_standard import seal as _seal
        from inkan_standard.seed import inkan_seed

        N, SCALE, KIND = _seal.CANVAS, 8, "identity"
        VICTIM, ATTACKER = b"acme-bank.example", b"evil-bank.example"

        def native(d):
            h = hashlib.sha256(inkan_seed(d, KIND)).digest()
            return bytes(c for px in _seal.seal_rgb(h, KIND) for c in px)

        vic, att = native(VICTIM), native(ATTACKER)
        self.assertNotEqual(vic, att, "the two seals must differ for this test to mean anything")

        W = N * SCALE
        buf = bytearray(W * W * 3)
        for y in range(N):
            for x in range(N):
                v = vic[(y * N + x) * 3:(y * N + x) * 3 + 3]
                a = att[(y * N + x) * 3:(y * N + x) * 3 + 3]
                for dy in range(SCALE):
                    for dx in range(SCALE):
                        o = ((y * SCALE + dy) * W + (x * SCALE + dx)) * 3
                        buf[o:o + 3] = a if (dy == 0 and dx == 0) else v

        def png_of(rgb, w):
            raw = b"".join(b"\x00" + bytes(rgb[r * w * 3:(r + 1) * w * 3]) for r in range(w))
            def chunk(tag, d):
                c = tag + d
                return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)
            return (b"\x89PNG\r\n\x1a\n"
                    + chunk(b"IHDR", struct.pack(">IIBBBBB", w, w, 8, 2, 0, 0, 0))
                    + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))

        forged = png_of(buf, W)

        r = verify.verify_seal(ATTACKER, KIND, forged)
        self.assertFalse(r.ok, "a tampered upscale must NEVER verify as the attacker's own seal")
        self.assertTrue(r.detail.get("tampered_blocks"),
                        "the verdict must say the blocks are non-uniform, not that the size is wrong")

        r = verify.verify_seal(VICTIM, KIND, forged)
        self.assertFalse(r.ok, "nor as the victim's")

        # and the honest case must still pass, or the fix has broken legitimate upscales
        honest = bytearray(W * W * 3)
        for y in range(N):
            for x in range(N):
                a = att[(y * N + x) * 3:(y * N + x) * 3 + 3]
                for dy in range(SCALE):
                    for dx in range(SCALE):
                        o = ((y * SCALE + dy) * W + (x * SCALE + dx)) * 3
                        honest[o:o + 3] = a
        r = verify.verify_seal(ATTACKER, KIND, png_of(honest, W))
        self.assertTrue(r.ok, "a clean 8x upscale must still verify")

    def test_malformed_canary_input_is_not_invalid(self):
        """REGRESSION (2026-08-04, SPEC §8 E11). A key or signature that does not parse means the
        check never RAN. Reporting it as INVALID fires the maximum-severity verdict -- 'this
        publisher may be compromised' -- for what is nearly always a truncated paste, and an alarm
        that cries wolf is one people learn to ignore. Same principle as E2's unknown-version rule.
        """
        import datetime, json, pathlib as _p
        from inkan_standard import canary

        v = json.loads((_p.Path(__file__).resolve().parents[2] / "test-vectors" / "vectors.json").read_text())

        def find(o, key):
            if isinstance(o, dict):
                if key in o:
                    return o
                for x in o.values():
                    r = find(x, key)
                    if r:
                        return r
            if isinstance(o, list):
                for x in o:
                    r = find(x, key)
                    if r:
                        return r
            return None

        fx = find(v, "signature_der_hex")
        self.assertIsNotNone(fx, "the pinned canary vector must exist for this test to mean anything")
        rec, sig, pub = fx["record"], fx["signature_der_hex"], fx["pubkey_hex"]
        when = datetime.datetime(2026, 8, 1)

        self.assertEqual(canary.status(rec, sig, pub, now=when), "OK")

        # a REAL key with a structurally valid signature that is simply wrong is still INVALID --
        # the whole point is that MALFORMED must not swallow genuine failures
        altered = dict(rec)
        altered["seq"] = rec["seq"] + 1
        self.assertEqual(canary.status(altered, sig, pub, now=when), "INVALID",
                         "a wrong-but-parseable signature must remain INVALID")

        for label, s, k in (("non-hex signature", "zzzz", pub),
                            ("truncated DER", sig[:20], pub),
                            ("empty signature", "", pub),
                            ("non-hex pubkey", sig, "nothex")):
            self.assertEqual(canary.status(rec, s, k, now=when), "MALFORMED",
                             f"{label} must read MALFORMED, not INVALID")

        # and the exception type is part of the contract, so a caller can branch on it
        with self.assertRaises(canary.MalformedCanaryInput):
            canary.verify(rec, "zzzz", pub)

    def test_rendering_chunks_rejected(self):
        """REGRESSION (2026-08-04, SPEC §6 E12). Ancillary chunks a conformant viewer MUST honour
        change what is DRAWN while leaving the decoded RGB identical. A genuine seal plus one tRNS
        chunk verified GENUINE while a browser rendered the named colours fully transparent -- the
        same class of defect as the tampered-upscale blocker: the verifier certified an image nobody
        would actually see.
        """
        import hashlib, struct, zlib
        from inkan_standard import seal as _seal
        from inkan_standard.seed import inkan_seed

        d = hashlib.sha256(inkan_seed(b"x", "identity")).digest()
        genuine = _seal.seal_png(d, "identity")
        self.assertTrue(verify.verify_seal(b"x", "identity", genuine).ok,
                        "the untouched genuine seal must still verify")

        def chunk(tag, body):
            c = tag + body
            return struct.pack(">I", len(body)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

        def splice(tag, body=b"\x00" * 8):
            i, out = 8, b"\x89PNG\r\n\x1a\n"
            while i < len(genuine):
                ln = struct.unpack(">I", genuine[i:i + 4])[0]
                if genuine[i + 4:i + 8] == b"IDAT":
                    out += chunk(tag, body)
                out += genuine[i:i + 12 + ln]
                i += 12 + ln
            return out

        # EVERY chunk SPEC §6 names, not a sample of three. The list is normative, and a later edit
        # that dropped one from the reference's frozenset would have gone unnoticed while that one
        # chunk kept its power to change what a viewer draws.
        for tag in (b"tRNS", b"gAMA", b"iCCP", b"sRGB", b"cHRM", b"sBIT", b"bKGD",
                    b"acTL", b"fcTL", b"fdAT"):
            r = verify.verify_seal(b"x", "identity", splice(tag))
            self.assertFalse(r.ok, f"a genuine seal carrying {tag.decode()} must be rejected")
            self.assertIn(tag.decode(), r.summary)

        # ...and the benign metadata §6 explicitly still tolerates must NOT be swept up with them,
        # or the same fix would break the re-encoding allowance §6 grants in the sentence before.
        # (Each with a body of its proper size: under the verifiable-PNG profile, E24, a pHYs is 9
        # bytes and a tIME 7, and a malformed one is refused like any other malformed chunk.)
        for tag, body in ((b"tEXt", b"Comment\x00x"), (b"pHYs", b"\x00\x00\x0b\x13" * 2 + b"\x01"),
                          (b"tIME", b"\x07\xea\x0a\x0a\x00\x00\x00")):
            r = verify.verify_seal(b"x", "identity", splice(tag, body))
            self.assertTrue(r.ok, f"{tag.decode()} does not change the picture and stays tolerated")
        r = verify.verify_seal(b"x", "identity", splice(b"pHYs", b"\x00" * 8))
        self.assertFalse(r.ok, "a pHYs of the wrong size is not a verifiable PNG (E24)")

    def test_compression_bomb_rejected_without_expanding(self):
        """A ~1 MB IDAT can expand to hundreds of MB. This decoder runs in a page intended for
        permanent on-chain inscription, where the code cannot be patched and 'reload the tab' is the
        only remedy, so it must not materialise more than IHDR declares."""
        import struct, time, zlib
        from inkan_standard import seal as _seal

        bomb = zlib.compress(b"\x00" * (400 * 1024 * 1024), 9)

        def chunk(tag, body):
            c = tag + body
            return struct.pack(">I", len(body)) + c + struct.pack(">I", zlib.crc32(c) & 0xffffffff)

        n = _seal.CANVAS
        png = (b"\x89PNG\r\n\x1a\n"
               + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 2, 0, 0, 0))
               + chunk(b"IDAT", bomb) + chunk(b"IEND", b""))
        t0 = time.time()
        r = verify.verify_seal(b"x", "identity", png)
        self.assertFalse(r.ok)
        self.assertLess(time.time() - t0, 5.0, "the bomb must be refused, not decompressed")

    def test_canary_record_shape_is_enforced(self):
        """REGRESSION (2026-08-04). Nothing validated the record shape in any port, on either side.
        A wrong shape cannot be FORGED -- the signature covers whatever fields are present -- but a
        publisher can emit one by mistake and every verifier would still have said OK.
        """
        import datetime, json, pathlib as _p
        from inkan_standard import canary

        v = json.loads((_p.Path(__file__).resolve().parents[2] / "test-vectors" / "vectors.json").read_text())

        def find(o, key):
            if isinstance(o, dict):
                if key in o:
                    return o
                for x in o.values():
                    r = find(x, key)
                    if r:
                        return r
            if isinstance(o, list):
                for x in o:
                    r = find(x, key)
                    if r:
                        return r
            return None

        fx = find(v, "signature_der_hex")
        rec, sig, pub = fx["record"], fx["signature_der_hex"], fx["pubkey_hex"]
        when = datetime.datetime(2026, 8, 1)
        self.assertEqual(canary.status(rec, sig, pub, now=when), "OK")
        for label, bad in (("extra field", {**rec, "note": "x"}),
                           ("missing field", {k: x for k, x in rec.items() if k != "block_hash"}),
                           ("wrong type", {**rec, "seq": "1"})):
            self.assertEqual(canary.status(bad, sig, pub, now=when), "MALFORMED", label)

    def test_code_version_rejection(self):
        """`code_to_digest_hex` is the only implementation of SPEC §2's "a conforming reader MUST
        reject a code whose version it does not implement". It had zero callers and zero tests, so
        the one normative MUST about forward compatibility was enforced by nothing that ran.

        REGRESSION (2026-08-06). It checked the prefix and nothing else, so four malformed shapes
        were accepted and returned as if they were anchors. The sharpest was `ik` + digest: the
        version was detected with `startswith("ik1")` against the WHOLE string rather than read
        positionally, so a code carrying no version digit passed whenever the digest happened to
        begin with `1` -- one anchor in sixteen, and the caller got a 63-character body back with no
        indication anything was wrong. Each case below pins one of those shapes.
        """
        from inkan_standard.seed import FULL_CODE_LEN, SHORT_CODE_LEN, code_to_digest_hex

        digest = "12cf1aaca7ef50793d990e94c9ae889af6f9e8fdfc28b2f9a72d4028bde05dcd"
        self.assertEqual(len(digest), FULL_CODE_LEN)
        self.assertTrue(digest.startswith("1"),
                        "this fixture must start with the version digit, or the 'no version digit' "
                        "case below stops reproducing the bug it was written for")
        self.assertEqual(code_to_digest_hex("ik1" + digest), digest)
        # an uppercase body is the same anchor and must not compare unequal to a fresh digest
        self.assertEqual(code_to_digest_hex("ik1" + digest.upper()), digest)

        for bad, why in (("ik2" + digest, "a future hash version must be rejected, not misread "
                                          "as SHA-256"),
                         ("ik" + digest, "no version digit"),
                         ("ik1", "prefix with no body at all"),
                         ("", "empty string"),
                         ("xx1" + digest, "wrong prefix"),
                         ("ik1" + digest[:-1], "short body"),
                         ("ik1" + digest + "aa", "long body"),
                         ("ik1" + "z" * FULL_CODE_LEN, "non-hex body"),
                         ("ik1" + digest[:SHORT_CODE_LEN], "a SHORT code is a label, not the anchor "
                                                           "(SPEC §9 E8)")):
            with self.assertRaises(ValueError, msg=why):
                code_to_digest_hex(bad)

        # a non-string must raise the same ValueError, not an AttributeError from startswith: a
        # caller catching ValueError to mean "bad code" would otherwise crash on a None from JSON
        for bad in (None, b"ik1" + digest.encode(), 1):
            with self.assertRaises(ValueError):
                code_to_digest_hex(bad)

        # the short-code refusal must NAME it -- "not an Inkan code" is a wrong diagnosis for a
        # perfectly valid SPEC §2 short form, and a wrong diagnosis sends the reader hunting a
        # typo that is not there
        with self.assertRaises(ValueError) as ctx:
            code_to_digest_hex("ik1" + digest[:SHORT_CODE_LEN])
        self.assertIn("SHORT", str(ctx.exception))

    def test_unencodable_kind_is_rejected_not_substituted(self):
        """SPEC §4 E4. Until 2026-08-04 this MUST was enforced by nothing, and the three ports gave
        three different answers: Python raised by accident of the default error handler, JavaScript's
        TextEncoder substituted U+FFFD, and Kotlin's toByteArray substituted too. Two of the three
        believed they had succeeded, which is the worst shape a divergence can take.

        Substitution is the danger, not the exception: every unpaired surrogate collapses onto the
        SAME replacement bytes, so distinct kinds would share one anchor.
        """
        from inkan_standard.seed import inkan_seed

        lone_high = "\ud800"
        lone_low = "\udfff"
        for bad in (lone_high, lone_low, "id" + lone_high, lone_high + "id"):
            with self.assertRaises(ValueError) as ctx:
                inkan_seed(b"x", bad)
            self.assertIn("E4", str(ctx.exception),
                          "the rejection must cite the rule it enforces")

        # A well-formed ASTRAL character is ordinary text and must still work -- the rule rejects
        # unencodable text, not non-BMP text, and a fix that failed here would be over-broad.
        #
        # MIND THE LITERAL. This case was written `"\ud83d\ude00"`, copied from the JS and Kotlin
        # tests, where strings are UTF-16 and that pair IS U+1F600. Python source escapes name
        # CODEPOINTS, so in Python the same spelling is TWO LONE SURROGATES -- the exact input the
        # loop above requires to be rejected. The assertion therefore demanded that a malformed kind
        # be ACCEPTED: it asserted the opposite of what it was written to prove, and the only reason
        # it was ever noticed is that E4 made the port fail closed. Spell astral characters
        # \U0001XXXX here; never as a surrogate pair.
        astral = "\U0001f600"          # U+1F600 GRINNING FACE, one codepoint
        self.assertEqual(len(astral), 1, "if this is 2, the literal is a surrogate pair again")
        seed = inkan_seed(b"x", astral)
        self.assertTrue(seed)
        self.assertIn(b"\xf0\x9f\x98\x80", seed,
                      "the astral kind must reach the seed as its real UTF-8 bytes, not U+FFFD")
        # and unencodable DATA is rejected on the same principle
        with self.assertRaises(ValueError):
            inkan_seed(lone_high, "identity")
        # ...as is a malformed kind in the seal derivation (§4.2) and a malformed adopter name (§7)
        from inkan_standard.fingerprint import fingerprint_hex
        for bad in (lone_high, lone_low, "x:" + lone_high + "@t1"):
            with self.assertRaises(ValueError) as ctx:
                seal.resolve_kind(bad)
            self.assertIn("E4", str(ctx.exception))
            with self.assertRaises(ValueError) as ctx:
                fingerprint_hex(b"build-bytes-v1", "acme" + bad)
            self.assertIn("E4", str(ctx.exception))
        self.assertEqual(list(seal.resolve_kind(astral)), [48, 1, 9])

    def test_non_multiple_size_rejected(self):
        # a 100x100 PNG is not an integer multiple of 224 -> cannot be the genuine seal
        import struct, zlib
        w = h = 100
        raw = bytearray()
        for _ in range(h):
            raw.append(0)
            raw += bytes([10, 20, 30]) * w
        def chunk(t, d):
            c = t + d
            return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        png = (b"\x89PNG\r\n\x1a\n"
               + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
               + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))
        r = verify.verify_seal("hello", "identity", png)
        self.assertFalse(r.ok)

    def test_decode_roundtrips_reference_render(self):
        png = self._png("roundtrip", "vault")
        decoded = verify.decode_png_rgb(png)
        truth = verify.canonical_seal("roundtrip", "vault")
        self.assertEqual(decoded.rgb, truth["rgb"])

    def test_fingerprint_match_and_mismatch(self):
        from inkan_standard.fingerprint import fingerprint_hex
        h = fingerprint_hex(b"payload", "acme")
        self.assertTrue(verify.verify_fingerprint(b"payload", "acme", h).ok)
        self.assertFalse(verify.verify_fingerprint(b"payload", "acme", "00" * 32).ok)

    def test_report_is_reproducible_except_timestamp(self):
        png = self._png("rep", "address")
        r = verify.verify_seal("rep", "address", png)
        a = verify.build_report("seal", {"data": "rep"}, r)
        b = verify.build_report("seal", {"data": "rep"}, r)
        del a["generated_utc"], b["generated_utc"]
        self.assertEqual(a, b, "report evidence must be deterministic")
        self.assertEqual(a["verdict"], "PASS")


class TestTag(unittest.TestCase):
    def _d(self, data, kind):
        return hashlib.sha256(inkan_seed(data, kind)).digest()

    def test_canonical_is_metadata_free(self):
        png = seal.seal_png(self._d("x", "address"), "address")   # tag defaults False
        self.assertNotIn(b"iTXt", png)
        self.assertNotIn(b"tEXt", png)

    def test_tagged_carries_code_and_same_pixels(self):
        d = self._d("x", "address")
        canon = seal.seal_png(d, "address", tag=False)
        tagged = seal.seal_png(d, "address", tag=True)
        emb = verify.read_embedded_tag(tagged)
        self.assertEqual(emb["code"], "ik1" + d.hex())
        self.assertEqual(emb["kind"], "address")
        self.assertEqual(verify.decode_png_rgb(canon).rgb, verify.decode_png_rgb(tagged).rgb)

    def test_tagged_verifies_and_matches(self):
        tagged = seal.seal_png(self._d("addr", "address"), "address", tag=True)
        r = verify.verify_seal("addr", "address", tagged)
        self.assertTrue(r.ok)
        self.assertTrue(r.detail["embedded_code_matches"])

    def test_lying_tag_flagged_but_pixels_still_judged(self):
        import struct, zlib
        d = self._d("addr", "address")
        tagged = seal.seal_png(d, "address", tag=True)
        def itxt(k, t):
            body = k.encode() + b"\x00\x00\x00\x00\x00" + t.encode(); c = b"iTXt" + body
            return struct.pack(">I", len(body)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
        lied = tagged.replace(itxt("inkan-code", "ik1" + d.hex()), itxt("inkan-code", "ik1" + "00" * 32))
        r = verify.verify_seal("addr", "address", lied)
        self.assertTrue(r.ok, "the pixels are genuine regardless of a false metadata claim")
        self.assertFalse(r.detail["embedded_code_matches"], "the lie must be caught by cross-check")


_ROOT = pathlib.Path(__file__).resolve().parents[2]
_VECTORS = _ROOT / "test-vectors"


def _render_from_tables_file(T, digest, kind):
    """Seal v3 built from the published tables file and SPEC §3-§4 ALONE: nothing here imports the
    engine. If this reproduces the vectors, the CC BY text plus the CC0 data are enough to build a
    conforming renderer, which is the claim LICENSING.md makes. Returns (words, palette, core, rgb)."""
    import base64
    sha = lambda b: hashlib.sha256(b).digest()
    if kind in T["KINDS"]:
        cells, k, motif = T["KINDS"][kind]
    else:
        tier = next((t for t in ("t1", "t2", "t3") if kind.endswith("@" + t)), "t2")
        cells = T["TIER_CELLS"][tier]
        kh = sha(bytes.fromhex(T["KIND_DOMAIN_HEX"]) + kind.encode("utf-8"))
        k = 1 + kh[0] % T["KMAX"][str(cells)]
        motif = T["ORBIT_REPS"][kh[1] % len(T["ORBIT_REPS"])]

    def blocks():
        ctr = 0
        while True:
            yield from sha(digest + bytes.fromhex(T["STREAM_DOMAIN_HEX"]) + ctr.to_bytes(4, "big"))
            ctr += 1
    s = blocks()

    def uniform(n):
        while True:
            b = next(s)
            if b < 256 - 256 % n:
                return b % n
    words = [((next(s) << 8) | next(s)) & 0xFFF for _ in range(cells // 12)]
    draw = [i for i, w in enumerate(T["SELECT_WEIGHTS"]) for _ in range(w)]
    pal = draw[uniform(len(draw))]
    core = T["CORE_PATTERNS"][uniform(len(T["CORE_PATTERNS"]))]

    def golay(x):
        c = 0
        for b in range(12):
            if (x >> b) & 1:
                c ^= T["GOLAY_G"] << b
        return (c << 1) | (bin(c).count("1") & 1)
    state = []
    for g in range(cells // 24):
        A, B = golay(words[2 * g]), golay(words[2 * g + 1])
        state += [(((B >> i) & 1) << 1) | ((A >> i) & 1) for i in range(24)]
    ground, a1, a2, a3, core_c = (bytes(c) for c in T["PALETTE"][pal])
    blob = base64.b64decode(T["REGION_RLE"]["%d,%d" % (cells, k)], validate=True)
    rgb = bytearray()
    for i in range(0, len(blob), 3):
        rid, run = blob[i], blob[i + 1] | (blob[i + 2] << 8)
        if rid < cells:
            px = (ground, a1, a2, a3)[state[rid]]
        elif 100 <= rid < 200:
            px = core_c if (core >> (rid - 100)) & 1 else ground
        elif 200 <= rid < 255:
            px = a1 if (motif >> (rid - 200)) & 1 else ground
        else:
            px = ground
        rgb += px * run
    assert len(rgb) == 3 * T["CANVAS"] ** 2
    return words, pal, core, bytes(rgb)


class TestPublishedTables(unittest.TestCase):
    """SPEC §3.0: the Seal v3 tables are a published CC0 data file pinned by its SHA-256."""

    def _bytes(self):
        return (_VECTORS / "seal-v3-tables.json").read_bytes()

    def test_tables_file_is_the_canonical_encoding_of_the_engine_tables(self):
        sys.path.insert(0, str(_ROOT / "python" / "tools"))
        import gen_seal_v3_tables
        self.assertEqual(gen_seal_v3_tables.canonical(gen_seal_v3_tables.tables_doc()), self._bytes(),
                         "the engine's tables no longer encode to the published file")

    def test_tables_digest_is_the_one_spec_pins(self):
        spec = (_ROOT / "SPEC.md").read_text(encoding="utf-8")
        section3 = spec.split("\n## 3.", 1)[1].split("\n## 4.", 1)[0]
        self.assertIn(hashlib.sha256(self._bytes()).hexdigest(), section3,
                      "SPEC §3 does not pin the SHA-256 of test-vectors/seal-v3-tables.json")

    def test_spec_names_every_member_of_the_file(self):
        """§3.0 says an implementation can rebuild the exact bytes from its own copy of the tables.
        That holds only if §3.0 names every member of the encoded object, including FORMAT, which
        the renderer never reads but the digest covers."""
        import json
        import re
        spec = (_ROOT / "SPEC.md").read_text(encoding="utf-8")
        section = spec.split("\n### 3.0 ", 1)[1].split("\n### 3.1 ", 1)[0]
        self.assertEqual(set(re.findall(r"`([A-Z][A-Z0-9_]+)`", section)), set(json.loads(self._bytes())),
                         "SPEC §3.0 and test-vectors/seal-v3-tables.json disagree about its members")

    def test_a_renderer_built_from_the_file_alone_reproduces_the_vectors(self):
        import json
        T = json.loads(self._bytes())
        cov = json.loads((_VECTORS / "seal-v3-coverage-vectors.json").read_text())
        old = json.loads((_VECTORS / "seal-v3-vectors.json").read_text())
        for v in cov["coverage"] + cov["second_block"] + old["sampled"]:
            words, pal, core, rgb = _render_from_tables_file(T, bytes.fromhex(v["digest_hex"]), v["kind"])
            self.assertEqual((words, pal, core), (v["words"], v["palette_ix"], v["core_pattern"]),
                             v["kind"])
            self.assertEqual(hashlib.sha256(rgb).hexdigest(), v["rgb_sha256"], v["kind"])


class TestCoverageVectors(unittest.TestCase):
    """seal-v3-coverage-vectors.json: every region map x every open-kind motif, every palette class,
    every core pattern, and the second block of the field stream."""

    def _doc(self):
        import json
        return json.loads((_VECTORS / "seal-v3-coverage-vectors.json").read_text())

    def test_engine_reproduces_every_coverage_vector(self):
        doc = self._doc()
        self.assertEqual(doc["seal_version"], seal.SEAL_VERSION)
        for v in doc["coverage"] + doc["second_block"]:
            d = bytes.fromhex(v["digest_hex"])
            self.assertEqual(list(seal.resolve_kind(v["kind"])), v["resolve"], v["kind"])
            words, pal, core = seal.seal_fields(d, v["kind"])
            self.assertEqual((list(words), pal, core), (v["words"], v["palette_ix"], v["core_pattern"]))
            rgb = bytes(c for px in seal.seal_rgb_from_fields(words, pal, core, v["kind"]) for c in px)
            self.assertEqual(hashlib.sha256(rgb).hexdigest(), v["rgb_sha256"], v["kind"])

    def test_the_set_reaches_every_table_entry(self):
        from inkan_standard import seal_tables as T
        doc = self._doc()
        res = [tuple(v["resolve"]) for v in doc["coverage"]]
        self.assertEqual({"%d,%d" % (c, k) for c, k, _ in res}, set(T.REGION_RLE))
        self.assertEqual(set(res), {(c, k, m) for c in (24, 48, 72) for k in range(1, T.KMAX[c] + 1)
                                    for m in T.ORBIT_REPS})
        self.assertEqual({v["palette_ix"] for v in doc["coverage"]}, set(range(len(T.PALETTE))))
        self.assertEqual({v["core_pattern"] for v in doc["coverage"]}, set(T.CORE_PATTERNS))

    def test_second_block_vectors_read_past_the_first_block(self):
        for v in self._doc()["second_block"]:
            s = seal._Stream(bytes.fromhex(v["digest_hex"]))
            for _ in range(v["resolve"][0] // 6):           # cells/12 info words, 2 bytes each
                s.byte()
            seal._uniform(s, sum(seal.SELECT_WEIGHTS))
            seal._uniform(s, len(seal.CORE_PATTERNS))
            self.assertEqual(32 * s._ctr - len(s._buf), v["stream_bytes_read"])
            self.assertGreater(v["stream_bytes_read"], 32)


# Errata whose vectors this port does not satisfy yet. A vector that tests one of these is reported as
# SKIPPED, by name, never counted as a pass; remove an erratum from this set in the commit that
# implements it.
PENDING_ERRATA = frozenset()


def _cp_text(points):
    return "".join(chr(int(h, 16)) for h in points)


def _unassigned_here(s):
    """E14's test, with the database this interpreter's NFC uses: General_Category Cn, except the 66
    noncharacters."""
    import unicodedata
    return any(unicodedata.category(c) == "Cn" and not (0xFDD0 <= ord(c) <= 0xFDEF
                                                        or (ord(c) & 0xFFFE) == 0xFFFE) for c in s)


def _version(s):
    """A Unicode version, "16.0" or "16.0.0", as a tuple of three numbers that compares by age."""
    return (tuple(int(x) for x in s.split(".")) + (0, 0))[:3]


def _unicode_result(v):
    """The result this port gives for a unicode-vectors.json input, or the exception it raises."""
    from inkan_standard.fingerprint import fingerprint_hex
    from inkan_standard.seed import inkan_code
    if "adopter" in v:
        return {"fingerprint_hex": fingerprint_hex(v["payload_utf8"].encode(), _cp_text(v["adopter"]),
                                                   v["fingerprint_version"])}
    kind = _cp_text(v["kind"])
    return {"code": inkan_code(_cp_text(v["data"]), kind), "resolve": list(seal.resolve_kind(kind))}


class TestUnicodeVectors(unittest.TestCase):
    """unicode-vectors.json (SPEC §1, E14): reject a text input with a code point this database does
    not know, or return exactly the pinned result; never anything else."""

    def _doc(self):
        import json
        return json.loads((_VECTORS / "unicode-vectors.json").read_text())

    @staticmethod
    def _inputs(v):
        return "".join(_cp_text(v.get(f, [])) for f in ("data", "kind", "adopter"))

    def test_accept_vectors_give_exactly_the_pinned_result(self):
        for v in self._doc()["accept"]:
            want = {k: v["result_if_accepted"][k] for k in ("code", "resolve", "fingerprint_hex")
                    if k in v["result_if_accepted"]}
            self.assertEqual(_unicode_result(v), want, v["name"])

    def test_either_or_vectors_this_database_can_answer(self):
        import unicodedata
        here = _version(unicodedata.unidata_version)
        vectors = self._doc()["either_or"]
        self.assertTrue(vectors, "unicode-vectors.json has no either/or vectors")
        answered = 0
        for v in vectors:
            # A database at least as new as the vector's newest code point knows every code point in it.
            too_old = here < _version(v["newest_code_point_assigned_in"])
            self.assertEqual(_unassigned_here(self._inputs(v)), too_old, v["name"])
            if too_old:
                continue                      # the reject branch: see the test below
            want = {k: v["result_if_accepted"][k] for k in ("code", "resolve", "fingerprint_hex")
                    if k in v["result_if_accepted"]}
            got = _unicode_result(v)
            self.assertEqual(got, want, v["name"])
            self.assertNotIn(got.get("code", got.get("fingerprint_hex")), v.get("never", []))
            answered += 1
        if not answered:
            # Python 3.13 and earlier carry Unicode 15.1 or older, which lacks a code point in every
            # either/or vector. Reported as SKIPPED, with the reason, never counted as a pass.
            self.skipTest("this database (Unicode %s) lacks a code point in every either/or vector; all "
                          "of them are in the reject branch" % unicodedata.unidata_version)

    def test_inputs_with_unassigned_code_points_are_rejected(self):
        doc = self._doc()
        due = [v for v in doc["either_or"] if _unassigned_here(self._inputs(v))]
        due += [v for v in doc["reject_unless_assigned"] if _unassigned_here(self._inputs(v))]
        self.assertTrue(due, "expected this database to lack at least the reject_unless_assigned code points")
        if doc["rule"] in PENDING_ERRATA:
            self.skipTest("%s not implemented in this port yet; %d vectors pending: %s"
                          % (doc["rule"], len(due), ", ".join(v["name"] for v in due)))
        for v in due:
            with self.assertRaises(ValueError, msg=v["name"]):
                _unicode_result(v)

    def test_the_kind_derivation_rejects_the_same_kinds(self):
        """SPEC §4.2: a kind rejected by the anchor is rejected by the seal derivation too, so no seal
        is drawn for a kind that has no anchor. Checked on its own, not through the anchor, because
        `_unicode_result` computes the anchor first and would raise before reaching it."""
        doc = self._doc()
        kinds = [_cp_text(v["kind"]) for v in doc["either_or"] + doc["reject_unless_assigned"]
                 if v.get("kind") and _unassigned_here(_cp_text(v["kind"]))]
        self.assertTrue(kinds, "expected at least one kind this database cannot assign")
        for kind in kinds:
            with self.assertRaises(ValueError) as ctx:
                seal.resolve_kind(kind)
            self.assertIn("E14", str(ctx.exception))
        # a kind of assigned code points, and one holding a noncharacter, still resolve
        self.assertEqual(list(seal.resolve_kind("nc:\ufdd0@t3")), [24, 4, 23])
        self.assertEqual(list(seal.resolve_kind("caf\u00e9@t2")), [48, 3, 1])

    def test_the_self_test_reports_its_unicode_version(self):
        import unicodedata
        r = verify.selftest()
        self.assertEqual(r.detail["unicode_version"], unicodedata.unidata_version)
        self.assertIn("Unicode " + unicodedata.unidata_version, r.summary)


class TestFingerprintVectors(unittest.TestCase):
    """fingerprint-vectors.json (SPEC §7, E21, E22): accepted names and versions give exactly the
    pinned fingerprint; rejected ones are refused before hashing."""

    def _doc(self):
        import json
        return json.loads((_VECTORS / "fingerprint-vectors.json").read_text())

    @staticmethod
    def _fp(v):
        from inkan_standard.fingerprint import fingerprint_hex
        return fingerprint_hex(v["payload_utf8"].encode(), _cp_text(v["adopter"]), v["version"])

    def test_accepted_names_and_versions_give_exactly_the_pinned_fingerprint(self):
        for v in self._doc()["accept"]:
            self.assertEqual(self._fp(v), v["fingerprint_hex"], v["name"])

    def test_rejected_names_and_versions_are_refused(self):
        due = [v for v in self._doc()["reject"] if v["rule"] not in PENDING_ERRATA]
        pending = [v for v in self._doc()["reject"] if v["rule"] in PENDING_ERRATA]
        for v in due:
            with self.assertRaises(ValueError, msg=v["name"]):
                self._fp(v)
        if pending:
            self.skipTest("%s not implemented in this port yet; %d vectors pending: %s"
                          % ("/".join(sorted({v["rule"] for v in pending})), len(pending),
                             ", ".join(v["name"] for v in pending)))

    def test_the_verifier_and_command_line_take_the_version(self):
        """SPEC §0 P5, §7 E22: the version is an explicit input. Without it a genuine version-2
        fingerprint read MISMATCH in the Python verifier and command line."""
        import contextlib
        import io
        import json
        v2 = next(v for v in self._doc()["accept"] if v["name"] == "version-2")
        payload = v2["payload_utf8"].encode()
        adopter = _cp_text(v2["adopter"])
        self.assertTrue(verify.verify_fingerprint(payload, adopter, v2["fingerprint_hex"], version=2).ok)
        self.assertFalse(verify.verify_fingerprint(payload, adopter, v2["fingerprint_hex"]).ok,
                         "the default is version 1, which is a different digest")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = verify.main(["fingerprint", "--payload", v2["payload_utf8"], "--adopter", adopter,
                              "--version", "2", "--expect", v2["fingerprint_hex"], "--json"])
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["detail"]["version"], 2)
        for bad in ("0", "-1", "1.5", "two", "\u0662"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                verify.main(["fingerprint", "--payload", "x", "--adopter", "acme", "--version", bad])
        for bad in (0, -1, 1.5, True, "2"):
            with self.assertRaises(ValueError):
                verify.verify_fingerprint(payload, adopter, version=bad)


class TestCanaryVectors(unittest.TestCase):
    """canary-vectors.json (SPEC §8, E23): each signed record, parsed from its wire text, gets exactly
    the pinned verdict."""

    def _verdict(self, doc, c, parsed=False):
        """The verdict for a case read from its wire text, as the vectors define it; or, with
        `parsed`, for the object a JSON reader makes of it (the canonical-bytes rule then has no
        bytes to check)."""
        import datetime
        import json
        from inkan_standard import canary
        now = datetime.datetime.strptime(doc["now"], "%Y-%m-%dT%H:%M:%SZ")
        record = json.loads(c["record_json"]) if parsed else c["record_json"]
        try:
            return canary.status(record, c["signature_der_hex"],
                                 c.get("pubkey_hex", doc["pubkey_hex"]), now, doc["max_age_days"])
        except canary.UnsupportedCanaryVersion:
            return "UNSUPPORTED"          # verify.verify_canary's mapping of an unknown version

    def _doc(self):
        import json
        return json.loads((_VECTORS / "canary-vectors.json").read_text())

    def test_cases_every_verifier_already_meets(self):
        doc = self._doc()
        due = [c for c in doc["cases"] if c["rule"] not in PENDING_ERRATA]
        self.assertTrue(due)
        for c in due:
            self.assertEqual(self._verdict(doc, c), c["expect"], c["name"])

    def test_cases_decided_by_the_input_rules(self):
        doc = self._doc()
        cases = [c for c in doc["cases"] if c["rule"] is not None]
        pending = [c["name"] for c in cases if c["rule"] in PENDING_ERRATA]
        if pending:
            self.skipTest("E23 not implemented in this port yet; %d cases pending: %s"
                          % (len(pending), ", ".join(pending)))
        for c in cases:
            self.assertEqual(self._verdict(doc, c), c["expect"], c["name"])

    def test_a_parsed_record_gets_the_same_verdict(self):
        """Rules 1-3 hold for a record handed over as an object, too; only rule 4, which is about
        bytes, needs the wire form."""
        doc = self._doc()
        for c in doc["cases"]:
            if c["name"] == "record-not-canonical":
                self.assertEqual(self._verdict(doc, c, parsed=True), "OK",
                                 "as an object the record is canonical; only its bytes were not")
                continue
            self.assertEqual(self._verdict(doc, c, parsed=True), c["expect"], c["name"])

    def test_a_key_or_signature_that_is_not_text_reads_malformed(self):
        """SPEC §8 E23: the key and signature are hexadecimal text. Bytes, a number or None is not
        a key or signature in any verifier."""
        from inkan_standard import canary
        doc = self._doc()
        tv7 = next(c for c in doc["cases"] if c["name"] == "tv7")
        sig, pub = tv7["signature_der_hex"], doc["pubkey_hex"]
        for s, p in ((sig.encode(), pub), (sig, pub.encode()), (None, pub), (sig, None),
                     (3006020101020101, pub)):
            self.assertEqual(canary.status(tv7["record_json"], s, p), "MALFORMED", repr(s)[:12])

    def test_the_command_line_reads_the_record_as_its_bytes(self):
        import contextlib
        import io
        import json
        import tempfile
        doc = self._doc()
        tv7 = next(c for c in doc["cases"] if c["name"] == "tv7")
        with tempfile.TemporaryDirectory() as tmp:
            for text, want in ((tv7["record_json"] + "\n", "STALE"),            # a file ends in a line feed
                               (tv7["record_json"].replace(":", ": "), "MALFORMED")):
                path = pathlib.Path(tmp) / "rec.json"
                path.write_text(text, encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    verify.main(["canary", "--record", "@" + str(path), "--sig",
                                 tv7["signature_der_hex"], "--pubkey", doc["pubkey_hex"], "--json"])
                self.assertEqual(json.loads(out.getvalue())["detail"]["status"], want, text[:40])


class TestPngProfileVectors(unittest.TestCase):
    """png-profile-vectors.json (SPEC §6, E24): each presented file gets exactly the pinned verdict
    for the claimed seal: GENUINE, MISMATCH or REJECTED."""

    def _doc(self):
        import json
        return json.loads((_VECTORS / "png-profile-vectors.json").read_text())

    @staticmethod
    def _verdict(doc, c):
        import base64
        r = verify.verify_seal(doc["data_utf8"], doc["kind"], base64.b64decode(c["png_base64"]))
        return "GENUINE" if r.ok else ("MISMATCH" if r.summary.startswith("MISMATCH") else "REJECTED")

    def test_cases_every_verifier_already_meets(self):
        doc = self._doc()
        due = [c for c in doc["cases"] if c["rule"] not in PENDING_ERRATA]
        self.assertTrue(due)
        for c in due:
            self.assertEqual(self._verdict(doc, c), c["expect"], c["name"])

    def test_cases_decided_by_the_profile(self):
        doc = self._doc()
        cases = [c for c in doc["cases"] if c["rule"] is not None]
        pending = [c["name"] for c in cases if c["rule"] in PENDING_ERRATA]
        if pending:
            self.skipTest("E24 not implemented in this port yet; %d cases pending: %s"
                          % (len(pending), ", ".join(pending)))
        for c in cases:
            self.assertEqual(self._verdict(doc, c), c["expect"], c["name"])


class TestTypedTextIsText(unittest.TestCase):
    """SPEC §1 E19: what a person types or pastes is text, so the command line and the tool-call
    interface anchor it over its NFC form, exactly as the libraries do. Only a file is bytes."""

    def _cafe(self):
        import json
        doc = json.loads((_VECTORS / "unicode-vectors.json").read_text())
        return next(v for v in doc["accept"] if v["name"] == "decomposed-cafe")

    def test_the_command_line_anchors_typed_text_as_text(self):
        import contextlib
        import io
        import json
        import tempfile
        v = self._cafe()
        typed = _cp_text(v["data"])
        self.assertEqual(typed, "cafe\u0301", "the vector must be the decomposed spelling")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = verify.main(["seal", "--data", typed, "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["detail"]["code"], v["result_if_accepted"]["code"])
        # ...and a genuine seal of that text, presented to the command line, reads GENUINE
        d = hashlib.sha256(inkan_seed("caf\u00e9", "")).digest()
        with tempfile.TemporaryDirectory() as tmp:
            png = pathlib.Path(tmp) / "seal.png"
            png.write_bytes(seal.seal_png(d, ""))
            raw = pathlib.Path(tmp) / "data.bin"
            raw.write_bytes(typed.encode("utf-8"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = verify.main(["seal", "--data", typed, "--seal", str(png), "--json"])
            self.assertEqual(rc, 0, out.getvalue())
            self.assertTrue(json.loads(out.getvalue())["summary"].startswith("GENUINE"))
            # a FILE is bytes: the same characters read from a file anchor as raw bytes
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                verify.main(["seal", "--data", "@" + str(raw), "--json"])
            self.assertEqual(json.loads(out.getvalue())["detail"]["code"], v["if_passed_as_bytes"])

    def test_the_tool_call_interface_anchors_text_as_text(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("inkan_mcp", _ROOT / "tools" / "inkan_mcp.py")
        mcp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mcp)
        v = self._cafe()
        typed = _cp_text(v["data"])
        self.assertEqual(mcp.op_generate({"text": typed})["code"], v["result_if_accepted"]["code"])
        self.assertTrue(mcp.op_verify_seal({"text": typed})["detail"]["code"] ==
                        v["result_if_accepted"]["code"])
        import base64
        self.assertEqual(mcp.op_generate({"base64": base64.b64encode(typed.encode()).decode()})["code"],
                         v["if_passed_as_bytes"], "base64 is marked binary, so it stays bytes")
        # a fingerprint payload is bytes (SPEC §7): text is hashed as its UTF-8, never normalised
        from inkan_standard.fingerprint import fingerprint_hex
        self.assertEqual(mcp.op_fingerprint({"text": typed, "adopter": "acme"})["fingerprint"],
                         fingerprint_hex(typed.encode("utf-8"), "acme"))


class TestReadmeSeals(unittest.TestCase):
    """README.md opens with six example seals. Each image must be exactly the seal of the data and
    kind its row names, and the README must show its short code and full code, so the examples a
    reader checks first can never drift from the standard (tools/emit_readme_seals.py)."""

    def test_every_readme_seal_is_genuine_and_shown_with_its_data_kind_and_code(self):
        sys.path.insert(0, str(_ROOT / "tools"))
        import emit_readme_seals
        self.assertEqual(len(emit_readme_seals.examples()), 6)
        self.assertEqual(emit_readme_seals.check(), [])


class TestSuiteIntegrity(unittest.TestCase):
    """Enforces on this module the rule the comment below only states.

    Moving `unittest.main()` to the bottom fixed the instance described there -- it did not stop it
    recurring, and nothing else in this file would notice if it did. "Ran 17 tests" was a CLEAN,
    GREEN result; the four uncollected TestTag cases, including the one proving a LYING
    `inkan-code` tag is caught, simply were not in the total. Nobody reads a number that only
    goes down.

    So the total is pinned. Anything that stops a case being collected -- an early `main()`, a
    class renamed out of the loader's pattern, a method losing its `test_` prefix -- fails here
    with the reason, instead of passing quietly over less than it claims to cover.
    """

    # Every case the loader should find in this module, including the one below.
    EXPECTED_CASES = 47

    def test_every_case_declared_in_this_module_is_collected(self):
        collected = unittest.TestLoader().loadTestsFromModule(
            sys.modules[__name__]).countTestCases()
        self.assertEqual(
            collected, self.EXPECTED_CASES,
            "the loader collected %d cases, not %d. If cases were added or removed deliberately, "
            "update EXPECTED_CASES; otherwise a case has stopped being collected and this suite "
            "is reporting success over less than it claims." % (collected, self.EXPECTED_CASES))


# `unittest.main()` MUST stay at the very bottom of this file. It used to sit between TestVerify and
# TestTag, and since it never returns, every test defined below it was silently skipped: the run
# reported "Ran 17 tests" and a clean exit while four TestTag cases -- the ones covering the embedded
# `inkan-code` tag, including the check that a LYING tag is caught -- had not been collected at all.
# A suite that passes by not running the tests is the failure mode this repo's doctrine names first.
if __name__ == "__main__":
    unittest.main()
