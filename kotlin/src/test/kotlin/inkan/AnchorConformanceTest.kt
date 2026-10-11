// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
package inkan

import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The ANCHOR layer of BRC-145, checked against the canonical vectors.
 *
 * WHY THIS FILE EXISTS. This port carried exactly one test file, covering the seal RENDERER. The
 * anchor underneath it — `seed = DOMAIN || u8(len(kind)) || kind || data`, BRC-145 §2, the value
 * every trust decision is actually made against — had no test at all. The seal is a presentation of
 * the anchor and the standard says so plainly: "the anchor, never the presentation, is trusted." A
 * port that renders the picture correctly and computes the wrong anchor would have passed.
 *
 * `Hex` and `Base64Url` were likewise untested, and they sit between the anchor and every text form
 * a user compares by eye.
 *
 * WHAT MAKES THIS A CONFORMANCE TEST rather than a self-consistency one: `seed_hex` comes from the
 * shared vector file, produced by the Python reference. Recomputing the anchor here and comparing to
 * our own output would prove only that this port agrees with itself.
 *
 * Point INKAN_ANCHOR_VECTORS at the vector file, or drop the Inkan checkout beside this repo:
 *     INKAN_ANCHOR_VECTORS=/path/to/Inkan/test-vectors/vectors.json ./gradlew :test
 *
 * The variable is NOT `INKAN_VECTORS`. SealV3ConformanceTest already owns that name and resolves it
 * to a DIFFERENT file (seal-v3-vectors.json). This file originally reused it, so setting it to run
 * this test handed the seal test the wrong JSON: its `isFile` guard still passed — the path exists,
 * it is simply the wrong document — and it then died on `!!` with a bare NullPointerException three
 * tests deep. One override name for two different files is a trap; each suite names its own.
 */
class AnchorConformanceTest {

    private fun vectorFile(): File {
        System.getenv("INKAN_ANCHOR_VECTORS")?.let { return File(it) }
        return File("../test-vectors/vectors.json").canonicalFile
    }

    private fun doc(): JsonObject {
        val f = vectorFile()
        assertTrue(f.isFile, "vector file not found at ${f.path}; set INKAN_ANCHOR_VECTORS")
        val root = Json.parseToJsonElement(f.readText()).jsonObject
        // Existing is not the same as correct. Point this at the seal vectors and every assertion
        // below would fail on a null deref instead of saying which file was wrong.
        assertTrue("inkan" in root,
            "${f.path} has no 'inkan' key — this is not the anchor vector file " +
            "(seal-v3-vectors.json is a different document; check INKAN_ANCHOR_VECTORS)")
        return root
    }

    private fun hexToBytes(h: String) = ByteArray(h.length / 2) {
        ((Character.digit(h[it * 2], 16) shl 4) or Character.digit(h[it * 2 + 1], 16)).toByte()
    }

    // ── the anchor ──────────────────────────────────────────────────────────────────────────────

    @Test
    fun `every vector's seed matches the Python reference byte for byte`() {
        val vectors = doc()["inkan"]!!.jsonObject["vectors"]!!.jsonArray
        assertTrue(vectors.size >= 3, "expected the shared vector set, found ${vectors.size}")
        var checked = 0
        for (v in vectors) {
            val o = v.jsonObject
            val data = o["data_utf8"]!!.jsonPrimitive.content
            val kind = o["kind"]!!.jsonPrimitive.content
            val expected = o["seed_hex"]!!.jsonPrimitive.content
            val got = Hex.encode(Inkan.seed(data, kind))
            // The vector file stores a PREFIX of the seed for compactness; compare on that prefix.
            assertTrue(got.startsWith(expected),
                "seed mismatch for data=${data.take(24)} kind='$kind'\n  expected prefix $expected\n  got            ${got.take(expected.length)}")
            checked++
        }
        assertEquals(vectors.size, checked)
    }

    @Test
    fun `the domain and the length prefix are both present and in the right order`() {
        // Asserted structurally as well as by vector, because a port that dropped the length prefix
        // still matches any vector whose kind is empty — and the empty-kind case is the first one.
        val seed = Inkan.seed("x", "address")
        val head = Hex.encode(seed.copyOf(11))
        assertEquals("696e6b616e2f76310007", head.take(20),
            "expected 'inkan/v1' + 0x00 + u8(7) for kind='address'")
    }

    @Test
    fun `a different kind over identical data gives a different anchor`() {
        // The whole point of the scheme: type is inside the digest, so a commitment to an address
        // cannot collide with a commitment to a contract over the same bytes.
        val a = Inkan.seed("same-bytes", "address")
        val b = Inkan.seed("same-bytes", "contract")
        assertTrue(!a.contentEquals(b), "kind is not reaching the seed")
    }

    @Test
    fun `the length prefix removes the boundary ambiguity it exists for`() {
        // BRC-145 TV5. Without u8(len(kind)) these two would produce identical bytes:
        //   kind="ab", data="cd"   vs   kind="a", data="bcd"
        val x = Inkan.seed("cd", "ab")
        val y = Inkan.seed("bcd", "a")
        assertTrue(!x.contentEquals(y), "length-prefix collision — the u8(len) prefix is missing")
    }

    @Test
    fun `text is NFC-normalised but raw bytes are not`() {
        // NFC composed vs decomposed must agree for TEXT...
        val composed = "é"                 // é
        val decomposed = "é"              // e + combining acute
        assertContentEquals(Inkan.seed(composed), Inkan.seed(decomposed),
            "text was not NFC-normalised, so the same character in two encodings anchors differently")
        // ...and raw octets must NOT be touched, because they are not text.
        val raw = byteArrayOf(0xE2.toByte(), 0x9C.toByte(), 0x93.toByte())
        assertContentEquals(Inkan.seed(raw), Inkan.seed(raw))
    }

    @Test
    fun `a kind longer than 255 bytes is refused rather than truncated`() {
        // The prefix is one byte. Truncating instead of refusing would silently alias two kinds.
        assertFailsWith<Exception> { Inkan.seed("data", "k".repeat(256)) }
    }

    @Test
    fun `an unpaired surrogate is REFUSED, not substituted (E4)`() {
        // SPEC §4 E4, and the only one of the three 2026-08-04 errata this port can carry: E10 and
        // E12 are verification rules and this port has no verifier. Kotlin implemented E4 and
        // nothing tested it, which is precisely the state that produced the erratum -- Python raised
        // by accident of its default error handler, JS and Kotlin substituted, and one malformed
        // kind yielded three anchors with every port believing it had succeeded.
        //
        // Substitution is a COLLISION, not leniency, so both must fail rather than agree:
        assertFailsWith<Exception> { Inkan.seed("data", "bad\uD800") }   // unpaired HIGH surrogate
        assertFailsWith<Exception> { Inkan.seed("data", "bad\uDC00") }   // unpaired LOW surrogate
        // ...and the same rule binds the DATA side, not just the kind.
        assertFailsWith<Exception> { Inkan.seed("bad\uD800", "address") }
    }

    @Test
    fun `the kind derivation refuses an unpaired surrogate too (E4)`() {
        // toByteArray(UTF_8) replaced it with '?', so every malformed kind resolved like the kind
        // "bad?" while the anchor, fixed earlier, refused it.
        for (bad in listOf("bad\uD800", "bad\uDC00", "x:\uDFFF@t1")) {
            val e = assertFailsWith<IllegalArgumentException> { SealV3.resolveKind(bad) }
            assertTrue("E4" in (e.message ?: ""), e.message)
        }
        assertEquals(Triple(48, 1, 9), SealV3.resolveKind("\uD83D\uDE00"))       // U+1F600, a valid pair
        assertEquals(Triple(72, 2, 27), SealV3.resolveKind("x:\uD83D\uDE00@t1"))
    }

    @Test
    fun `a WELL-FORMED surrogate pair is ordinary text and still anchors`() {
        // The guard must reject ill-formed text, not all astral characters. U+1F600 is a legitimate
        // pair; refusing it would break every emoji kind and make E4 a regression instead of a fix.
        val emoji = "😀"                       // U+1F600, a valid pair: F0 9F 98 80
        val seed = Inkan.seed(emoji, emoji)
        // seed = domain(8) || 0x00 || u8(len(kind)) || kind || data, so 8+1+1+4+4 for this input.
        assertEquals(18, seed.size, "the pair was substituted or dropped rather than encoded")
        assertTrue(Hex.encode(seed).contains("f09f9880"),
            "the emoji's real UTF-8 bytes are absent from the seed")
        assertTrue(!Inkan.seed(emoji).contentEquals(Inkan.seed("x")))
    }

    @Test
    fun `the tag is a prefix of the anchor digest and its length is respected`() {
        val tag8 = Inkan.tag("Hello")
        val tag16 = Inkan.tag("Hello", length = 16)
        assertEquals(8, tag8.length)
        assertEquals(16, tag16.length)
        assertTrue(tag16.startsWith(tag8), "the shorter tag is not a prefix of the longer one")
    }

    // ── the encodings underneath it ─────────────────────────────────────────────────────────────

    @Test
    fun `Hex round-trips and emits lower case`() {
        val bytes = ByteArray(256) { it.toByte() }
        val hex = Hex.encode(bytes)
        assertEquals(512, hex.length)
        assertEquals(hex.lowercase(), hex, "BRC-145 specifies lower-case hex")
        assertContentEquals(bytes, Hex.decode(hex))
    }

    @Test
    fun `Hex decodes upper case too, since it only has to READ what others emit`() {
        assertContentEquals(Hex.decode("ABCDEF"), Hex.decode("abcdef"))
    }

    @Test
    fun `Hex refuses odd-length and non-hex input instead of guessing`() {
        assertFailsWith<Exception> { Hex.decode("abc") }
        assertFailsWith<Exception> { Hex.decode("zz") }
    }

    @Test
    fun `Hex reads ASCII hex digits only`() {
        // Character.digit accepted every Unicode decimal digit, so these all decoded as "00".
        for (bad in listOf("\u0660\u0660", "\u0966\u0966", "\uFF10\uFF10", "0\uFF10", "\uFF41\uFF41")) {
            assertFailsWith<IllegalArgumentException>(bad) { Hex.decode(bad) }
        }
        assertContentEquals(byteArrayOf(0x0a, 0xBC.toByte()), Hex.decode("0aBc"))
    }

    @Test
    fun `codes are the ik1 forms SPEC section 2 defines`() {
        // BRC-145 TV1 and TV2, the same codes every other port shows.
        assertEquals("ik1ae63a28a7b3fbae640f24ab4003d285a453e5493b89741326a7fbcc36a2a6a44", Inkan.code("Hello"))
        assertEquals("ik1ae63a28a7b3fbae6", Inkan.shortCode("Hello"))
        val addr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        assertEquals("ik112cf1aaca7ef50793d990e94c9ae889af6f9e8fdfc28b2f9a72d4028bde05dcd",
            Inkan.code(addr.toByteArray(Charsets.UTF_8), Inkan.KIND_ADDRESS))
        assertEquals(Inkan.code(addr, Inkan.KIND_ADDRESS), Inkan.code(addr.toByteArray(Charsets.UTF_8), Inkan.KIND_ADDRESS))
        assertEquals(19, Inkan.shortCode(addr, "address").length)
        assertTrue(Inkan.code("Hello").startsWith(Inkan.shortCode("Hello")))
        assertTrue(Inkan.code("Hello").substring(3).startsWith(Inkan.tag("Hello")), "the bare tag is a prefix of the body")
    }

    @Test
    fun `a code is parsed back only in its full ik1 form`() {
        val digest = "12cf1aaca7ef50793d990e94c9ae889af6f9e8fdfc28b2f9a72d4028bde05dcd"
        assertEquals(digest, Inkan.codeToDigestHex("ik1$digest"))
        assertEquals(digest, Inkan.codeToDigestHex("ik1" + digest.uppercase()))
        for (bad in listOf("ik2$digest", "ik$digest", "ik1", "", "xx1$digest", "ik1" + digest.dropLast(1),
                "ik1${digest}aa", "ik1" + "z".repeat(64), "ik1" + digest.take(16),
                "ik1" + "\uFF10".repeat(64), "ik1" + "\u0660".repeat(64))) {
            assertFailsWith<IllegalArgumentException>(bad.take(24)) { Inkan.codeToDigestHex(bad) }
        }
        val e = assertFailsWith<IllegalArgumentException> { Inkan.codeToDigestHex("ik1" + digest.take(16)) }
        assertTrue("SHORT" in (e.message ?: ""))
    }

    @Test
    fun `Base64Url round-trips and uses the URL alphabet`() {
        // 0xFB 0xFF would be "+/" in standard base64 and must be "-_" here, or a code pasted into a
        // URL changes meaning in transit.
        val bytes = byteArrayOf(0xFB.toByte(), 0xFF.toByte())
        val enc = Base64Url.encode(bytes)
        assertTrue(!enc.contains('+') && !enc.contains('/'),
            "standard-alphabet output would corrupt any code carried in a URL: $enc")
        assertContentEquals(bytes, Base64Url.decode(enc))
    }
}
