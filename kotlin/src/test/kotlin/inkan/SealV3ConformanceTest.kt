package inkan

import java.io.File
import java.security.MessageDigest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * THE parity gate for [SealV3], and the standard's own proof that a conforming Kotlin
 * implementation exists. STATUS: PASSING on Temurin JDK 17.0.19, so the Kotlin engine reproduces
 * every pinned vector byte-for-byte. This test is the standing regression gate: re-run it after any
 * change to SealV3.kt or SealTables.kt. A red run here means the cross-surface comparison protocol
 * is broken and no seal from this engine can be trusted.
 *
 * This is the CANONICAL copy, kept in this repository so the standard is self-contained: all three
 * reference implementations (Python, JS, Kotlin) and all three conformance gates live here. A
 * vendored copy of the engine is the same four files with a different `package` line -- that
 * declaration is the ONLY permitted divergence. If a vendored copy and this one disagree on anything
 * else, this one wins.
 *
 * Vectors resolve from ../test-vectors/seal-v3-vectors.json, or override:
 *     INKAN_VECTORS=/path/to/seal-v3-vectors.json ./gradlew test
 *
 * The vectors are the canonical cross-language reference and are generated only by the Python
 * implementation (Inkan/python/tools/gen_seal_v3_vectors.py). This file never regenerates them.
 */
class SealV3ConformanceTest {

    private fun vectorFile(): File {
        System.getenv("INKAN_VECTORS")?.let { return File(it) }
        return File("../test-vectors/seal-v3-vectors.json").canonicalFile
    }

    private fun doc(): JsonObject {
        val f = vectorFile()
        assertTrue(f.isFile, "vector file not found at ${f.path}; set INKAN_VECTORS")
        val root = Json.parseToJsonElement(f.readText()).jsonObject
        // A file that EXISTS is not a file that is right. Handed the anchor vectors instead of these
        // — which is what happened when both suites read one override variable — the guard above
        // passes and three tests then die on `!!` with a bare NullPointerException that names
        // neither the file nor the cause.
        assertTrue("sampled" in root,
            "${f.path} has no 'sampled' key — this is not the seal-v3 vector file " +
            "(vectors.json is a different document; check INKAN_VECTORS)")
        return root
    }

    private fun hexToBytes(h: String): ByteArray = ByteArray(h.length / 2) {
        ((Character.digit(h[it * 2], 16) shl 4) or Character.digit(h[it * 2 + 1], 16)).toByte()
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** Channels are unsigned 0..255 Ints; the vectors hash the raw RGB888 byte stream. */
    private fun rgbBytes(px: IntArray) = ByteArray(px.size) { px[it].toByte() }

    // ---------------------------------------------------------------- JVM arithmetic hazards
    //
    // Each of these silently corrupts a seal rather than throwing. They are asserted here so a
    // regression is caught at its cause, not 200 vectors later at its symptom.

    @Test
    fun `signed-shift and signed-byte hazards behave as the engine assumes`() {
        // 1. `shr` sign-extends; `ushr` does not. The engine uses ushr everywhere.
        assertEquals(-1, -1 shr 31, "shr must sign-extend (this is why the engine never uses it)")
        assertEquals(1, -1 ushr 31, "ushr must zero-fill")
        // 2. Byte is signed: 0x80..0xFF read back negative unless widened.
        val b: Byte = 0xAE.toByte()
        assertEquals(-82, b.toInt())
        assertEquals(0xAE, b.toInt() and 0xFF, "every byte read must be masked")
        // 3. Shift counts are masked to 6 bits for Long: `1L shl 64` is 1L, not 0.
        assertEquals(1L, 1L shl 64, "shift counts mask to 6 bits for Long")
    }


    // ---------------------------------------------------------------- the codes
    @Test
    fun `Golay is linear, injective, and has minimum weight 8`() {
        assertEquals(
            SealV3.golay24(0x123) xor SealV3.golay24(0xabc),
            SealV3.golay24(0x123 xor 0xabc),
            "Golay must be linear",
        )
        val seen = HashSet<Int>(8192)
        var minWeight = 24
        for (i in 0 until 4096) {
            val c = SealV3.golay24(i)
            seen.add(c)
            if (i != 0) minWeight = minOf(minWeight, Integer.bitCount(c))
            assertEquals(0, Integer.bitCount(c) and 1, "extended Golay codewords have even weight")
        }
        assertEquals(4096, seen.size, "Golay must be injective")
        assertEquals(8, minWeight, "the entire structural guarantee rests on this")
    }



    // ---------------------------------------------------------------- kinds
    @Test
    fun `kind table matches the vectors and is rotation-distinct within each config`() {
        val d = doc()
        assertEquals(3, d["seal_version"]!!.jsonPrimitive.content.toInt())
        assertEquals(SealV3.CANVAS, d["canvas"]!!.jsonPrimitive.content.toInt())
        val kinds = d["kinds"]!!.jsonObject
        // The vector `kinds` map includes OPEN kinds (not in the reserved table); resolveKind must
        // reproduce every one. The reserved table is a subset.
        assertTrue(kinds.size >= SealV3.KINDS.size, "vectors cover at least the reserved kinds")
        for ((name, spec) in kinds) {
            val o = spec.jsonObject
            val expect = Triple(
                o["cells"]!!.jsonPrimitive.content.toInt(),
                o["k"]!!.jsonPrimitive.content.toInt(),
                o["motif"]!!.jsonPrimitive.content.toInt(),
            )
            assertEquals(expect, SealV3.resolveKind(name), "kind $name")
        }
        // Motifs sharing a (cells, k) must be distinct under all 6 rotations, or the kinds are
        // visually confusable -- the one property the frame exists to provide.
        fun rots(m: Int): Set<Int> = (0 until 6).map { ((m shl it) or (m ushr (6 - it))) and 0b111111 }.toSet()
        val byConfig = SealV3.KINDS.entries.groupBy { Pair(it.value.first, it.value.second) }
        for ((cfg, members) in byConfig) {
            for (i in members.indices) for (j in i + 1 until members.size) {
                val a = rots(members[i].value.third)
                val b = rots(members[j].value.third)
                assertTrue(
                    a.intersect(b).isEmpty(),
                    "${members[i].key} and ${members[j].key} share config $cfg and a rotation",
                )
            }
        }
    }

    // ---------------------------------------------------------------- the vectors
    @Test
    fun `every sampled vector matches the Python reference exactly`() {
        val sampled = doc()["sampled"]!!.jsonArray
        assertTrue(sampled.size >= 75, "expected the full sampled set, got ${sampled.size}")
        for (el in sampled) {
            val v = el.jsonObject
            val kind = v["kind"]!!.jsonPrimitive.content
            val digest = hexToBytes(v["digest_hex"]!!.jsonPrimitive.content)
            val f = SealV3.sealFields(digest, kind)

            val words = v["words"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }.toIntArray()
            assertTrue(f.words.contentEquals(words), "words $kind/${v["digest_hex"]}")
            assertEquals(v["palette_ix"]!!.jsonPrimitive.content.toInt(), f.paletteIx, "palette $kind")
            assertEquals(v["core_pattern"]!!.jsonPrimitive.content.toInt(), f.corePattern, "core $kind")

            val rgb = SealV3.sealRgbFromFields(f.words, f.paletteIx, f.corePattern, kind)
            assertEquals(SealV3.CANVAS * SealV3.CANVAS * 3, rgb.size)
            assertTrue(rgb.all { it in 0..255 }, "channels must be unsigned 0..255")
            assertEquals(v["rgb_sha256"]!!.jsonPrimitive.content, sha256Hex(rgbBytes(rgb)), "rgb $kind")
        }
    }

    @Test
    fun `constructed worst case differs in exactly 8 cells and both renders match`() {
        for (el in doc()["constructed_worst_case"]!!.jsonArray) {
            val v = el.jsonObject
            val kind = v["kind"]!!.jsonPrimitive.content
            val cells = v["cells"]!!.jsonPrimitive.content.toInt()
            val err = v["min_weight_error_word"]!!.jsonPrimitive.content.toInt()
            val f = SealV3.sealFields(hexToBytes(v["digest_hex"]!!.jsonPrimitive.content), kind)

            val words2 = f.words.copyOf()
            words2[0] = words2[0] xor err
            val c1 = SealV3.cellsFromWords(f.words, cells)
            val c2 = SealV3.cellsFromWords(words2, cells)
            val diff = c1.indices.count { c1[it] != c2[it] }
            assertEquals(v["cells_differing"]!!.jsonPrimitive.content.toInt(), diff)
            assertEquals(8, diff, "the floor is 8 cells, for every profile and every k")

            assertEquals(
                v["rgb_sha256_a"]!!.jsonPrimitive.content,
                sha256Hex(rgbBytes(SealV3.sealRgbFromFields(f.words, f.paletteIx, f.corePattern, kind))),
            )
            assertEquals(
                v["rgb_sha256_b"]!!.jsonPrimitive.content,
                sha256Hex(rgbBytes(SealV3.sealRgbFromFields(words2, f.paletteIx, f.corePattern, kind))),
            )
        }
    }

    // ---------------------------------------------------------------- engine invariants
    @Test
    fun `core is constant-weight 2 and seals render 4 or 5 flat colours`() {
        val md = MessageDigest.getInstance("SHA-256")
        for (i in 0 until 64) {
            val digest = md.digest("prop/$i".toByteArray())
            val f = SealV3.sealFields(digest, "")
            assertEquals(2, Integer.bitCount(f.corePattern), "core must be constant-weight 2")
            val rgb = SealV3.sealRgb(digest, "")
            val colours = HashSet<Int>()
            for (p in rgb.indices step 3) colours.add((rgb[p] shl 16) or (rgb[p + 1] shl 8) or rgb[p + 2])
            assertTrue(colours.size in 4..5, "expected 4-5 flat colours, got ${colours.size}")
        }
    }

    @Test
    fun `every kind renders, including the custom presets`() {
        val md = MessageDigest.getInstance("SHA-256")
        for (kind in SealV3.KINDS.keys) {
            val rgb = SealV3.sealRgb(md.digest(kind.toByteArray()), kind)
            assertEquals(SealV3.CANVAS * SealV3.CANVAS * 3, rgb.size, "kind '$kind' must render")
        }
    }


    @Test
    fun `sealPng encodes a valid indexed PNG whose pixels match the reference`() {
        val md = MessageDigest.getInstance("SHA-256")
        for (kind in listOf("address", "signer", "café@t2", "custom/32")) {
            val digest = md.digest("demo/$kind".toByteArray())
            val png = SealV3.sealPng(digest, kind)
            // valid PNG signature
            assertEquals(0x89.toByte(), png[0]); assertEquals('P'.code.toByte(), png[1])
            // decode via ImageIO and compare RGB to the engine's own sealRgb
            val img = javax.imageio.ImageIO.read(java.io.ByteArrayInputStream(png))
            assertEquals(SealV3.CANVAS, img.width); assertEquals(SealV3.CANVAS, img.height)
            val rgb = SealV3.sealRgb(digest, kind)
            var mismatch = 0
            for (y in 0 until img.height) for (x in 0 until img.width) {
                val argb = img.getRGB(x, y); val i = (y * img.width + x) * 3
                if (((argb ushr 16) and 0xFF) != rgb[i] || ((argb ushr 8) and 0xFF) != rgb[i + 1] ||
                    (argb and 0xFF) != rgb[i + 2]) mismatch++
            }
            assertEquals(0, mismatch, "PNG pixels must match sealRgb for kind '$kind'")

            // tagged export carries the ik1 code + kind, still decodes to the same pixels
            val tagged = SealV3.sealPng(digest, kind, tag = true)
            val hex = digest.joinToString("") { "%02x".format(it) }
            assertTrue(String(tagged, Charsets.ISO_8859_1).contains("ik1$hex"), "tag must embed ik1 code")
            val timg = javax.imageio.ImageIO.read(java.io.ByteArrayInputStream(tagged))
            assertEquals(SealV3.CANVAS, timg.width)
        }
    }
}
