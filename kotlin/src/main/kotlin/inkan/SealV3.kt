// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
package inkan

import java.security.MessageDigest
import java.util.Base64
import java.util.zip.CRC32
import java.util.zip.Deflater

/**
 * Inkan Seal v3 (ISv3) -- the visual seal engine. Original work.
 *
 * Port of the reference implementation in `Inkan/python/inkan_standard/seal.py`. All three ports consume the
 * same precomputed integer tables ([SealTables]) and contain no floating point, so Kotlin, Python
 * and JS agree byte-for-byte by construction rather than by luck.
 *
 * Structure is coded. Interior cells hold 2 bits each, fed by bit-interleaved extended Golay
 * [24,12,8] blocks (cell profiles 24/48/72). Any two distinct seals therefore differ in at least 8
 * interior cells: cells differing = popcount(A or B) >= max(|A|, |B|) >= 8. Every field is drawn
 * from a domain-separated SHA-256 stream, so flipping one input bit re-randomises everything at once.
 *
 * The `kind` selects the cell profile, the rotational symmetry order and the frame motif, and is
 * never digest-derived, so a signer seal cannot be mistaken for an address seal. `(cells, k)` is a
 * function of the kind and never a caller knob: one digest must render one seal, everywhere.
 *
 * This shares no code, structure, or output with LifeHash, and does not use Conway's Game of Life.
 * It is an original design. The legacy v1 engine (LifeHash, (c) Blockchain Commons) was DELETED on
 * 2026-07-09: no Inkan seals had ever been published, so nothing needed preserving and no
 * attribution obligation remains.
 *
 * JVM ARITHMETIC HAZARDS, handled explicitly below because each one silently corrupts a seal:
 *   1. `shr` is an ARITHMETIC shift and sign-extends. Every right shift over a codeword or a
 *      packed byte uses `ushr`, or masks immediately.
 *   2. `Byte` is signed. Every byte read from a table or a digest is widened with `and 0xFF`.
 *   3. Infix `and`/`or`/`shl` bind *looser* than arithmetic operators, so every mixed expression
 *      is parenthesised.
 *
 * PARITY STATUS: VERIFIED. [SealV3ConformanceTest] passes on Temurin JDK 17.0.19: `every sampled
 * vector matches the Python reference exactly` reproduces every sampled and constructed vector in
 * test-vectors/seal-v3-vectors.json byte-for-byte, and `sealPng encodes a valid indexed PNG whose
 * pixels match the reference` carries that parity through to the encoded image. The Python and JS
 * suites hold their engines to the same vector file. No counts are repeated here: the suites report
 * them, and a number copied into a comment goes stale. Re-run [SealV3ConformanceTest] after any
 * change to this file or the tables.
 */
object SealV3 {
    const val SEAL_VERSION: Int = 3

    /** Native canvas edge, in pixels. [SealTables] is module-internal, so code outside the module
     *  that compiles this engine reads the size from here. Pinned to the tables by the conformance
     *  test. */
    val CANVAS: Int = SealTables.CANVAS

    private val STREAM_DOMAIN = "inkan/seal/v3".toByteArray(Charsets.US_ASCII)

    /** kind -> (cells, symmetry order k, 6-bit frame motif). Never digest-derived. */
    val KINDS: Map<String, Triple<Int, Int, Int>> = SealTables.KINDS

    private val KIND_DOMAIN = "inkan/kind/v1\u0000".toByteArray(Charsets.UTF_8)

    /**
     * Resolve any kind string to (cells, k, motif). Reserved kinds use their curated entry; any
     * other string is derived deterministically (tier from an optional @t1/@t2/@t3 suffix; k and
     * frame motif from a domain-separated SHA-256 of the string). The standard is open to ANY kind,
     * tier-weighted, third-party assignable with no registry: any non-reserved string is a kind.
     */
    fun resolveKind(kind: String): Triple<Int, Int, Int> {
        KINDS[kind]?.let { return it }
        // A kind the anchor rejects (an unassigned code point, SPEC §4.2 E14) is rejected here too,
        // so no seal is ever drawn for a kind that has no anchor.
        Inkan.rejectUnassigned(kind, "kind")
        var tier = "t2"
        for (t in listOf("t1", "t2", "t3")) if (kind.endsWith("@$t")) { tier = t; break }
        val cells = SealTables.TIER_CELLS.getValue(tier)
        val md = MessageDigest.getInstance("SHA-256")
        md.update(KIND_DOMAIN)
        // Strict UTF-8 (SPEC §4.2 E4): toByteArray would replace an unpaired surrogate with '?', so
        // every malformed kind would resolve like a well-formed one instead of being refused.
        md.update(Inkan.encodeUtf8(kind, "kind"))
        val kh = md.digest()
        val k = 1 + ((kh[0].toInt() and 0xFF) % SealTables.KMAX.getValue(cells))
        val motif = SealTables.ORBIT_REPS[(kh[1].toInt() and 0xFF) % SealTables.ORBIT_REPS.size]
        return Triple(cells, k, motif)
    }

    /** Weighted palette draw table: class i appears SELECT_WEIGHTS[i] times. Normative order. */
    private val SELECT_TABLE: IntArray = run {
        val out = ArrayList<Int>()
        for (i in SealTables.SELECT_WEIGHTS.indices) {
            repeat(SealTables.SELECT_WEIGHTS[i]) { out.add(i) }
        }
        out.toIntArray()
    }

    // ---------------------------------------------------------------- codes
    private const val GOLAY_G = 0xAE3

    /** 12 info bits -> 24-bit extended Golay codeword. Minimum weight 8. */
    fun golay24(info12: Int): Int {
        var c = 0
        for (b in 0 until 12) {
            if (((info12 ushr b) and 1) == 1) c = c xor (GOLAY_G shl b)
        }
        return (c shl 1) or (Integer.bitCount(c) and 1)
    }


    // ---------------------------------------------------------------- field extraction
    /** SHA-256 in counter mode: an endless, portable byte stream over the digest. */
    private class Stream(private val digest: ByteArray) {
        private val md = MessageDigest.getInstance("SHA-256")
        private var buf: ByteArray = ByteArray(0)
        private var pos = 0
        private var ctr = 0

        fun byte(): Int {
            if (pos >= buf.size) {
                md.reset()
                md.update(digest)
                md.update(STREAM_DOMAIN)
                md.update(byteArrayOf(
                    ((ctr ushr 24) and 0xFF).toByte(),
                    ((ctr ushr 16) and 0xFF).toByte(),
                    ((ctr ushr 8) and 0xFF).toByte(),
                    (ctr and 0xFF).toByte(),
                ))
                buf = md.digest()
                pos = 0
                ctr++
            }
            return buf[pos++].toInt() and 0xFF          // Byte is signed; widen explicitly
        }
    }

    /** Rejection-sampled uniform value in [0, n). A plain `byte % n` over-weights low residues. */
    private fun uniform(s: Stream, n: Int): Int {
        val limit = 256 - (256 % n)
        while (true) {
            val b = s.byte()
            if (b < limit) return b % n
        }
    }

    /** Derived fields for a digest. Draw order is NORMATIVE and identical in all three ports. */
    data class Fields(val words: IntArray, val paletteIx: Int, val corePattern: Int) {
        override fun equals(other: Any?): Boolean =
            other is Fields && words.contentEquals(other.words) &&
                paletteIx == other.paletteIx && corePattern == other.corePattern
        override fun hashCode(): Int =
            (words.contentHashCode() * 31 + paletteIx) * 31 + corePattern
    }

    fun sealFields(digest: ByteArray, kind: String = ""): Fields {
        require(digest.size == 32) { "digest must be 32 bytes" }
        val cells = resolveKind(kind).first
        val s = Stream(digest)
        val words = IntArray(cells / 12) { ((s.byte() shl 8) or s.byte()) and 0xFFF }
        val paletteIx = SELECT_TABLE[uniform(s, SELECT_TABLE.size)]
        val corePattern = SealTables.CORE_PATTERNS[uniform(s, SealTables.CORE_PATTERNS.size)]
        return Fields(words, paletteIx, corePattern)
    }

    /** Info words -> per-cell 2-bit states, via the profile's code and its interleave. */
    fun cellsFromWords(words: IntArray, cells: Int): IntArray {
        val out = IntArray(cells)
        for (g in 0 until cells / 24) {
            val a = golay24(words[2 * g])
            val b = golay24(words[2 * g + 1])
            for (i in 0 until 24) {
                out[g * 24 + i] = (((b ushr i) and 1) shl 1) or ((a ushr i) and 1)
            }
        }
        return out
    }

    // ---------------------------------------------------------------- region maps
    private val regionCache = HashMap<String, IntArray>()

    private fun region(cells: Int, k: Int): IntArray = synchronized(regionCache) {
        val key = "$cells,$k"
        regionCache.getOrPut(key) {
            val blob = Base64.getDecoder().decode(
                SealTables.REGION_RLE[key] ?: throw IllegalStateException("no region table $key"))
            val out = IntArray(CANVAS * CANVAS)
            var w = 0
            var i = 0
            while (i < blob.size) {
                val v = blob[i].toInt() and 0xFF
                val n = (blob[i + 1].toInt() and 0xFF) or ((blob[i + 2].toInt() and 0xFF) shl 8)
                for (j in 0 until n) out[w++] = v
                i += 3
            }
            check(w == out.size) { "corrupt region table $key: $w of ${out.size}" }
            out
        }
    }

    // ---------------------------------------------------------------- render
    /**
     * Render directly from fields, as flat RGB888 channels (row-major, CANVAS*CANVAS*3).
     *
     * Returns `IntArray` of 0..255, not `ByteArray`, and deliberately: `Byte` is signed on the
     * JVM, so an Android caller doing `Color.argb(255, rgb[i], rgb[i+1], rgb[i+2])` would receive
     * negative channels for every value above 127. Keeping the channel type unsigned removes the
     * hazard at every call site rather than relying on each of them to mask.
     *
     * Exposed so the conformance test can CONSTRUCT the worst case (a minimum-weight codeword
     * difference) rather than hope to sample it.
     */
    fun sealRgbFromFields(words: IntArray, paletteIx: Int, corePattern: Int, kind: String = ""): IntArray {
        val (cells, k, motif) = resolveKind(kind)
        val cl = cellsFromWords(words, cells)
        val pal = SealTables.PALETTE[paletteIx]          // 15 ints: 5 roles x RGB
        val reg = region(cells, k)
        val out = IntArray(reg.size * 3)
        for (i in reg.indices) {
            val r = reg[i]
            val role: Int = when {
                r < cells -> cl[r]                                                   // 0..3
                r < 200 -> if (((corePattern ushr (r - 100)) and 1) == 1) 4 else 0    // core | ground
                r < 255 -> if (((motif ushr (r - 200)) and 1) == 1) 1 else 0          // accent1 | ground
                else -> 0                                                            // ground
            }
            val base = role * 3
            out[i * 3] = pal[base]
            out[i * 3 + 1] = pal[base + 1]
            out[i * 3 + 2] = pal[base + 2]
        }
        return out
    }

    /** Render a 32-byte digest to flat RGB888 channels (0..255). At most 5 colours appear. */
    fun sealRgb(digest: ByteArray, kind: String = ""): IntArray {
        val f = sealFields(digest, kind)
        return sealRgbFromFields(f.words, f.paletteIx, f.corePattern, kind)
    }

    /**
     * Convenience: seed -> SHA-256 -> seal, matching `inkanGlyph` in the other ports. `data` is TEXT,
     * so it goes through [Inkan.seed] (String), which NFC-normalises it (SPEC §1 E19). This used to
     * convert it straight to UTF-8 bytes, so a decomposed "café" drew a different seal here from
     * every other port and from this port's own text tag.
     */
    fun sealForInkan(data: String, kind: String = ""): IntArray {
        val digest = MessageDigest.getInstance("SHA-256").digest(Inkan.seed(data, kind))
        return sealRgb(digest, kind)
    }

    /** Convenience overload for raw payloads (addresses, pubkeys, instance ids). */
    fun sealForInkan(data: ByteArray, kind: String = ""): IntArray {
        val digest = MessageDigest.getInstance("SHA-256").digest(Inkan.seed(data, kind))
        return sealRgb(digest, kind)
    }


    // ---------------------------------------------------------------- PNG export
    private fun crc(vararg parts: ByteArray): Long {
        val c = CRC32(); for (p in parts) c.update(p); return c.value
    }

    private fun chunk(name: String, data: ByteArray): ByteArray {
        val nameB = name.toByteArray(Charsets.US_ASCII)
        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf((data.size ushr 24).toByte(), (data.size ushr 16).toByte(),
            (data.size ushr 8).toByte(), data.size.toByte()))
        out.write(nameB); out.write(data)
        val cv = crc(nameB, data)
        out.write(byteArrayOf((cv ushr 24).toByte(), (cv ushr 16).toByte(), (cv ushr 8).toByte(), cv.toByte()))
        return out.toByteArray()
    }

    private fun iTxt(keyword: String, text: String): ByteArray {
        val kw = keyword.toByteArray(Charsets.US_ASCII); val tx = text.toByteArray(Charsets.UTF_8)
        val body = java.io.ByteArrayOutputStream()
        body.write(kw); body.write(byteArrayOf(0, 0, 0, 0, 0)); body.write(tx)
        return chunk("iTXt", body.toByteArray())
    }

    /**
     * Encode a seal to an 8-bit indexed PNG whose PIXELS match the reference exactly. Uses the JVM
     * Deflater (available on Android too). `tag` embeds the ik1 code + kind as iTXt, matching the
     * cross-language tag format. The cross-language invariant is the RGB, not the PNG bytes.
     */
    fun sealPng(digest: ByteArray, kind: String = "", tag: Boolean = false): ByteArray {
        val n = CANVAS
        val rgb = sealRgb(digest, kind)               // IntArray of unsigned 0..255
        val seen = sortedSetOf<Int>()
        for (i in 0 until n * n) seen.add((rgb[i * 3] shl 16) or (rgb[i * 3 + 1] shl 8) or rgb[i * 3 + 2])
        val pal = seen.toIntArray()
        val ix = HashMap<Int, Int>(); pal.forEachIndexed { i, k -> ix[k] = i }
        val raw = ByteArray(n * (n + 1))
        var o = 0
        for (y in 0 until n) {
            raw[o++] = 0
            for (x in 0 until n) {
                val p = (y * n + x) * 3
                raw[o++] = ix.getValue((rgb[p] shl 16) or (rgb[p + 1] shl 8) or rgb[p + 2]).toByte()
            }
        }
        val def = Deflater(Deflater.BEST_COMPRESSION); def.setInput(raw); def.finish()
        val comp = java.io.ByteArrayOutputStream(); val buf = ByteArray(8192)
        while (!def.finished()) comp.write(buf, 0, def.deflate(buf))
        def.end()

        val ihdr = ByteArray(13)
        ihdr[0] = (n ushr 24).toByte(); ihdr[1] = (n ushr 16).toByte(); ihdr[2] = (n ushr 8).toByte(); ihdr[3] = n.toByte()
        ihdr[4] = (n ushr 24).toByte(); ihdr[5] = (n ushr 16).toByte(); ihdr[6] = (n ushr 8).toByte(); ihdr[7] = n.toByte()
        ihdr[8] = 8; ihdr[9] = 3       // bit depth 8, colour type 3 (indexed)
        val plte = ByteArray(pal.size * 3)
        pal.forEachIndexed { i, k -> plte[i * 3] = (k ushr 16).toByte(); plte[i * 3 + 1] = (k ushr 8).toByte(); plte[i * 3 + 2] = k.toByte() }

        val out = java.io.ByteArrayOutputStream()
        out.write(byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))
        out.write(chunk("IHDR", ihdr)); out.write(chunk("PLTE", plte)); out.write(chunk("IDAT", comp.toByteArray()))
        if (tag) {
            out.write(iTxt("inkan-code", Inkan.CODE_PREFIX + Hex.encode(digest))); out.write(iTxt("inkan-kind", kind))
        }
        out.write(chunk("IEND", ByteArray(0)))
        return out.toByteArray()
    }
}
