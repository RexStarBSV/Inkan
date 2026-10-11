// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
package inkan

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * SPEC §3.0: this port's tables must equal the published, SHA-256-pinned tables file, and the
 * engine must reproduce the coverage vectors, which reach every region map, every open-kind frame
 * motif, every palette class, every core pattern and the second block of the field stream.
 */
class SealV3CoverageTest {

    private fun json(name: String): JsonObject =
        Json.parseToJsonElement(File("../test-vectors/$name").canonicalFile.readText()).jsonObject

    private fun ints(o: JsonObject, key: String) = o[key]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }

    private fun sha256Hex(b: ByteArray) = Hex.encode(MessageDigest.getInstance("SHA-256").digest(b))

    @Test
    fun `this port's tables equal the published tables file`() {
        val t = json("seal-v3-tables.json")
        assertEquals(SealTables.CANVAS, t["CANVAS"]!!.jsonPrimitive.content.toInt())
        assertEquals(3, t["SEAL_VERSION"]!!.jsonPrimitive.content.toInt())
        assertEquals(0xAE3, t["GOLAY_G"]!!.jsonPrimitive.content.toInt())
        assertEquals(ints(t, "ORBIT_REPS"), SealTables.ORBIT_REPS.toList())
        assertEquals(ints(t, "SELECT_WEIGHTS"), SealTables.SELECT_WEIGHTS.toList())
        assertEquals(ints(t, "CORE_PATTERNS"), SealTables.CORE_PATTERNS.toList())
        assertEquals(t["TIER_CELLS"]!!.jsonObject.mapValues { it.value.jsonPrimitive.content.toInt() },
            SealTables.TIER_CELLS)
        assertEquals(t["KMAX"]!!.jsonObject.entries.associate { it.key.toInt() to it.value.jsonPrimitive.content.toInt() },
            SealTables.KMAX)
        val kinds = t["KINDS"]!!.jsonObject.mapValues {
            val e = it.value.jsonArray.map { x -> x.jsonPrimitive.content.toInt() }; Triple(e[0], e[1], e[2])
        }
        assertEquals(kinds, SealTables.KINDS)
        val pal = t["PALETTE"]!!.jsonArray
        assertEquals(pal.size, SealTables.PALETTE.size)
        for (i in pal.indices) {
            val flat = pal[i].jsonArray.flatMap { rgb -> rgb.jsonArray.map { it.jsonPrimitive.content.toInt() } }
            assertContentEquals(flat.toIntArray(), SealTables.PALETTE[i], "palette class $i")
        }
        val rle = t["REGION_RLE"]!!.jsonObject.mapValues { it.value.jsonPrimitive.content }
        assertEquals(rle, SealTables.REGION_RLE)
    }

    @Test
    fun `coverage and second-block vectors match the Python reference exactly`() {
        val doc = json("seal-v3-coverage-vectors.json")
        val all = doc["coverage"]!!.jsonArray + doc["second_block"]!!.jsonArray
        assertTrue(all.size >= 184, "expected the full coverage set, got ${all.size}")
        for (el in all) {
            val v = el.jsonObject
            val kind = v["kind"]!!.jsonPrimitive.content
            val r = ints(v, "resolve")
            assertEquals(Triple(r[0], r[1], r[2]), SealV3.resolveKind(kind), "resolve $kind")
            val f = SealV3.sealFields(Hex.decode(v["digest_hex"]!!.jsonPrimitive.content), kind)
            assertEquals(ints(v, "words"), f.words.toList(), "words $kind")
            assertEquals(v["palette_ix"]!!.jsonPrimitive.content.toInt(), f.paletteIx, "palette $kind")
            assertEquals(v["core_pattern"]!!.jsonPrimitive.content.toInt(), f.corePattern, "core $kind")
            val rgb = SealV3.sealRgbFromFields(f.words, f.paletteIx, f.corePattern, kind)
            assertEquals(v["rgb_sha256"]!!.jsonPrimitive.content,
                sha256Hex(ByteArray(rgb.size) { rgb[it].toByte() }), "rgb $kind")
        }
    }
}
