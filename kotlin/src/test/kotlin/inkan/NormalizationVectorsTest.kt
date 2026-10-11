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
 * Text and the anchor (SPEC §1, E3, E19): test-vectors/normalization-vectors.json, which pins that the
 * anchor NFC-normalises the kind while the seal derivation hashes it as provided, and the decomposed
 * "café" of unicode-vectors.json, which pins that text typed in decomposed form anchors as text.
 * The Python and JavaScript suites already ran these vectors; this port did not.
 */
class NormalizationVectorsTest {

    private fun load(name: String): JsonObject =
        Json.parseToJsonElement(File("../test-vectors/$name").canonicalFile.readText()).jsonObject

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    private fun rgbSha256(rgb: IntArray) = Hex.encode(sha256(ByteArray(rgb.size) { rgb[it].toByte() }))

    @Test
    fun `the anchor normalises the kind and the derivation hashes it as provided`() {
        val doc = load("normalization-vectors.json")
        val a = doc["anchor_layer"]!!.jsonObject
        val data = a["data_utf8"]!!.jsonPrimitive.content
        val nfc = a["kind_nfc"]!!.jsonPrimitive.content
        val nfd = buildString {
            a["kind_nfd_codepoints"]!!.jsonArray.forEach { appendCodePoint(it.jsonPrimitive.content.removePrefix("0x").toInt(16)) }
        }
        val dNfc = sha256(Inkan.seed(data, nfc))
        val dNfd = sha256(Inkan.seed(data, nfd))
        assertContentEquals(dNfc, dNfd, "the anchor must normalise: NFC and NFD kinds share one anchor")
        assertEquals(a["code"]!!.jsonPrimitive.content, "ik1" + Hex.encode(dNfc))
        val layers = doc["derivation_layer"]!!.jsonArray.map { it.jsonObject }
        assertEquals(2, layers.size)
        for (layer in layers) {
            val form = layer["kind_form"]!!.jsonPrimitive.content
            val kind = String(Hex.decode(layer["kind_utf8_hex"]!!.jsonPrimitive.content), Charsets.UTF_8)
            val res = layer["resolve"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }
            assertEquals(Triple(res[0], res[1], res[2]), SealV3.resolveKind(kind), "derivation is raw for $form")
            val digest = if (form == "NFC") dNfc else dNfd
            assertEquals(layer["rgb_sha256"]!!.jsonPrimitive.content, rgbSha256(SealV3.sealRgb(digest, kind)), "rgb pin $form")
        }
    }

    @Test
    fun `decomposed cafe typed as text anchors and seals as text`() {
        val v = load("unicode-vectors.json")["accept"]!!.jsonArray.map { it.jsonObject }
            .first { it["name"]!!.jsonPrimitive.content == "decomposed-cafe" }
        val typed = buildString { v["data"]!!.jsonArray.forEach { appendCodePoint(it.jsonPrimitive.content.toInt(16)) } }
        assertEquals("café", typed)
        val pinned = v["result_if_accepted"]!!.jsonObject["code"]!!.jsonPrimitive.content
        val asText = sha256(Inkan.seed(typed, ""))
        assertEquals(pinned, "ik1" + Hex.encode(asText))
        assertEquals(v["if_passed_as_bytes"]!!.jsonPrimitive.content,
            "ik1" + Hex.encode(sha256(Inkan.seed(typed.toByteArray(Charsets.UTF_8), ""))),
            "bytes are not text: the same characters as raw UTF-8 give the bytes anchor")
        // The String convenience draws the seal of the TEXT anchor, equal to the precomposed spelling.
        val seal = SealV3.sealForInkan(typed, "")
        assertTrue(seal.contentEquals(SealV3.sealRgb(asText, "")), "sealForInkan(String) must normalise")
        assertTrue(seal.contentEquals(SealV3.sealForInkan("café", "")))
        assertTrue(!seal.contentEquals(SealV3.sealForInkan(typed.toByteArray(Charsets.UTF_8), "")))
        assertEquals(Inkan.tag(typed, "", 16), Hex.encode(asText).substring(0, 16), "seal and tag agree")
    }
}
