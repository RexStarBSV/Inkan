// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
package inkan

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Release provenance (SPEC §7.1): the anchor of a released file is the Inkan of the lower-case hex
 * of SHA-256(file bytes) under kind "code", and the inscription is that anchor's tagged Seal v3 PNG.
 * This port must reproduce the worked example `inkan_image_example` in test-vectors/vectors.json.
 * (The §7 fingerprint published beside it is not part of this port.)
 */
class ProvenanceTest {

    private fun example() = Json.parseToJsonElement(
        File("../test-vectors/vectors.json").canonicalFile.readText(),
    ).jsonObject["inkan_image_example"]!!.jsonObject

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    @Test
    fun `the release-provenance example is reproduced exactly`() {
        val v = example()
        val fileHex = Hex.encode(sha256(v["payload_utf8"]!!.jsonPrimitive.content.toByteArray(Charsets.UTF_8)))
        assertEquals(v["file_sha256_hex"]!!.jsonPrimitive.content, fileHex)
        val kind = v["kind"]!!.jsonPrimitive.content
        val seed = Inkan.seed(fileHex, kind)
        assertEquals(v["seed_hex"]!!.jsonPrimitive.content, Hex.encode(seed))
        val anchor = sha256(seed)
        assertEquals(v["code"]!!.jsonPrimitive.content, "ik1" + Hex.encode(anchor))
        val resolve = v["resolve"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }
        assertEquals(Triple(resolve[0], resolve[1], resolve[2]), SealV3.resolveKind(kind))
        val rgb = SealV3.sealRgb(anchor, kind)
        assertEquals(v["rgb_sha256"]!!.jsonPrimitive.content,
            Hex.encode(sha256(ByteArray(rgb.size) { rgb[it].toByte() })))
        val tagged = String(SealV3.sealPng(anchor, kind, tag = true), Charsets.ISO_8859_1)
        val tag = v["tag"]!!.jsonObject
        assertTrue(tagged.contains("inkan-code\u0000\u0000\u0000\u0000\u0000" + tag["inkan-code"]!!.jsonPrimitive.content))
        assertTrue(tagged.contains("inkan-kind\u0000\u0000\u0000\u0000\u0000" + tag["inkan-kind"]!!.jsonPrimitive.content))
    }
}
