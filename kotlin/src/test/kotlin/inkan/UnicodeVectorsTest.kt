// SPDX-License-Identifier: BUSL-1.1
// SPDX-FileCopyrightText: 2026 RexStarBSV
package inkan

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions

/**
 * Text inputs and the Unicode database (SPEC §1, E14): reject a text input containing a code point
 * this JVM's Unicode database leaves unassigned, or return exactly the pinned result; never anything
 * else. Vectors: test-vectors/unicode-vectors.json. The adopter (fingerprint) vectors are not part of
 * this port, which has no fingerprint.
 */
class UnicodeVectorsTest {

    /** Errata whose vectors this port does not satisfy yet: reported as SKIPPED by name, never as
     *  passes. Remove an erratum here in the commit that implements it. */
    private val pendingErrata = setOf<String>()

    private val doc: JsonObject = Json.parseToJsonElement(
        File("../test-vectors/unicode-vectors.json").canonicalFile.readText(),
    ).jsonObject

    private fun text(v: JsonObject, key: String): String {
        val sb = StringBuilder()
        (v[key] as? JsonArray)?.forEach { sb.appendCodePoint(it.jsonPrimitive.content.toInt(16)) }
        return sb.toString()
    }

    private fun isNoncharacter(cp: Int) = cp in 0xFDD0..0xFDEF || (cp and 0xFFFE) == 0xFFFE

    /** E14's test, with the database this JVM's Normalizer uses. */
    private fun unassignedHere(s: String) = s.codePoints().anyMatch {
        Character.getType(it) == Character.UNASSIGNED.toInt() && !isNoncharacter(it)
    }

    private fun anchorVectors(group: String) =
        doc[group]!!.jsonArray.map { it.jsonObject }.filter { "adopter" !in it }

    private fun check(v: JsonObject) {
        val kind = text(v, "kind")
        val r = v["result_if_accepted"]!!.jsonObject
        val code = "ik1" + Hex.encode(MessageDigest.getInstance("SHA-256").digest(Inkan.seed(text(v, "data"), kind)))
        assertEquals(r["code"]!!.jsonPrimitive.content, code, v["name"]!!.jsonPrimitive.content)
        val res = r["resolve"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }
        assertEquals(Triple(res[0], res[1], res[2]), SealV3.resolveKind(kind))
    }

    @Test
    fun `accept vectors give exactly the pinned result`() {
        val vs = anchorVectors("accept")
        assertTrue(vs.isNotEmpty())
        vs.forEach(::check)
    }

    @Test
    fun `either-or vectors this JVM's Unicode database can answer`() {
        val answerable = anchorVectors("either_or").filter { !unassignedHere(text(it, "data") + text(it, "kind")) }
        Assumptions.assumeTrue(answerable.isNotEmpty(),
            "this JVM's Unicode database lacks a code point in every either/or vector; all of them are " +
            "in the reject branch")
        answerable.forEach(::check)
    }

    @Test
    fun `inputs with unassigned code points are rejected`() {
        val due = (anchorVectors("either_or") + anchorVectors("reject_unless_assigned"))
            .filter { unassignedHere(text(it, "data") + text(it, "kind")) }
        assertTrue(due.isNotEmpty())
        val rule = doc["rule"]!!.jsonPrimitive.content
        Assumptions.assumeTrue(rule !in pendingErrata,
            "$rule not implemented in this port yet; ${due.size} vectors pending: " +
            due.joinToString(", ") { it["name"]!!.jsonPrimitive.content })
        for (v in due) assertFailsWith<IllegalArgumentException>(v["name"]!!.jsonPrimitive.content) {
            Inkan.seed(text(v, "data"), text(v, "kind"))
        }
    }

    @Test
    fun `the kind derivation rejects the same kinds`() {
        // SPEC §4.2: a kind the anchor rejects is rejected by the seal derivation too. Checked on its
        // own, because the test above stops at the anchor.
        val kinds = (anchorVectors("either_or") + anchorVectors("reject_unless_assigned"))
            .map { text(it, "kind") }.filter { it.isNotEmpty() && unassignedHere(it) }
        assertTrue(kinds.isNotEmpty())
        for (k in kinds) {
            val e = assertFailsWith<IllegalArgumentException>(k) { SealV3.resolveKind(k) }
            assertTrue("E14" in (e.message ?: ""), e.message)
        }
        assertEquals(Triple(24, 4, 23), SealV3.resolveKind("nc:\uFDD0@t3"))
        assertEquals(Triple(48, 3, 1), SealV3.resolveKind("caf\u00e9@t2"))
    }

    @Test
    fun `the Unicode version the check uses is reported`() {
        val v = Inkan.UNICODE_VERSION
        println("Unicode database (E14 check and NFC) on Java ${System.getProperty("java.version")}: $v")
        assertTrue(v != null && Regex("""\d+\.\d+""").matches(v), "unexpected Unicode version $v")
    }
}
