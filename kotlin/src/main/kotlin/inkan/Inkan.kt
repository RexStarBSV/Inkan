// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
package inkan

import java.security.MessageDigest
import java.text.Normalizer

/**
 * Inkan domain separation + text tag — the anchor layer of BRC-145 (Inkan Standard v1.0).
 * The same data + kind always give the same seed and the same short hex tag, so a tag computed here
 * equals the one every conforming implementation computes — that is what lets a user compare the
 * seals two devices show, including two that never share a network.
 *
 * The seal image itself is rendered by [SealV3]; this provides the seed + the hex tag (two views of
 * one fingerprint), which is enough for the Code-Inkan integrity check and for comparing
 * signer / address / contract seals by their text form.
 */
object Inkan {
    // Fixed published domain — MUST match BRC-145 ("inkan/v1\0").
    private val DOMAIN = "inkan/v1\u0000".toByteArray(Charsets.UTF_8)

    const val KIND_CODE = "code"
    const val KIND_ADDRESS = "address"
    const val KIND_IDENTITY = "identity"
    const val KIND_ACCOUNT = "account"
    const val KIND_CONTRACT = "contract"
    const val KIND_SIGNER = "signer"

    /**
     * UTF-8 encode, REJECTING unencodable text rather than substituting for it (SPEC §4 E4).
     *
     * `String.toByteArray(UTF_8)` replaces an unpaired surrogate instead of failing, so every
     * distinct malformed kind collapsed onto ONE anchor while the caller believed it had succeeded.
     * Python raised and JavaScript substituted differently again: three ports, three answers, and no
     * failure anywhere. Fail closed; the caller has malformed text and needs to know.
     */
    internal fun encodeUtf8(text: String, what: String): ByteArray {
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c.isHighSurrogate()) {
                require(i + 1 < text.length && text[i + 1].isLowSurrogate()) {
                    "$what is not encodable as UTF-8 and MUST be rejected, not substituted " +
                        "(SPEC §4 E4): unpaired high surrogate at position $i"
                }
                i++
            } else require(!c.isLowSurrogate()) {
                "$what is not encodable as UTF-8 and MUST be rejected, not substituted " +
                    "(SPEC §4 E4): unpaired low surrogate at position $i"
            }
            i++
        }
        return text.toByteArray(Charsets.UTF_8)
    }

    /** For each Unicode version, the first code point it assigned, newest first. */
    private val UNICODE_SENTINELS = listOf(
        "17.0" to 0x088F, "16.0" to 0x0897, "15.1" to 0x2FFC, "15.0" to 0x0CF3, "14.0" to 0x061D,
        "13.0" to 0x08BE, "12.1" to 0x32FF, "12.0" to 0x0C77, "11.0" to 0x0560, "10.0" to 0x0860,
        "9.0" to 0x08B6, "8.0" to 0x08B3, "7.0" to 0x037F, "6.3" to 0x061C, "6.2" to 0x20BA,
        "6.1" to 0x058F, "6.0" to 0x0526, "5.2" to 0x0524, "5.1" to 0x0370, "5.0" to 0x0242,
        "4.1" to 0x0237, "4.0" to 0x0221, "3.2" to 0x0220, "3.1" to 0x03F4, "3.0" to 0x01F6,
    )

    /**
     * The Unicode version of this JVM's character database, read through `Character.getType`, the
     * same database the E14 check below uses (and the one `java.text.Normalizer` is built from): the
     * newest version in the table above whose first new code point it assigns. A runtime newer than
     * the table reports the table's newest entry; null means older than Unicode 3.0.
     */
    val UNICODE_VERSION: String? by lazy {
        UNICODE_SENTINELS.firstOrNull { Character.getType(it.second) != Character.UNASSIGNED.toInt() }?.first
    }

    /** The 66 noncharacters: U+FDD0..U+FDEF, and the last two code points of each plane. */
    private fun isNoncharacter(cp: Int) = cp in 0xFDD0..0xFDEF || (cp and 0xFFFE) == 0xFFFE

    /**
     * Refuse text holding a code point this JVM's Unicode database leaves unassigned (SPEC §1 E14).
     *
     * NFC treats a code point it does not know as an unassigned starter, while a newer database may
     * know it as a combining mark or a composable letter, so guessing gives a different anchor from
     * an implementation that knew. Two databases that both assign every code point of a string
     * normalise it identically, now and later, so refusing never disagrees with another conforming
     * implementation. Noncharacters are permanently unassigned and normalise to themselves, so they
     * are accepted. Throws IllegalArgumentException.
     */
    fun rejectUnassigned(text: String, what: String) {
        var i = 0
        while (i < text.length) {
            val cp = text.codePointAt(i)
            require(Character.getType(cp) != Character.UNASSIGNED.toInt() || isNoncharacter(cp)) {
                "$what contains U+${"%04X".format(java.util.Locale.ROOT, cp)} at position $i, which is " +
                    "unassigned in the Unicode ${UNICODE_VERSION ?: "unknown"} database this JVM " +
                    "normalises with. Such text MUST be rejected, never normalised or hashed (SPEC §1 E14)"
            }
            i += Character.charCount(cp)
        }
    }

    fun seed(data: ByteArray, kind: String = ""): ByteArray {
        // Length-prefixed kind, per BRC-145: DOMAIN + u8(len(kind)) + kind + data.
        // Unambiguous for every kind/data pair, and NFC-normalised so visually-identical strings make
        // the same Inkan. len(kind_utf8) must be <= 255. A kind with an unassigned code point is
        // refused before it is normalised (E14).
        rejectUnassigned(kind, "kind")
        val kindBytes = encodeUtf8(Normalizer.normalize(kind, Normalizer.Form.NFC), "kind")
        require(kindBytes.size <= 255) { "kind must be at most 255 UTF-8 bytes" }
        return DOMAIN + byteArrayOf(kindBytes.size.toByte()) + kindBytes + data
    }

    fun seed(data: String, kind: String = ""): ByteArray {
        rejectUnassigned(data, "data")
        return seed(encodeUtf8(Normalizer.normalize(data, Normalizer.Form.NFC), "data"), kind)
    }

    /** A bare-hex prefix of the anchor, for compact display inside a product. It is not an Inkan
     *  code: SPEC §2 defines exactly two code forms, [code] and [shortCode]. */
    fun tag(data: ByteArray, kind: String = "", length: Int = 8): String =
        Hex.encode(sha256(seed(data, kind))).substring(0, length)

    fun tag(data: String, kind: String = "", length: Int = 8): String =
        Hex.encode(sha256(seed(data, kind))).substring(0, length)   // via seed(String): NFC-normalised

    // ---- codes (SPEC §2) ---------------------------------------------------------------------
    /** `ik` marks an Inkan code; the digit is the code-format / hash version (1 = SHA-256 over
     *  the glyph domain `inkan/v1`). */
    const val CODE_PREFIX = "ik1"

    /** Hex characters in the SHORT code's body: 16, a 64-bit prefix of the anchor. */
    const val SHORT_CODE_LEN = 16

    /** Hex characters in the FULL code's body: the 32-byte anchor. */
    const val FULL_CODE_LEN = 64

    /** The 32-byte anchor of (data, kind): SHA-256 of the glyph seed. */
    fun digest(data: ByteArray, kind: String = ""): ByteArray = sha256(seed(data, kind))

    fun digest(data: String, kind: String = ""): ByteArray = sha256(seed(data, kind))

    /** The full code, `ik1` + 64 lower-case hex: the self-identifying text form of the anchor. */
    fun code(data: ByteArray, kind: String = ""): String = CODE_PREFIX + Hex.encode(digest(data, kind))

    fun code(data: String, kind: String = ""): String = CODE_PREFIX + Hex.encode(digest(data, kind))

    /**
     * The short code, `ik1` + 16 hex, for filenames and display. The same form every other port
     * shows: a reader comparing two devices compares like with like. It is a label only; a GENUINE
     * verdict needs the full 32-byte anchor (SPEC §9 E8).
     */
    fun shortCode(data: ByteArray, kind: String = ""): String = code(data, kind).substring(0, CODE_PREFIX.length + SHORT_CODE_LEN)

    fun shortCode(data: String, kind: String = ""): String = code(data, kind).substring(0, CODE_PREFIX.length + SHORT_CODE_LEN)

    /**
     * Parse a FULL code and return its anchor as lower-case hex, refusing every other shape with
     * IllegalArgumentException, as the Python reader does (SPEC §2): a version this build does not
     * implement (never read as SHA-256), no version digit, a short code (a label that does not carry
     * the anchor), a body of the wrong length, or a body that is not ASCII hex.
     */
    fun codeToDigestHex(code: String): String {
        require(code.startsWith("ik")) { "not an Inkan code: $code" }
        require(code.startsWith(CODE_PREFIX)) {
            "unsupported code format ${code.take(CODE_PREFIX.length)}; this build understands $CODE_PREFIX. A " +
                "code whose version this build does not implement MUST be rejected, never read as SHA-256 (SPEC §2)"
        }
        val body = code.substring(CODE_PREFIX.length)
        require(body.isNotEmpty()) { "$code is a bare $CODE_PREFIX prefix carrying no digest at all" }
        require(body.all { Hex.nibble(it) >= 0 }) { "Inkan code body is not hex: $body" }
        require(body.length != SHORT_CODE_LEN) {
            "$code is a SHORT code ($SHORT_CODE_LEN hex): a label carrying only a prefix of the anchor. " +
                "Recompute and compare the full $FULL_CODE_LEN-hex digest (SPEC §9 E8)"
        }
        require(body.length == FULL_CODE_LEN) {
            "Inkan code body must be $FULL_CODE_LEN hex characters (SHA-256), got ${body.length}: $code"
        }
        return body.lowercase(java.util.Locale.ROOT)
    }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)
}
