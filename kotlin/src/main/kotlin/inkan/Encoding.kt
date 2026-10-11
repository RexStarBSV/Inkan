// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 RexStarBSV
// Inkan verification path (see LICENSE-VERIFY and NOTICE). Repository default licence: BSL 1.1.
package inkan

import java.util.Base64

/** Lower-case hex, and URL-safe base64 without padding — the encodings the wire protocol uses. */
object Hex {
    private val TABLE = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xff
            out[i * 2] = TABLE[v ushr 4]
            out[i * 2 + 1] = TABLE[v and 0x0f]
        }
        return String(out)
    }

    /**
     * The value of one ASCII hex digit (0-9, a-f, A-F), or -1. Not `Character.digit`, which also
     * accepts every other Unicode decimal digit: Arabic-Indic, Devanagari and full-width digits all
     * parsed as hex, so a code or digest typed or pasted with them decoded instead of being refused,
     * where the Python and JavaScript readers reject it.
     */
    fun nibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }

    fun decode(text: String): ByteArray {
        require(text.length % 2 == 0) { "hex length must be even" }
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val hi = nibble(text[i * 2])
            val lo = nibble(text[i * 2 + 1])
            require(hi >= 0 && lo >= 0) { "invalid hex: only the ASCII digits 0-9, a-f and A-F are hex" }
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }
}

object Base64Url {
    // URL-safe base64 WITH padding — matches Python base64.urlsafe_b64encode (keeps '=').
    private val ENC = Base64.getUrlEncoder()
    private val DEC = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = ENC.encodeToString(bytes)
    fun decode(text: String): ByteArray = DEC.decode(text)
}
