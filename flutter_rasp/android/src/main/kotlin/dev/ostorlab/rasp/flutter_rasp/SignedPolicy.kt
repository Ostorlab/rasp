package dev.ostorlab.rasp.flutter_rasp

import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.Base64
import org.json.JSONObject

/** Verifies exact signed bytes before parsing policy fields. Keys come only from bootstrap configuration. */
class SignedPolicy(private val keys: Map<String, PublicKey>, private val tenantId: String, private val appId: String) {
    data class Verified(val revision: Long, val expiresAt: Long, val config: JSONObject)

    fun verify(envelope: String, currentRevision: Long, nowSeconds: Long, allowCurrent: Boolean = false): Verified {
        require(envelope.length <= 131072) { "policy too large" }
        val outer = JSONObject(envelope)
        val key = keys[outer.getString("kid")] as? ECPublicKey ?: throw IllegalArgumentException("unknown policy key")
        require(key.params.curve.field.fieldSize == 256 && key.params.order == java.math.BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)) { "policy key must be P-256" }
        val payload = Base64.getUrlDecoder().decode(outer.getString("payload"))
        val raw = Base64.getUrlDecoder().decode(outer.getString("signature"))
        require(raw.size == 64) { "invalid ES256 signature" }
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key); update(payload); verify(rawToDer(raw))
        }
        require(valid) { "invalid policy signature" }
        val value = JSONObject(String(payload, Charsets.UTF_8))
        require(value.getString("tenantId") == tenantId && value.getString("appId") == appId) { "wrong policy audience" }
        val revision = integer(value, "revision")
        val issuedAt = integer(value, "issuedAt")
        val expiresAt = integer(value, "expiresAt")
        require(revision > 0 && (revision > currentRevision || (allowCurrent && revision == currentRevision))) { "policy rollback" }
        require(issuedAt <= nowSeconds + 60 && issuedAt >= 0 && expiresAt > nowSeconds && expiresAt > issuedAt) { "policy expired or not yet valid" }
        val config = value.getJSONObject("config")
        val allowed = setOf("policy", "checkIntervalSeconds", "accessibilityAllowlist", "pins", "wipeOnThreats", "reactionDelayMillis")
        require(config.keys().asSequence().all { it in allowed }) { "unsupported policy parameter" }
        return Verified(revision, expiresAt, config)
    }

    private fun integer(value: JSONObject, name: String): Long {
        val number = value.get(name)
        require(number is Long || number is Int) { "$name must be an integer" }
        return (number as Number).toLong()
    }

    companion object {
        fun rawToDer(raw: ByteArray): ByteArray {
            require(raw.size == 64)
            fun integer(offset: Int): ByteArray {
                var part = raw.copyOfRange(offset, offset + 32).dropWhile { it == 0.toByte() }.toByteArray()
                if (part.isEmpty()) part = byteArrayOf(0)
                if (part[0].toInt() and 128 != 0) part = byteArrayOf(0) + part
                return byteArrayOf(2, part.size.toByte()) + part
            }
            val body = integer(0) + integer(32)
            return byteArrayOf(48, body.size.toByte()) + body
        }
    }
}
