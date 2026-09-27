package dev.ostorlab.rasp.flutter_rasp

import android.content.Context
import android.util.Base64
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.UUID

/**
 * Client-side crypto for the trust-service flow: base64url, ECDSA-P-256 raw (R||S) signatures, RFC 7638
 * JWK thumbprints, the ephemeral session key, per-request proofs, and the persisted install id.
 *
 * The token model uses two keys. The hardware-backed install key (see [DeviceBinding]) is user-auth bound
 * and authorizes token issuance with a biometric prompt. The [SessionKey] here is ephemeral and needs no
 * user auth: the install key binds it into the token, and it then signs each request's DPoP proof silently
 * for the token's short lifetime, so there is no prompt per request.
 */
object TrustCrypto {

    fun b64Url(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP or Base64.URL_SAFE or Base64.NO_PADDING)

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    /** Converts a DER ECDSA signature (SEQUENCE of two INTEGERs) to raw R||S, 64 bytes for P-256. */
    fun derToRaw(der: ByteArray): ByteArray {
        var i = 0
        require(der[i++].toInt() and 0xff == 0x30) { "not a DER sequence" }
        var seqLen = der[i++].toInt() and 0xff
        if (seqLen and 0x80 != 0) {
            var n = seqLen and 0x7f
            seqLen = 0
            while (n-- > 0) seqLen = (seqLen shl 8) or (der[i++].toInt() and 0xff)
        }
        require(der[i++].toInt() and 0xff == 0x02) { "expected r integer" }
        val rLen = der[i++].toInt() and 0xff
        val r = der.copyOfRange(i, i + rLen); i += rLen
        require(der[i++].toInt() and 0xff == 0x02) { "expected s integer" }
        val sLen = der[i++].toInt() and 0xff
        val s = der.copyOfRange(i, i + sLen); i += sLen
        return leftPad32(r) + leftPad32(s)
    }

    /** RFC 7638 thumbprint of a P-256 public key: base64url(SHA-256 of the canonical JWK). */
    fun ecThumbprint(key: ECPublicKey): String {
        val x = b64Url(coordinate(key.w.affineX))
        val y = b64Url(coordinate(key.w.affineY))
        val json = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$x\",\"y\":\"$y\"}"
        return b64Url(sha256(json.toByteArray(Charsets.UTF_8)))
    }

    fun spkiBase64(key: java.security.PublicKey): String = Base64.encodeToString(key.encoded, Base64.NO_WRAP)

    /** A random, persisted per-install id. Stable across launches; created on first use. */
    fun installId(context: Context): String {
        val file = File(context.filesDir, "flutter_rasp/install_id")
        if (file.exists()) {
            val existing = file.readText().trim()
            if (existing.isNotEmpty()) return existing
        }
        val id = UUID.randomUUID().toString()
        file.parentFile?.mkdirs()
        file.writeText(id)
        return id
    }

    private fun leftPad32(value: ByteArray): ByteArray {
        var v = value
        if (v.size > 32) v = v.copyOfRange(v.size - 32, v.size)  // drop a leading sign byte
        if (v.size == 32) return v
        val out = ByteArray(32)
        System.arraycopy(v, 0, out, 32 - v.size, v.size)
        return out
    }

    private fun coordinate(value: BigInteger): ByteArray = leftPad32(value.toByteArray())
}

/**
 * An ephemeral EC P-256 key that binds requests to a token. Generated per token issuance, kept in memory,
 * never user-auth gated. The install key authorizes it at issuance; it then signs DPoP request proofs.
 */
class SessionKey {
    private val pair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private var counter: Long = 0

    val publicKeyBase64: String get() = TrustCrypto.spkiBase64(pair.public)
    val thumbprint: String get() = TrustCrypto.ecThumbprint(pair.public as ECPublicKey)

    fun nextCounter(): Long = ++counter

    /** ES256 over [message] as raw R||S, base64url. Silent (no user auth). */
    fun signRaw(message: ByteArray): String {
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(pair.private)
            update(message)
        }
        return TrustCrypto.b64Url(TrustCrypto.derToRaw(signature.sign()))
    }

    companion object {
        /** Loads an SPKI-DER (base64, standard) public key, e.g. to check a thumbprint in tests. */
        fun publicFromSpki(b64: String): java.security.PublicKey =
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.decode(b64, Base64.NO_WRAP)))
    }
}

/** Canonical strings signed by the device, matching the server (`resource.canonical_request`, `trust`). */
object ProofMessages {
    fun tokenProof(nonce: String, reportMac: String, sessionThumbprint: String): ByteArray =
        "rasp-token-1\n$nonce\n$reportMac\n$sessionThumbprint".toByteArray(Charsets.UTF_8)

    fun request(method: String, path: String, body: ByteArray, tsMillis: Long, counter: Long): ByteArray {
        val bodyHash = TrustCrypto.b64Url(TrustCrypto.sha256(body))
        return "rasp-req-1\n${method.uppercase()}\n$path\n$bodyHash\n$tsMillis\n$counter".toByteArray(Charsets.UTF_8)
    }
}
