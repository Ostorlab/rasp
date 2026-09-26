package dev.ostorlab.rasp.flutter_rasp

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import android.security.keystore.KeyInfo
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Binds the app install to a hardware-backed signing key (Android Keystore, StrongBox when available).
 *
 * Binding: the bank's server sends a random challenge; the key is generated with that challenge in its Key
 * Attestation certificate, and the server verifies the chain (see verifier/). Afterwards every transaction is
 * signed with that key, together with the RASP risk report, so the server can check both.
 */
class DeviceBinding(private val alias: String = DEFAULT_ALIAS) {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun isBound(): Boolean = keyStore.containsAlias(alias)

    /**
     * With [requireUserAuth], every signature needs the user's biometric or device credential, enforced by the secure
     * hardware and visible to the server in the attestation. Malware driving the screen cannot sign silently.
     * Needs a secure lock screen.
     */
    fun bind(challenge: ByteArray, requireUserAuth: Boolean): Map<String, Any> {
        require(challenge.size in 16..128) { "challenge must be 16 to 128 bytes" }
        unbind()
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            tryGenerate(challenge, strongBox = true, requireUserAuth)
        if (!strongBox) {
            generate(challenge, strongBox = false, requireUserAuth)
        }
        val chain = keyStore.getCertificateChain(alias).orEmpty()
        return mapOf(
            "keyAlias" to alias,
            "strongBox" to strongBox,
            "userAuthRequired" to requireUserAuth,
            "publicKey" to b64(keyStore.getCertificate(alias).publicKey.encoded),
            "certificateChain" to chain.map { b64(it.encoded) },
        )
    }

    fun unbind() {
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    fun requiresUserAuth(): Boolean {
        val key = privateKey()
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        return info.isUserAuthenticationRequired
    }

    /** A signature object ready to sign; for user-auth keys it must go through BiometricPrompt before [finish]. */
    fun initSignature(): Signature = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey()) }

    fun finish(signature: Signature, data: ByteArray): String {
        signature.update(data)
        return b64(signature.sign())
    }

    private fun privateKey(): PrivateKey =
        keyStore.getKey(alias, null) as? PrivateKey ?: throw IllegalStateException("device is not bound")

    private fun tryGenerate(challenge: ByteArray, strongBox: Boolean, requireUserAuth: Boolean): Boolean = try {
        generate(challenge, strongBox, requireUserAuth)
        true
    } catch (e: StrongBoxUnavailableException) {
        false
    }

    private fun generate(challenge: ByteArray, strongBox: Boolean, requireUserAuth: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply { if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true) }
            .apply { if (requireUserAuth) requireUserAuthPerUse(this) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    @Suppress("DEPRECATION")
    private fun requireUserAuthPerUse(builder: KeyGenParameterSpec.Builder) {
        builder.setUserAuthenticationRequired(true).setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Timeout 0 = authentication for every single use.
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(-1) // per use, biometric only before Android 11
        }
    }

    companion object {
        const val DEFAULT_ALIAS = "flutter_rasp_device_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"

        private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
    }
}

/**
 * Canonical text that is signed for a transaction: a fixed header, the server's nonce, the RASP verdict, then the
 * transaction fields sorted by name. Line-based and escaped, so the server can parse it without ambiguity.
 */
object SignedPayload {
    const val VERSION = "rasp-tx-1"

    fun build(
        nonce: String,
        timestampMillis: Long,
        packageName: String,
        decision: Decision,
        fields: Map<String, String>,
    ): String {
        require(fields.keys.all { KEY.matches(it) }) { "field names must match ${KEY.pattern}" }
        val lines = mutableListOf(
            "v=$VERSION",
            "nonce=${escape(nonce)}",
            "ts=$timestampMillis",
            "app=${escape(packageName)}",
            "risk=${decision.riskLevel.wireName}",
            "threats=${decision.threats.keys.map { it.wireName }.sorted().joinToString(",")}",
        )
        fields.toSortedMap().forEach { (key, value) -> lines += "f.$key=${escape(value)}" }
        return lines.joinToString("\n")
    }

    /** Percent-escapes the characters that would break the line format. */
    fun escape(value: String): String = value.replace("%", "%25").replace("\n", "%0A").replace("\r", "%0D")

    private val KEY = Regex("[A-Za-z0-9_.-]{1,64}")
}
