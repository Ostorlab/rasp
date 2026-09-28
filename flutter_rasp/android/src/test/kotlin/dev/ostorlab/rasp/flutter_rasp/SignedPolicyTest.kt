package dev.ostorlab.rasp.flutter_rasp

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.json.JSONObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SignedPolicyTest {
    private val key = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()
    private val verifier = SignedPolicy(mapOf("k1" to key.public), "tenant", "app")
    private fun envelope(revision: Long = 1, expires: Long = 2000, app: String = "app"): String {
        val bytes = JSONObject(mapOf("tenantId" to "tenant", "appId" to app, "revision" to revision,
            "issuedAt" to 900, "expiresAt" to expires, "config" to mapOf("checkIntervalSeconds" to 30)))
            .toString().toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private); update(bytes); sign()
        }
        val b64 = Base64.getUrlEncoder().withoutPadding()
        return JSONObject(mapOf("kid" to "k1", "payload" to b64.encodeToString(bytes),
            "signature" to b64.encodeToString(TrustCrypto.derToRaw(signature)))).toString()
    }
    @Test fun validPolicyPreservesConfig() {
        assertEquals(30, verifier.verify(envelope(), 0, 1000).config.getInt("checkIntervalSeconds"))
    }
    @Test fun rejectsRollbackExpirationAndWrongApp() {
        assertFailsWith<IllegalArgumentException> { verifier.verify(envelope(), 1, 1000) }
        assertFailsWith<IllegalArgumentException> { verifier.verify(envelope(expires = 1000), 0, 1000) }
        assertFailsWith<IllegalArgumentException> { verifier.verify(envelope(app = "other"), 0, 1000) }
    }
    @Test fun rejectsChangedPayloadAndUnknownKey() {
        val modified = JSONObject(envelope()).put("payload", Base64.getUrlEncoder().encodeToString("{}".toByteArray()))
        assertFailsWith<IllegalArgumentException> { verifier.verify(modified.toString(), 0, 1000) }
        assertFailsWith<IllegalArgumentException> { verifier.verify(JSONObject(envelope()).put("kid", "unknown").toString(), 0, 1000) }
    }
}
