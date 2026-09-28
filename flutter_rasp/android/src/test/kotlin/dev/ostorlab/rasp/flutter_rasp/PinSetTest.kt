package dev.ostorlab.rasp.flutter_rasp

import java.net.URL
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PinSetTest {
    @Test fun requiresPinnedHttpsExactHostAndRejectsCredentials() {
        val pin = Base64.getEncoder().encodeToString(ByteArray(32))
        val pins = PinSet(mapOf("api.example.com" to listOf(pin)))
        pins.requireHost(URL("https://api.example.com/v1/token"))
        assertFailsWith<IllegalArgumentException> { pins.requireHost(URL("http://api.example.com/")) }
        assertFailsWith<IllegalArgumentException> { pins.requireHost(URL("https://evil.example.com/")) }
        assertFailsWith<IllegalArgumentException> { pins.requireHost(URL("https://user@api.example.com/")) }
    }
    @Test fun digestMatchesEncodedPublicKeyOnly() {
        val key = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair().public
        val pin = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key.encoded))
        assertTrue(PinSet(mapOf("api.example.com" to listOf(pin))).matches("api.example.com", listOf(key)))
    }
}
