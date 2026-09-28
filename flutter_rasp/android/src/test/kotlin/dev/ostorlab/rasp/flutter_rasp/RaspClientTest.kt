package dev.ostorlab.rasp.flutter_rasp

import android.content.Context
import android.util.Base64
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import org.mockito.Mockito

class RaspClientTest {
    @Test fun successfulRebindingDiscardsPreviouslyAuthorizedSession() {
        val directory = Files.createTempDirectory("rasp-rebind").toFile()
        val context = Mockito.mock(Context::class.java)
        Mockito.`when`(context.noBackupFilesDir).thenReturn(directory)
        Mockito.`when`(context.filesDir).thenReturn(directory)
        val client = RaspClient(context, Mockito.mock(RaspListener::class.java))
        val sessionField = RaspClient::class.java.getDeclaredField("sessionKey").apply { isAccessible = true }
        val engineField = RaspClient::class.java.getDeclaredField("engine").apply { isAccessible = true }
        sessionField.set(client, SessionKey())
        engineField.set(client, Mockito.mock(RaspEngine::class.java))
        val challenge = ByteArray(32) { 1 }
        try {
            Mockito.mockStatic(Base64::class.java).use { codec ->
                codec.`when`<ByteArray> { Base64.decode("challenge", Base64.NO_WRAP) }.thenReturn(challenge)
                Mockito.mockConstruction(DeviceBinding::class.java) { binding, _ ->
                    Mockito.`when`(binding.bind(challenge, true)).thenReturn(mapOf("keyAlias" to "replacement"))
                }.use { bindings ->
                    @Suppress("UNCHECKED_CAST")
                    val result = client.execute("bindDevice", mapOf("challenge" to "challenge")) as Map<String, Any>
                    assertEquals("replacement", result["keyAlias"])
                    assertNull(sessionField.get(client))
                    val error = assertFailsWith<IllegalStateException> {
                        client.execute("signRequest", mapOf("path" to "/pay"))
                    }
                    assertEquals("no session; call prepareToken first", error.message)
                    // DeviceBinding deletes the old install key before generating its replacement.
                    sessionField.set(client, SessionKey())
                    Mockito.`when`(bindings.constructed().single().bind(challenge, true))
                        .thenThrow(IllegalStateException("replacement key unavailable"))
                    assertFailsWith<IllegalStateException> { client.execute("bindDevice", mapOf("challenge" to "challenge")) }
                    assertNull(sessionField.get(client))
                    val failedReplacement = assertFailsWith<IllegalStateException> {
                        client.execute("signRequest", mapOf("path" to "/pay"))
                    }
                    assertEquals("no session; call prepareToken first", failedReplacement.message)
                }
            }
        } finally { client.close(); directory.deleteRecursively() }
    }
}
