package dev.ostorlab.rasp.flutter_rasp

import java.nio.file.Files
import javax.crypto.KeyGenerator
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFails
import kotlin.test.assertNull

class SecureStoreTest {
    @Test fun roundtripRejectsTamperAndWipeInvalidatesRestoredCiphertext() {
        val directory = Files.createTempDirectory("rasp-store").toFile()
        var key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val store = SecureStore(directory, object : StoreKey {
            override fun key() = key
            override fun delete() { key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey() }
        })
        try {
            store.put("token", "secret".toByteArray())
            assertContentEquals("secret".toByteArray(), store.get("token"))
            val file = directory.listFiles()!!.single()
            val original = file.readBytes()
            file.writeBytes(original.clone().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() })
            assertFails { store.get("token") }
            file.writeBytes(original)
            store.clear()
            assertNull(store.get("token"))
            directory.mkdirs()
            file.writeBytes(original)
            assertFails { store.get("token") }
        } finally { directory.deleteRecursively() }
    }
    @Test fun deletingWrappingKeyImmediatelyMakesPendingCleanupIrrelevant() {
        val directory = Files.createTempDirectory("rasp-store").toFile()
        var key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val store = SecureStore(directory, object : StoreKey {
            override fun key() = key
            override fun delete() { key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey() }
        })
        try {
            store.put("secret", byteArrayOf(1, 2, 3))
            store.invalidateKey()
            // Simulate stop or process death canceling delayed ciphertext cleanup.
            assertFails { store.get("secret") }
        } finally { directory.deleteRecursively() }
    }
    @Test fun entryNamesAreAuthenticated() {
        val directory = Files.createTempDirectory("rasp-store").toFile()
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val store = SecureStore(directory, object : StoreKey { override fun key() = key; override fun delete() {} })
        try {
            store.put("one", byteArrayOf(1)); val first = directory.listFiles()!!.single().readBytes()
            store.put("two", byteArrayOf(2))
            directory.listFiles()!!.forEach { it.writeBytes(first) }
            assertFails { store.get("two") }
        } finally { directory.deleteRecursively() }
    }
}
