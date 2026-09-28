package dev.ostorlab.rasp.flutter_rasp

import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

interface StoreKey {
    fun key(): SecretKey
    fun delete()
}

/** Each value has a random data key wrapped by a non-exportable per-install key. No plaintext is persisted. */
class SecureStore(private val directory: File, private val wrappingKey: StoreKey) {
    @Synchronized fun put(name: String, value: ByteArray) {
        require(value.size <= MAX_VALUE) { "value too large" }
        val file = entry(name)
        directory.mkdirs()
        val dataKey = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            val aad = name.toByteArray(Charsets.UTF_8)
            val wrapped = encrypt(wrappingKey.key(), dataKey, aad)
            val sealed = encrypt(SecretKeySpec(dataKey, "AES"), value, aad)
            val temporary = File.createTempFile(".store-", ".tmp", directory)
            try {
                temporary.outputStream().use { output ->
                    output.write(byteArrayOf(1)); output.write(wrapped); output.write(sealed)
                    output.fd.sync()
                }
                check(temporary.renameTo(file)) { "cannot commit secure entry" }
            } finally { temporary.delete() }
        } finally { dataKey.fill(0) }
    }

    @Synchronized fun get(name: String): ByteArray? {
        val file = entry(name)
        if (!file.exists()) return null
        require(file.length() in 89L..(MAX_VALUE + 89L)) { "invalid secure entry length" }
        val bytes = file.readBytes()
        require(bytes[0] == 1.toByte()) { "unsupported secure entry" }
        val aad = name.toByteArray(Charsets.UTF_8)
        val dataKey = decrypt(wrappingKey.key(), bytes.copyOfRange(1, 61), aad)
        return try { decrypt(SecretKeySpec(dataKey, "AES"), bytes.copyOfRange(61, bytes.size), aad) }
        finally { dataKey.fill(0) }
    }

    @Synchronized fun delete(name: String) {
        val file = entry(name)
        check(!file.exists() || file.delete()) { "cannot delete secure entry" }
    }

    @Synchronized fun clear() {
        // Delete the non-exportable wrapping key first; old files remain unreadable even if deletion fails.
        invalidateKey()
        deleteCiphertext()
    }

    @Synchronized fun invalidateKey() = wrappingKey.delete()

    @Synchronized fun deleteCiphertext() {
        check(!directory.exists() || directory.deleteRecursively()) { "cannot delete secure store" }
    }

    private fun entry(name: String): File {
        require(name.isNotEmpty() && name.length <= 256) { "invalid entry name" }
        val hash = MessageDigest.getInstance("SHA-256").digest(name.toByteArray(Charsets.UTF_8))
        return File(directory, hash.joinToString("") { "%02x".format(it) })
    }

    private fun encrypt(key: SecretKey, plain: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)
        require(cipher.iv.size == 12) { "unexpected GCM nonce" }
        return cipher.iv + cipher.doFinal(plain)
    }

    private fun decrypt(key: SecretKey, sealed: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, 12)))
        cipher.updateAAD(aad)
        return cipher.doFinal(sealed.copyOfRange(12, sealed.size))
    }

    companion object { private const val MAX_VALUE = 4 * 1024 * 1024 }
}
