package dev.ostorlab.rasp.flutter_rasp

import java.net.InetAddress
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import java.util.concurrent.Executors
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails

class PinnedTransportTest {
    @Test fun trustedPinnedServerReceivesBodyButWrongPinAndHostnameReceiveNothing() {
        val store = KeyStore.getInstance("PKCS12").apply {
            load(PinnedTransportTest::class.java.getResourceAsStream("/localhost.p12"), "test-only".toCharArray())
        }
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, "test-only".toCharArray()) }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            .trustManagers.filterIsInstance<X509TrustManager>().single()
        val tls = SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) }
        val server = tls.serverSocketFactory.createServerSocket(0, 10, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        val received = AtomicInteger()
        val executor = Executors.newSingleThreadExecutor()
        executor.submit {
            while (!server.isClosed) {
                try {
                    (server.accept() as SSLSocket).use { socket ->
                        socket.soTimeout = 3000
                        socket.startHandshake()
                        val input = socket.inputStream
                        val header = StringBuilder()
                        while (!header.endsWith("\r\n\r\n")) {
                            val byte = input.read()
                            if (byte < 0) break
                            header.append(byte.toChar())
                        }
                        if (header.isNotEmpty()) {
                            received.incrementAndGet()
                            val length = Regex("(?i)Content-Length: (\\d+)").find(header)?.groupValues?.get(1)?.toInt() ?: 0
                            val body = ByteArray(length)
                            java.io.DataInputStream(input).readFully(body)
                            socket.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: $length\r\nConnection: close\r\n\r\n".toByteArray())
                            socket.outputStream.write(body)
                            socket.outputStream.flush()
                        }
                    }
                } catch (_: java.io.IOException) { /* A rejected handshake must not yield an HTTP request. */ }
            }
        }
        try {
            val cert = store.getCertificate(store.aliases().nextElement()) as X509Certificate
            val pin = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded))
            val port = server.localPort
            val client = PinnedTransport(PinSet(mapOf("localhost" to listOf(pin))), trust)
            val response = client.request("https://localhost:$port/", "POST", emptyMap(), byteArrayOf(1, 2, 3))
            assertEquals(200, response["status"])
            assertContentEquals(byteArrayOf(1, 2, 3), response["body"] as ByteArray)
            val wrongPin = Base64.getEncoder().encodeToString(ByteArray(32))
            assertFails { PinnedTransport(PinSet(mapOf("localhost" to listOf(wrongPin))), trust)
                .request("https://localhost:$port/", "POST", emptyMap(), byteArrayOf(4)) }
            assertFails { PinnedTransport(PinSet(mapOf("127.0.0.1" to listOf(pin))), trust)
                .request("https://127.0.0.1:$port/", "POST", emptyMap(), byteArrayOf(5)) }
            assertEquals(1, received.get())
        } finally { server.close(); executor.shutdownNow() }
    }
}
