package dev.ostorlab.rasp.flutter_rasp

import java.net.URL
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Locale
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class PinSet(pins: Map<String, List<String>>) {
    private val pins = pins.mapKeys { it.key.lowercase(Locale.ROOT) }.mapValues { (_, values) ->
        require(values.isNotEmpty()) { "pin set cannot be empty" }
        values.map { Base64.getDecoder().decode(it.removePrefix("sha256/")).also { hash -> require(hash.size == 32) } }
    }
    fun requireHost(url: URL): String {
        require(url.protocol == "https" && url.userInfo == null && url.ref == null) { "pinned HTTPS URL required" }
        val host = url.host.lowercase(Locale.ROOT)
        require(host in pins) { "no pins configured for $host" }
        return host
    }
    fun matches(host: String, keys: List<PublicKey>): Boolean = keys.any { key ->
        val hash = MessageDigest.getInstance("SHA-256").digest(key.encoded)
        pins[host.lowercase(Locale.ROOT)].orEmpty().any { MessageDigest.isEqual(it, hash) }
    }
}

/** Pin verification runs inside TLS trust evaluation, before any HTTP headers or body can be sent. */
class PinnedTransport(private val pins: PinSet, private val platformTrust: X509TrustManager = systemTrust()) {
    companion object {
        private fun systemTrust(): X509TrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as KeyStore?)
        }.trustManagers.filterIsInstance<X509TrustManager>().single()
    }
    fun request(urlString: String, method: String, headers: Map<String, String>, body: ByteArray): Map<String, Any> {
        val url = URL(urlString)
        val host = pins.requireHost(url)
        require(method in setOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")) { "unsupported method" }
        require(body.size <= 4 * 1024 * 1024) { "request too large" }
        require(headers.keys.none { it.lowercase(Locale.ROOT) in setOf("host", "content-length", "transfer-encoding", "connection") }) { "reserved header" }
        val system = platformTrust
        val pinned = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = system.acceptedIssuers
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = system.checkClientTrusted(chain, authType)
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                system.checkServerTrusted(chain, authType)
                if (!pins.matches(host, listOf(chain.first().publicKey))) throw java.security.cert.CertificateException("SPKI pin mismatch")
            }
        }
        val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(pinned), null) }
        val connection = url.openConnection() as HttpsURLConnection
        try {
            connection.sslSocketFactory = tls.socketFactory
            // Retain HttpsURLConnection's default hostname verifier.
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 15000
            connection.readTimeout = 15000
            connection.requestMethod = method
            headers.forEach { (name, value) -> connection.setRequestProperty(name, value) }
            if (body.isNotEmpty()) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
            }
            connection.connect()
            if (body.isNotEmpty()) connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val bytes = stream?.use {
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val read = it.read(buffer)
                    if (read < 0) break
                    require(out.size() + read <= 8 * 1024 * 1024) { "response too large" }
                    out.write(buffer, 0, read)
                }
                out.toByteArray()
            } ?: ByteArray(0)
            return mapOf("status" to status, "body" to bytes,
                "headers" to connection.headerFields.filterKeys { it != null }.mapValues { it.value.joinToString(",") })
        } finally { connection.disconnect() }
    }
}
