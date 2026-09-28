package dev.ostorlab.rasp.flutter_rasp

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** Framework-independent Android SDK. Call execute on a worker thread; callbacks may originate on scan threads. */
class RaspClient(private val context: Context, private val listener: RaspListener) : RaspListener {
    @Volatile var activity: Activity? = null
    @Volatile var engine: RaspEngine? = null
        private set
    private val deviceBinding by lazy { DeviceBinding() }
    private val integrity by lazy { PlayIntegrityClient(context) }
    private val secureStore by lazy { SecureStore(File(context.noBackupFilesDir, "rasp/store"), AndroidStoreKey()) }
    @Volatile private var sessionKey: SessionKey? = null
    @Volatile private var degraded = false
    @Volatile private var wipeRequested = false
    private var bootstrap = emptyMap<String, Any?>()
    private var active = emptyMap<String, Any?>()
    private var transport: PinnedTransport? = null
    private var policyVerifier: SignedPolicy? = null
    private var revision = 0L
    private var policyExpiry = Long.MAX_VALUE
    private val policyFile = AtomicFile(File(context.noBackupFilesDir, "rasp/policy.json"))
    private val scheduler = Executors.newSingleThreadScheduledExecutor()
    private val pending = mutableListOf<ScheduledFuture<*>>()
    @Volatile private var generation = 0L
    private val main = Handler(Looper.getMainLooper())

    @Synchronized fun execute(method: String, arguments: Map<String, Any?> = emptyMap()): Any? = handle(ClientCall(method, arguments))
    private class ClientCall(val method: String, val arguments: Map<String, Any?>) {
        @Suppress("UNCHECKED_CAST") fun <T> argument(key: String): T? = arguments[key] as? T
        fun required(key: String): String = argument<String>(key) ?: throw IllegalArgumentException("$key required")
    }

    private fun handle(call: ClientCall): Any? = when (call.method) {
        "start" -> {
            stopEngine()
            bootstrap = call.arguments
            active = bootstrap
            policyVerifier = makePolicyVerifier()
            loadPolicy()
            val config = RaspConfig.fromMap(active)
            transport = PinnedTransport(PinSet(pins(active)))
            val started = RaspEngine(context, config, this)
            engine = started
            val decision = started.scan()
            started.start()
            decision.toMap()
        }
        "check" -> requireEngine().scan().toMap()
        "guard" -> {
            val flow = call.argument<String>("flow") ?: throw IllegalArgumentException("flow is required")
            val (guard, decision) = requireEngine().guard(flow)
            guardMap(guard, decision)
        }
        "eventLog" -> requireEngine().events()
        "clearEventLog" -> {
            requireEngine().clearEvents()
            null
        }
        "isDeviceBound" -> deviceBinding.isBound()
        "installId" -> TrustCrypto.installId(context)
        "bindDevice" -> {
            val challenge = call.argument<String>("challenge") ?: throw IllegalArgumentException("challenge is required")
            deviceBinding.bind(Base64.decode(challenge, Base64.NO_WRAP), call.argument<Boolean>("requireUserAuth") ?: true) +
                mapOf("installId" to TrustCrypto.installId(context))
        }
        "unbindDevice" -> {
            deviceBinding.unbind()
            sessionKey = null
            null
        }
        // Seals a fresh report and authorizes a token: the user-auth install key signs a proof over the
        // challenge, the report MAC and a new ephemeral session key. One biometric prompt (showing the
        // action) per token; the session key then signs each request silently.
        "prepareToken" -> {
            ensureTrusted()
            val nonce = call.argument<String>("nonce") ?: throw IllegalArgumentException("nonce is required")
            val engine = requireEngine()
            engine.scan()
            ensureTrusted()
            val envelope = JSONObject(engine.sealedReport(nonce))
            val mac = envelope.optString("mac")
            if (mac.isEmpty()) {
                throw IllegalStateException("native core unavailable; cannot seal the report")
            }
            val session = SessionKey()
            val proofMessage = ProofMessages.tokenProof(nonce, mac, session.thumbprint)
            var signature = deviceBinding.initSignature()
            if (deviceBinding.requiresUserAuth()) {
                val host = activity ?: throw IllegalStateException("no activity to ask the user")
                signature = UserConfirmation.authorize(
                    host, signature,
                    call.argument<String>("confirmationTitle") ?: "Authorize",
                    call.argument<String>("confirmationText") ?: "Confirm this action",
                )
            }
            val proof = deviceBinding.finishRaw(signature, proofMessage)
            ensureTrusted()
            sessionKey = session
            mapOf(
                "installId" to TrustCrypto.installId(context),
                "proof" to proof,
                "sessionPublicKey" to session.publicKeyBase64,
                "sealedReport" to mapOf("report" to envelope.getString("report"), "mac" to mac),
            )
        }
        // Signs the DPoP proof for one request with the current session key (silent, no prompt).
        "signRequest" -> {
            ensureTrusted()
            val session = sessionKey ?: throw IllegalStateException("no session; call prepareToken first")
            val method = call.argument<String>("method") ?: "POST"
            val path = call.argument<String>("path") ?: throw IllegalArgumentException("path is required")
            val body = call.argument<ByteArray>("body") ?: ByteArray(0)
            val ts = System.currentTimeMillis()
            val counter = session.nextCounter()
            mapOf(
                "key" to session.publicKeyBase64,
                "sig" to session.signRaw(ProofMessages.request(method, path, body, ts, counter)),
                "ts" to ts,
                "counter" to counter,
            )
        }
        "stop" -> { stop(); null }
        "request" -> {
            ensurePolicyCurrent()
            transport?.request(call.required("url"), call.argument<String>("method") ?: "GET",
                call.argument<Map<String, String>>("headers").orEmpty(), call.argument<ByteArray>("body") ?: ByteArray(0))
                ?: throw IllegalStateException("call start first")
        }
        "playIntegrityToken" -> integrity.token(call.required("nonce"), call.argument<Number>("cloudProjectNumber")?.toLong()
            ?: throw IllegalArgumentException("cloudProjectNumber required"))
        "securePut" -> { ensureTrusted(); secureStore.put(call.required("key"), call.argument<ByteArray>("value")
            ?: throw IllegalArgumentException("value required")); null }
        "secureGet" -> { ensureTrusted(); secureStore.get(call.required("key")) }
        "secureDelete" -> { secureStore.delete(call.required("key")); null }
        "secureClear" -> { secureStore.clear(); sessionKey = null; null }
        "applyPolicy" -> { applyPolicy(call.required("envelope")); null }
        else -> throw IllegalArgumentException("unknown method ${call.method}")
    }

    private fun guardMap(guard: GuardResult, decision: Decision) = mapOf(
        "flow" to guard.flow,
        "allowed" to guard.allowed,
        "blockingThreats" to guard.blockingThreats.map { it.wireName },
        "warnings" to guard.warnings.map { it.wireName },
        "report" to decision.toMap(),
    )

    private fun requireEngine(): RaspEngine = engine ?: throw IllegalStateException("call Rasp.start() first")

    private fun ensureTrusted() {
        check(!degraded) { "session and storage disabled by security policy" }
        requireEngine()
        ensurePolicyCurrent()
    }
    private fun ensurePolicyCurrent() { check(System.currentTimeMillis() / 1000 < policyExpiry) { "signed policy expired" } }

    @Suppress("UNCHECKED_CAST") private fun pins(config: Map<String, Any?>): Map<String, List<String>> =
        config["pins"] as? Map<String, List<String>> ?: emptyMap()

    @Suppress("UNCHECKED_CAST") private fun makePolicyVerifier(): SignedPolicy? {
        val configured = bootstrap["policyKeys"] as? Map<String, String> ?: return null
        if (configured.isEmpty()) return null
        val keys = configured.mapValues { (_, value) -> KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.decode(value, Base64.DEFAULT))) }
        return SignedPolicy(keys, bootstrap["tenantId"] as? String ?: throw IllegalArgumentException("tenantId required"), context.packageName)
    }

    private fun loadPolicy() {
        if (!policyFile.baseFile.exists()) return
        val verifier = policyVerifier ?: throw IllegalStateException("persisted policy requires bootstrap keys")
        val envelope = policyFile.openRead().use { String(it.readBytes(), Charsets.UTF_8) }
        val verified = verifier.verify(envelope, revision, System.currentTimeMillis() / 1000, allowCurrent = true)
        active = bootstrap + jsonMap(verified.config)
        revision = verified.revision
        policyExpiry = verified.expiresAt
    }

    private fun applyPolicy(envelope: String) {
        requireEngine()
        val verified = (policyVerifier ?: throw IllegalStateException("no trusted policy keys"))
            .verify(envelope, revision, System.currentTimeMillis() / 1000)
        val updated = bootstrap + jsonMap(verified.config)
        val config = RaspConfig.fromMap(updated)
        val newTransport = PinnedTransport(PinSet(pins(updated)))
        policyFile.baseFile.parentFile?.mkdirs()
        val output = policyFile.startWrite()
        try { output.write(envelope.toByteArray(Charsets.UTF_8)); policyFile.finishWrite(output) }
        catch (error: Exception) { policyFile.failWrite(output); throw error }
        active = updated; revision = verified.revision; policyExpiry = verified.expiresAt
        stopEngine()
        transport = newTransport
        engine = RaspEngine(context, config, this)
        engine!!.start()
    }

    private fun jsonMap(json: JSONObject): Map<String, Any?> = json.keys().asSequence().associateWith { key ->
        fun value(item: Any?): Any? = when (item) {
            is JSONObject -> jsonMap(item)
            is org.json.JSONArray -> (0 until item.length()).map { value(item.get(it)) }
            JSONObject.NULL -> null
            else -> item
        }
        value(json.get(key))
    }

    override fun onThreatsDetected(event: Map<String, Any>) { listener.onThreatsDetected(event) }
    override fun onReactionsChanged(reactions: Set<Reaction>) {
        val current = engine
        if (current != null && !current.config.devMode) {
            if (Reaction.SILENT_DEGRADE in reactions) { degraded = true; sessionKey = null }
            if (Reaction.CLOSE_APP in reactions) {
                val scheduledGeneration = generation
                schedule(current.config.reactionDelayMillis) {
                    main.post { if (scheduledGeneration == generation) activity?.finishAndRemoveTask() }
                }
            }
        }
        listener.onReactionsChanged(reactions)
    }
    /** Called for every scan, including persistent threats after a policy update. */
    override fun onDecision(decision: Decision) {
        val config = engine?.config ?: return
        if (!config.devMode && decision.threats.keys.any { it in config.wipeOnThreats } && !wipeRequested) {
            wipeRequested = true
            degraded = true; sessionKey = null
            schedule(config.reactionDelayMillis) { secureStore.clear() }
        }
    }
    private fun schedule(delay: Long, action: () -> Unit) = synchronized(pending) {
        pending.removeAll { it.isDone }
        pending += scheduler.schedule({ synchronized(pending) { action() } }, delay, TimeUnit.MILLISECONDS)
    }
    private fun stopEngine() { engine?.stop(); engine = null }
    fun stop() {
        generation++
        stopEngine(); sessionKey = null
        synchronized(pending) { pending.forEach { it.cancel(false) }; pending.clear() }
        main.removeCallbacksAndMessages(null)
    }
    fun close() { stop(); scheduler.shutdownNow(); activity = null }
}
