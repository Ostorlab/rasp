package dev.ostorlab.rasp.flutter_rasp

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Base64
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.util.concurrent.Executors

class FlutterRaspPlugin : FlutterPlugin, MethodChannel.MethodCallHandler, EventChannel.StreamHandler,
    ActivityAware, RaspListener {

    private lateinit var context: Context
    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private val mainHandler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "rasp-calls").apply { isDaemon = true } }
    private val deviceBinding by lazy { DeviceBinding() }

    private var engine: RaspEngine? = null
    private var activity: Activity? = null
    private var screen: ScreenProtector? = null
    private var eventSink: EventChannel.EventSink? = null

    // The ephemeral session key bound into the current token; signs per-request DPoP proofs.
    private var sessionKey: SessionKey? = null

    // Kept here so they survive activity re-creation and apply to the next ScreenProtector.
    private var appSecure = false
    private var appSensitive = false
    private var policySecure = false

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        methodChannel = MethodChannel(binding.binaryMessenger, "flutter_rasp")
        methodChannel.setMethodCallHandler(this)
        eventChannel = EventChannel(binding.binaryMessenger, "flutter_rasp/events")
        eventChannel.setStreamHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        engine?.stop()
        engine = null
        worker.shutdown()
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        // Screen flags must be changed on the UI thread; everything else does I/O and runs on the worker.
        when (call.method) {
            "setSecureScreen" -> {
                appSecure = call.argument<Boolean>("enabled") ?: false
                screen?.setSecure(appSecure)
                result.success(null)
                return
            }
            "setSensitiveScreen" -> {
                appSensitive = call.argument<Boolean>("enabled") ?: false
                screen?.setSensitive(appSensitive)
                result.success(null)
                return
            }
        }
        worker.execute {
            try {
                val value = handle(call)
                mainHandler.post { result.success(value) }
            } catch (e: UserConfirmationException) {
                mainHandler.post { result.error(e.code, e.message, null) }
            } catch (e: IllegalStateException) {
                mainHandler.post { result.error("not_started", e.message, null) }
            } catch (e: Exception) {
                mainHandler.post { result.error("rasp_error", e.message, null) }
            }
        }
    }

    private fun handle(call: MethodCall): Any? = when (call.method) {
        "start" -> {
            engine?.stop()
            @Suppress("UNCHECKED_CAST")
            val config = RaspConfig.fromMap(call.arguments as? Map<String, Any?> ?: emptyMap())
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
            val nonce = call.argument<String>("nonce") ?: throw IllegalArgumentException("nonce is required")
            val engine = requireEngine()
            val envelope = JSONObject(engine.sealedReport(nonce))
            val mac = envelope.optString("mac")
            if (mac.isEmpty()) {
                throw IllegalStateException("native core unavailable; cannot seal the report")
            }
            val session = SessionKey()
            sessionKey = session
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
            mapOf(
                "installId" to TrustCrypto.installId(context),
                "proof" to deviceBinding.finishRaw(signature, proofMessage),
                "sessionPublicKey" to session.publicKeyBase64,
                "sealedReport" to mapOf("report" to envelope.getString("report"), "mac" to mac),
            )
        }
        // Signs the DPoP proof for one request with the current session key (silent, no prompt).
        "signRequest" -> {
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

    override fun onThreatsDetected(event: Map<String, Any>) {
        mainHandler.post { eventSink?.success(event) }
        @Suppress("UNCHECKED_CAST")
        val reactions = (event["reactions"] as List<String>).mapNotNull(Reaction::fromWire)
        if (Reaction.CLOSE_APP in reactions) {
            // Give the app time to show the warning it received in the event, then close.
            mainHandler.postDelayed({ activity?.finishAndRemoveTask() }, CLOSE_DELAY_MILLIS)
        }
    }

    override fun onReactionsChanged(reactions: Set<Reaction>) {
        policySecure = Reaction.SECURE_SCREEN in reactions
        mainHandler.post { screen?.setPolicySecure(policySecure) }
    }

    private fun onScreenSignal(signal: Signal) {
        val current = engine ?: return
        current.transientSignals.record(signal)
        current.requestScan()
    }

    private fun onRecordingChanged(visible: Boolean) {
        val current = engine ?: return
        current.screenState.recordingVisible = visible
        current.requestScan()
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        screen = ScreenProtector(binding.activity, ::onScreenSignal, ::onRecordingChanged).apply {
            attach()
            setSecure(appSecure)
            setSensitive(appSensitive)
            setPolicySecure(policySecure)
        }
    }

    override fun onDetachedFromActivityForConfigChanges() = onDetachedFromActivity()

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = onAttachedToActivity(binding)

    override fun onDetachedFromActivity() {
        screen?.detach()
        screen = null
        activity = null
    }

    companion object {
        private const val CLOSE_DELAY_MILLIS = 4000L
    }
}
