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
        "bindDevice" -> {
            val challenge = call.argument<String>("challenge") ?: throw IllegalArgumentException("challenge is required")
            deviceBinding.bind(Base64.decode(challenge, Base64.NO_WRAP))
        }
        "unbindDevice" -> {
            deviceBinding.unbind()
            null
        }
        "signTransaction" -> {
            val flow = call.argument<String>("flow") ?: throw IllegalArgumentException("flow is required")
            val nonce = call.argument<String>("nonce") ?: throw IllegalArgumentException("nonce is required")
            val fields = call.argument<Map<String, String>>("fields").orEmpty()
            // Always sign, even when the policy would block: the server gets the verdict and decides.
            val (guard, decision) = requireEngine().guard(flow)
            val payload = SignedPayload.build(nonce, decision.timestampMillis, context.packageName, decision, fields)
            mapOf(
                "signedData" to payload,
                "signature" to deviceBinding.sign(payload.toByteArray(Charsets.UTF_8)),
                "guard" to guardMap(guard, decision),
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
