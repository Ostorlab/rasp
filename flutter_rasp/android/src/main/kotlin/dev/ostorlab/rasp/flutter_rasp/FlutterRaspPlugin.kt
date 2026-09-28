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
    private val client by lazy { RaspClient(context, this) }

    private val engine: RaspEngine? get() = client.engine
    private var activity: Activity? = null
    private var screen: ScreenProtector? = null
    private var eventSink: EventChannel.EventSink? = null

    // The ephemeral session key bound into the current token; signs per-request DPoP proofs.

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
        client.close()
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

    private fun handle(call: MethodCall): Any? {
        @Suppress("UNCHECKED_CAST")
        return client.execute(call.method, call.arguments as? Map<String, Any?> ?: emptyMap())
    }

    override fun onThreatsDetected(event: Map<String, Any>) {
        mainHandler.post { eventSink?.success(event) }

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
        client.activity = binding.activity
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
        client.activity = null
    }

    companion object {
        private const val CLOSE_DELAY_MILLIS = 4000L
    }
}
