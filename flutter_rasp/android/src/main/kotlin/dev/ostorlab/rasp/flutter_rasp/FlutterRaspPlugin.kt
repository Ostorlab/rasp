package dev.ostorlab.rasp.flutter_rasp

import android.app.Activity
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
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

    private var engine: RaspEngine? = null
    private var activity: Activity? = null
    private var eventSink: EventChannel.EventSink? = null
    private var appSecureScreen = false
    private var policySecureScreen = false

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
        // Detectors do file and socket I/O, so every call runs off the platform thread.
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
            mapOf(
                "flow" to guard.flow,
                "allowed" to guard.allowed,
                "blockingThreats" to guard.blockingThreats.map { it.wireName },
                "report" to decision.toMap(),
            )
        }
        "setSecureScreen" -> {
            appSecureScreen = call.argument<Boolean>("enabled") ?: false
            mainHandler.post { applySecureFlag() }
            null
        }
        "eventLog" -> requireEngine().events()
        "clearEventLog" -> {
            requireEngine().clearEvents()
            null
        }
        else -> throw IllegalArgumentException("unknown method ${call.method}")
    }

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
        policySecureScreen = Reaction.SECURE_SCREEN in reactions
        mainHandler.post { applySecureFlag() }
    }

    private fun applySecureFlag() {
        val window = activity?.window ?: return
        if (appSecureScreen || policySecureScreen) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        applySecureFlag()
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        onAttachedToActivity(binding)
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    companion object {
        private const val CLOSE_DELAY_MILLIS = 4000L
    }
}
