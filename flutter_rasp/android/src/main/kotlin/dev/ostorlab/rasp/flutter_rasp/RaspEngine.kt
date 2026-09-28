package dev.ostorlab.rasp.flutter_rasp

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** Receives what the engine decides; implemented by the plugin, which owns the activity and the event channel. */
interface RaspListener {
    fun onThreatsDetected(event: Map<String, Any>)
    fun onReactionsChanged(reactions: Set<Reaction>)
    fun onDecision(decision: Decision) {}
}

/**
 * Headless, offline engine: runs detectors on a schedule, evaluates the local policy and keeps an on-device event log.
 * Nothing leaves the device.
 */
class RaspEngine(
    private val context: Context,
    val config: RaspConfig,
    private val listener: RaspListener,
) {
    private val policy = PolicyEngine(config)
    private val platformDetectors = PlatformDetectors(context, config)
    val transientSignals = TransientSignals()
    val screenState = ScreenState()
    private val fraudDetectors = FraudDetectors(context, config, transientSignals, screenState)
    private val executor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "rasp-engine").apply { isDaemon = true }
    }
    private val eventLog = EventLog(File(context.filesDir, "flutter_rasp/events.jsonl"))
    private var task: ScheduledFuture<*>? = null
    private var lastDecision: Decision? = null

    fun start() {
        task?.cancel(false)
        task = executor.scheduleWithFixedDelay({ scan() }, 0, config.checkIntervalSeconds, TimeUnit.SECONDS)
    }

    fun stop() {
        task?.cancel(false)
        executor.shutdown()
    }

    /** Runs all detectors now. Emits an event for threats that were not active in the previous scan. */
    @Synchronized
    fun scan(): Decision {
        val signals = NativeDetectors.scan() + platformDetectors.scan() + fraudDetectors.scan()
        val decision = policy.evaluate(signals, System.currentTimeMillis())
        listener.onDecision(decision)
        val previous = lastDecision
        lastDecision = decision

        val newThreats = decision.threats.keys - previous?.threats?.keys.orEmpty()
        if (newThreats.isNotEmpty()) {
            val event = mapOf(
                "timestamp" to decision.timestampMillis,
                "riskLevel" to decision.riskLevel.wireName,
                "newThreats" to newThreats.map { it.wireName },
                "reactions" to newThreats.flatMap { decision.threats[it].orEmpty() }.distinct().map { it.wireName },
                "signals" to decision.signals.filter { it.threat in newThreats }.map { it.toMap() },
            )
            eventLog.append(event)
            listener.onThreatsDetected(event)
        }
        if (previous == null || previous.reactions != decision.reactions) {
            listener.onReactionsChanged(decision.reactions)
        }
        return decision
    }

    /** Schedules a scan soon, e.g. after a window callback reported a screenshot. */
    fun requestScan() {
        if (!executor.isShutdown) {
            executor.execute { scan() }
        }
    }

    /** Runs a fresh scan before a sensitive flow, so a tool attached after the last scheduled scan is still seen. */
    fun guard(flow: String): Pair<GuardResult, Decision> {
        val decision = scan()
        return policy.guard(flow, decision) to decision
    }

    /**
     * Seals a fresh report for the trust service, bound to the server [nonce]. The native core reruns its
     * detectors and MACs them together with the managed-layer signals (platform and fraud) from this scan.
     */
    fun sealedReport(nonce: String): String {
        val managed = platformDetectors.scan() + fraudDetectors.scan()
        return NativeDetectors.seal(managed, nonce, System.currentTimeMillis())
    }

    fun events(): List<Map<String, Any?>> = eventLog.readAll()

    fun clearEvents() = eventLog.clear()
}

/** Append-only JSON-lines log in the app's private storage, capped at [maxEntries]. */
class EventLog(private val file: File, private val maxEntries: Int = 500) {

    @Synchronized
    fun append(event: Map<String, Any>) {
        file.parentFile?.mkdirs()
        val lines = if (file.exists()) file.readLines() else emptyList()
        val kept = (lines + JSONObject(event).toString()).takeLast(maxEntries)
        file.writeText(kept.joinToString("\n", postfix = "\n"))
    }

    @Synchronized
    fun readAll(): List<Map<String, Any?>> {
        if (!file.exists()) {
            return emptyList()
        }
        return file.readLines().filter { it.isNotBlank() }.map { line -> toMap(JSONObject(line)) }
    }

    @Synchronized
    fun clear() {
        file.delete()
    }

    private fun toMap(json: JSONObject): Map<String, Any?> = json.keys().asSequence().associateWith { key ->
        toValue(json.get(key))
    }

    private fun toValue(value: Any?): Any? = when (value) {
        is JSONObject -> toMap(value)
        is org.json.JSONArray -> (0 until value.length()).map { toValue(value.get(it)) }
        JSONObject.NULL -> null
        else -> value
    }
}
