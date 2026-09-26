package dev.ostorlab.rasp.flutter_rasp

data class Decision(
    val signals: List<Signal>,
    val threats: Map<ThreatType, Set<Reaction>>,
    val riskLevel: RiskLevel,
    val timestampMillis: Long,
) {
    val reactions: Set<Reaction> get() = threats.values.flatten().toSet()

    fun toMap(): Map<String, Any> = mapOf(
        "riskLevel" to riskLevel.wireName,
        "threats" to threats.map { (threat, reactions) ->
            mapOf("type" to threat.wireName, "reactions" to reactions.map { it.wireName })
        },
        "signals" to signals.map { it.toMap() },
        "timestamp" to timestampMillis,
    )
}

/**
 * [warnings] are active threats whose policy asks to warn the user, e.g. a phone call during a transfer.
 * The flow is still allowed; the app should confirm with the user first.
 */
data class GuardResult(
    val flow: String,
    val allowed: Boolean,
    val blockingThreats: List<ThreatType>,
    val warnings: List<ThreatType> = emptyList(),
)

/** Pure policy evaluation: signals in, decision out. No Android dependencies, so it is unit-tested on the JVM. */
class PolicyEngine(private val config: RaspConfig) {

    fun evaluate(signals: List<Signal>, nowMillis: Long): Decision {
        val threats = signals.map { it.threat }.toSet().associateWith { threat ->
            val reactions = config.policy[threat].orEmpty()
            // Dev mode never reacts, so developers can use debuggers and emulators freely.
            if (config.devMode) reactions.intersect(setOf(Reaction.REPORT)) else reactions
        }
        return Decision(signals, threats, riskLevel(threats.keys), nowMillis)
    }

    fun guard(flow: String, decision: Decision): GuardResult {
        if (flow !in config.sensitiveFlows) {
            return GuardResult(flow, allowed = true, blockingThreats = emptyList())
        }
        val blocking = decision.threats.filterValues { Reaction.BLOCK_SENSITIVE in it }.keys.sorted()
        val warnings = decision.threats.filterValues { Reaction.WARN_USER in it }.keys.sorted() - blocking.toSet()
        return GuardResult(flow, allowed = blocking.isEmpty(), blockingThreats = blocking, warnings = warnings)
    }

    private fun riskLevel(threats: Set<ThreatType>): RiskLevel = when {
        threats.any { it in HIGH_RISK } -> RiskLevel.HIGH
        threats.any { it in MEDIUM_RISK } -> RiskLevel.MEDIUM
        threats.isNotEmpty() -> RiskLevel.LOW
        else -> RiskLevel.NONE
    }

    companion object {
        private val HIGH_RISK = setOf(
            ThreatType.TAMPER, ThreatType.HOOKING, ThreatType.DEBUGGER,
            ThreatType.ACCESSIBILITY_ABUSE, ThreatType.OVERLAY, ThreatType.SCREEN_RECORDING, ThreatType.SCREEN_MIRRORING,
        )
        private val MEDIUM_RISK = setOf(
            ThreatType.ROOT, ThreatType.EMULATOR, ThreatType.ACTIVE_CALL, ThreatType.REMOTE_ACCESS_APP,
            ThreatType.SCREEN_CAPTURE, ThreatType.DETECTOR_FAILURE,
        )
    }
}
