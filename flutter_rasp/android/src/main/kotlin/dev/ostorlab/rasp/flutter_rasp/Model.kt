package dev.ostorlab.rasp.flutter_rasp

/** Threat classes. `wireName` is shared with the Dart API; `nativeId` with signals.h. */
enum class ThreatType(val wireName: String, val nativeId: Int?) {
    ROOT("root", 0),
    EMULATOR("emulator", 1),
    DEBUGGER("debugger", 2),
    HOOKING("hooking", 3),
    TAMPER("tamper", null),
    UNTRUSTED_INSTALLER("untrustedInstaller", null),
    DEV_OPTIONS("devOptions", null),
    ADB_ENABLED("adbEnabled", null),
    NO_SCREEN_LOCK("noScreenLock", null);

    companion object {
        fun fromWire(name: String): ThreatType? = entries.firstOrNull { it.wireName == name }
        fun fromNative(id: Int): ThreatType? = entries.firstOrNull { it.nativeId == id }
    }
}

/** Local reactions. The engine is headless, so every reaction runs on the device. */
enum class Reaction(val wireName: String) {
    REPORT("report"),
    WARN_USER("warnUser"),
    BLOCK_SENSITIVE("blockSensitive"),
    SECURE_SCREEN("secureScreen"),
    CLOSE_APP("closeApp");

    companion object {
        fun fromWire(name: String): Reaction? = entries.firstOrNull { it.wireName == name }
    }
}

enum class RiskLevel(val wireName: String) { NONE("none"), LOW("low"), MEDIUM("medium"), HIGH("high") }

data class Signal(
    val threat: ThreatType,
    val detector: String,
    val confidence: Int,
    val evidence: String,
) {
    fun toMap(): Map<String, Any> = mapOf(
        "threat" to threat.wireName,
        "detector" to detector,
        "confidence" to confidence,
        "evidence" to evidence,
    )
}

data class RaspConfig(
    val expectedPackageName: String?,
    val expectedSigningCertSha256: List<String>,
    val allowedInstallers: List<String>,
    val checkIntervalSeconds: Long,
    val sensitiveFlows: Set<String>,
    val policy: Map<ThreatType, Set<Reaction>>,
    val devMode: Boolean,
) {
    companion object {
        val DEFAULT_POLICY: Map<ThreatType, Set<Reaction>> = mapOf(
            ThreatType.ROOT to setOf(Reaction.REPORT, Reaction.WARN_USER, Reaction.BLOCK_SENSITIVE),
            ThreatType.EMULATOR to setOf(Reaction.REPORT, Reaction.BLOCK_SENSITIVE),
            ThreatType.DEBUGGER to setOf(Reaction.REPORT, Reaction.BLOCK_SENSITIVE, Reaction.SECURE_SCREEN),
            ThreatType.HOOKING to setOf(Reaction.REPORT, Reaction.WARN_USER, Reaction.BLOCK_SENSITIVE, Reaction.SECURE_SCREEN),
            ThreatType.TAMPER to setOf(Reaction.REPORT, Reaction.WARN_USER, Reaction.CLOSE_APP),
            ThreatType.UNTRUSTED_INSTALLER to setOf(Reaction.REPORT),
            ThreatType.DEV_OPTIONS to setOf(Reaction.REPORT),
            ThreatType.ADB_ENABLED to setOf(Reaction.REPORT),
            ThreatType.NO_SCREEN_LOCK to setOf(Reaction.REPORT),
        )

        /** Parses the map sent by the Dart side. Unknown threat or reaction names are ignored. */
        @Suppress("UNCHECKED_CAST")
        fun fromMap(map: Map<String, Any?>): RaspConfig {
            val policyMap = map["policy"] as? Map<String, List<String>>
            val policy = policyMap?.mapNotNull { (threat, reactions) ->
                ThreatType.fromWire(threat)?.let { it to reactions.mapNotNull(Reaction::fromWire).toSet() }
            }?.toMap()
            return RaspConfig(
                expectedPackageName = map["expectedPackageName"] as? String,
                expectedSigningCertSha256 = (map["expectedSigningCertSha256"] as? List<String>).orEmpty()
                    .map(::normalizeDigest),
                allowedInstallers = (map["allowedInstallers"] as? List<String>).orEmpty(),
                checkIntervalSeconds = ((map["checkIntervalSeconds"] as? Number)?.toLong() ?: 15L).coerceAtLeast(5L),
                sensitiveFlows = (map["sensitiveFlows"] as? List<String>).orEmpty().toSet(),
                policy = DEFAULT_POLICY + policy.orEmpty(),
                devMode = map["devMode"] as? Boolean ?: false,
            )
        }

        fun normalizeDigest(digest: String): String = digest.replace(":", "").lowercase()
    }
}
