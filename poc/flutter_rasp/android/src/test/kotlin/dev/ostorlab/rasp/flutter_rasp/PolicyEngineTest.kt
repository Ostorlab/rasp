package dev.ostorlab.rasp.flutter_rasp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class PolicyEngineTest {

    private fun config(devMode: Boolean = false, policy: Map<String, List<String>> = emptyMap()) = RaspConfig.fromMap(
        mapOf(
            "sensitiveFlows" to listOf("transfer"),
            "policy" to policy,
            "devMode" to devMode,
            "expectedSigningCertSha256" to listOf("15:A8:94"),
        ),
    )

    private val root = Signal(ThreatType.ROOT, "native.su_binary", 90, "/system/xbin/su")
    private val hook = Signal(ThreatType.HOOKING, "native.instrumentation_maps", 90, "frida-agent")
    private val devOptions = Signal(ThreatType.DEV_OPTIONS, "platform.dev_options", 100, "enabled")

    @Test
    fun cleanDeviceHasNoRiskAndAllowsFlows() {
        val engine = PolicyEngine(config())
        val decision = engine.evaluate(emptyList(), 0)
        assertEquals(RiskLevel.NONE, decision.riskLevel)
        assertTrue(engine.guard("transfer", decision).allowed)
    }

    @Test
    fun rootBlocksSensitiveFlowOnly() {
        val engine = PolicyEngine(config())
        val decision = engine.evaluate(listOf(root), 0)
        assertEquals(RiskLevel.MEDIUM, decision.riskLevel)
        val guard = engine.guard("transfer", decision)
        assertFalse(guard.allowed)
        assertEquals(listOf(ThreatType.ROOT), guard.blockingThreats)
        assertTrue(engine.guard("viewBalance", decision).allowed)
    }

    @Test
    fun hookingIsHighRiskAndSecuresScreen() {
        val decision = PolicyEngine(config()).evaluate(listOf(hook, devOptions), 0)
        assertEquals(RiskLevel.HIGH, decision.riskLevel)
        assertTrue(Reaction.SECURE_SCREEN in decision.reactions)
    }

    @Test
    fun reportOnlyThreatDoesNotBlock() {
        val engine = PolicyEngine(config())
        val decision = engine.evaluate(listOf(devOptions), 0)
        assertEquals(RiskLevel.LOW, decision.riskLevel)
        assertTrue(engine.guard("transfer", decision).allowed)
    }

    @Test
    fun devModeOnlyReports() {
        val engine = PolicyEngine(config(devMode = true))
        val decision = engine.evaluate(listOf(root, hook), 0)
        assertEquals(setOf(Reaction.REPORT), decision.reactions)
        assertTrue(engine.guard("transfer", decision).allowed)
    }

    @Test
    fun customPolicyOverridesDefaultAndIgnoresUnknownNames() {
        val engine = PolicyEngine(config(policy = mapOf("root" to listOf("report", "nope"), "unknown" to listOf("report"))))
        val decision = engine.evaluate(listOf(root), 0)
        assertEquals(setOf(Reaction.REPORT), decision.threats[ThreatType.ROOT])
        assertTrue(engine.guard("transfer", decision).allowed)
    }

    @Test
    fun activeCallWarnsButAllowsTransfer() {
        val engine = PolicyEngine(config())
        val call = Signal(ThreatType.ACTIVE_CALL, "fraud.active_call", 90, "audio mode=2")
        val guard = engine.guard("transfer", engine.evaluate(listOf(call), 0))
        assertTrue(guard.allowed)
        assertEquals(listOf(ThreatType.ACTIVE_CALL), guard.warnings)
    }

    @Test
    fun accessibilityAbuseBlocksAndIsHighRisk() {
        val engine = PolicyEngine(config())
        val a11y = Signal(ThreatType.ACCESSIBILITY_ABUSE, "fraud.accessibility_services", 95, "com.evil.service")
        val decision = engine.evaluate(listOf(a11y), 0)
        assertEquals(RiskLevel.HIGH, decision.riskLevel)
        val guard = engine.guard("transfer", decision)
        assertFalse(guard.allowed)
        // A blocking threat is not also listed as a warning.
        assertTrue(guard.warnings.isEmpty())
    }

    @Test
    fun assistiveToolsAreAllowlistedByDefault() {
        assertTrue("com.google.android.marvin.talkback" in config().accessibilityAllowlist)
    }

    @Test
    fun digestsAreNormalized() {
        assertEquals(listOf("15a894"), config().expectedSigningCertSha256)
    }
}
