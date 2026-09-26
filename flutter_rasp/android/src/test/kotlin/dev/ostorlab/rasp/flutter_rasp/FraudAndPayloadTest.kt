package dev.ostorlab.rasp.flutter_rasp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

internal class FraudAndPayloadTest {

    @Test
    fun transientSignalsExpire() {
        var now = 0L
        val store = TransientSignals(ttlMillis = 1000, clock = { now })
        store.record(Signal(ThreatType.SCREEN_CAPTURE, "fraud.screenshot", 100, "shot"))
        assertEquals(1, store.active().size)
        now = 999
        assertEquals(1, store.active().size)
        now = 1001
        assertTrue(store.active().isEmpty())
    }

    @Test
    fun signedPayloadIsCanonical() {
        val config = RaspConfig.fromMap(mapOf("sensitiveFlows" to listOf("transfer")))
        val decision = PolicyEngine(config).evaluate(
            listOf(
                Signal(ThreatType.ROOT, "native.su_binary", 90, "/sbin/su"),
                Signal(ThreatType.ACTIVE_CALL, "fraud.active_call", 90, "mode=2"),
            ),
            0,
        )
        val payload = SignedPayload.build(
            nonce = "n1",
            timestampMillis = 42,
            packageName = "dev.example",
            decision = decision,
            fields = mapOf("payee" to "Alex\nSmith", "amount" to "50.00", "memo" to "100%"),
        )
        assertEquals(
            listOf(
                "v=rasp-tx-1", "nonce=n1", "ts=42", "app=dev.example", "risk=medium", "threats=activeCall,root",
                "f.amount=50.00", "f.memo=100%25", "f.payee=Alex%0ASmith",
            ).joinToString("\n"),
            payload,
        )
    }

    @Test
    fun signedPayloadRejectsBadFieldNames() {
        val decision = PolicyEngine(RaspConfig.fromMap(emptyMap())).evaluate(emptyList(), 0)
        assertFailsWith<IllegalArgumentException> {
            SignedPayload.build("n", 0, "p", decision, mapOf("bad=key" to "x"))
        }
    }
}
