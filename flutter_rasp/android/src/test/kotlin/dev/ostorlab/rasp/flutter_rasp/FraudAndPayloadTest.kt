package dev.ostorlab.rasp.flutter_rasp

import kotlin.test.Test
import kotlin.test.assertEquals
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
    fun throwingDetectorIsReportedNotSilent() {
        val ok = Signal(ThreatType.ROOT, "native.su_binary", 90, "/sbin/su")
        val signals = runDetectors("platform", listOf({ listOf(ok) }, { throw SecurityException("hooked") }))
        assertEquals(listOf(ThreatType.ROOT, ThreatType.DETECTOR_FAILURE), signals.map { it.threat })
        assertEquals("SecurityException", signals[1].evidence)
    }
}
