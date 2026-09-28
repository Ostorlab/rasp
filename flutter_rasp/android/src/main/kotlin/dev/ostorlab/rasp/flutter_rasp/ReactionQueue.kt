package dev.ostorlab.rasp.flutter_rasp

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/** Generation checks cover both queued reactions and work already posted to a UI dispatcher. */
class ReactionQueue {
    private val executor = Executors.newSingleThreadScheduledExecutor()
    private val pending = mutableListOf<ScheduledFuture<*>>()
    private var generation = 0L

    @Synchronized fun schedule(delayMillis: Long, action: (Long) -> Unit) {
        require(delayMillis in 0..60000)
        val epoch = generation
        pending.removeAll { it.isDone }
        pending += executor.schedule({ runIfCurrent(epoch) { action(epoch) } }, delayMillis, TimeUnit.MILLISECONDS)
    }
    @Synchronized fun runIfCurrent(epoch: Long, action: () -> Unit) {
        if (epoch == generation) action()
    }
    @Synchronized fun current(): Long = generation
    @Synchronized fun cancel() {
        generation++
        pending.forEach { it.cancel(false) }
        pending.clear()
    }
    fun close() { cancel(); executor.shutdownNow() }
}
