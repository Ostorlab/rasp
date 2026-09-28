package dev.ostorlab.rasp.flutter_rasp

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReactionQueueTest {
    @Test fun replacementCancelsOldWorkAndAcceptsNewReactions() {
        val queue = ReactionQueue()
        try {
            val old = CountDownLatch(1)
            queue.schedule(100) { old.countDown() }
            queue.cancel()
            val current = CountDownLatch(1)
            queue.schedule(0) { current.countDown() }
            assertTrue(current.await(2, TimeUnit.SECONDS))
            assertFalse(old.await(200, TimeUnit.MILLISECONDS))
        } finally { queue.close() }
    }
    @Test fun alreadyPostedUiCallbackChecksGenerationAgain() {
        val queue = ReactionQueue()
        try {
            val posted = CountDownLatch(1)
            var epoch = -1L
            queue.schedule(0) { generation -> epoch = generation; posted.countDown() }
            assertTrue(posted.await(2, TimeUnit.SECONDS))
            queue.cancel()
            var closed = false
            queue.runIfCurrent(epoch) { closed = true }
            assertFalse(closed)
        } finally { queue.close() }
    }
}
