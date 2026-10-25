package ai.sourceorrery.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * SR07 of the 2026-10-25 review: a reader's native handle is never freed
 * while a call uses it. The handle here is a fake that records when it is
 * freed, so no native library is needed and nothing freed is touched; the
 * ordering is forced with latches, not left to timing.
 */
class GuardedTest {
    /** A handle that knows whether, and how often, it was freed. */
    static final class Fake {
        volatile boolean freed;
        final AtomicInteger frees = new AtomicInteger();
    }

    private static Guarded<Fake> guard(Fake fake) {
        return new Guarded<>(fake, f -> {
            f.freed = true;
            f.frees.incrementAndGet();
        }, "SecretReader is closed");
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(30, TimeUnit.SECONDS), "latch");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static void waitForWaiter(Guarded<?> guarded) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (!guarded.hasWaiters()) {
            assertTrue(System.nanoTime() < deadline, "the close never queued");
            Thread.onSpinWait();
        }
    }

    @Test
    void closeWaitsForEveryRunningCallThenFreesOnce() throws Exception {
        Fake fake = new Fake();
        Guarded<Fake> guarded = guard(fake);
        int calls = 4;
        CountDownLatch entered = new CountDownLatch(calls);
        CountDownLatch proceed = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Boolean>> running = new ArrayList<>();
            for (int i = 0; i < calls; i++) {
                // Each call reports whether its handle was freed under it.
                running.add(pool.submit(() -> guarded.call(f -> {
                    entered.countDown();
                    await(proceed);
                    return f.freed;
                })));
            }
            await(entered);
            Future<?> closer = pool.submit(guarded::close);
            waitForWaiter(guarded);
            // Requested: closed to new calls, but nothing freed yet.
            assertTrue(guarded.isClosed());
            assertEquals(0, fake.frees.get());
            assertFalse(closer.isDone());
            IllegalStateException refused =
                    assertThrows(IllegalStateException.class, () -> guarded.call(f -> 1));
            assertEquals("SecretReader is closed", refused.getMessage());
            proceed.countDown();
            for (Future<Boolean> call : running) {
                assertFalse(call.get(), "a call saw its handle freed");
            }
            closer.get();
            assertEquals(1, fake.frees.get());
        }
    }

    @Test
    void callsShareTheHandleAcrossThreads() throws Exception {
        Fake fake = new Fake();
        Guarded<Fake> guarded = guard(fake);
        int calls = 16;
        // Every call is inside at the same moment: they do not exclude each other.
        CountDownLatch together = new CountDownLatch(calls);
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<Integer>> running = new ArrayList<>();
            for (int i = 0; i < calls; i++) {
                int n = i;
                running.add(pool.submit(() -> guarded.call(f -> {
                    together.countDown();
                    await(together);
                    return n;
                })));
            }
            for (int i = 0; i < calls; i++) {
                assertEquals(i, running.get(i).get());
            }
        }
        assertFalse(guarded.isClosed());
        guarded.close();
        assertEquals(1, fake.frees.get());
    }

    @Test
    void aFailedCallReleasesTheHandleAndCloseRunsOnce() {
        Fake fake = new Fake();
        Guarded<Fake> guarded = guard(fake);
        assertThrows(IllegalArgumentException.class, () -> guarded.call(f -> {
            throw new IllegalArgumentException("from the native call");
        }));
        guarded.close();
        guarded.close();
        assertEquals(1, fake.frees.get());
        assertThrows(IllegalStateException.class, () -> guarded.call(f -> 1));
    }

    @Test
    void aCallCannotCloseTheHandleItUses() {
        Fake fake = new Fake();
        Guarded<Fake> guarded = guard(fake);
        guarded.call(f -> {
            assertThrows(IllegalStateException.class, guarded::close);
            return null;
        });
        assertFalse(guarded.isClosed());
        assertEquals(0, fake.frees.get());
        guarded.close();
        assertEquals(1, fake.frees.get());
    }

    @Test
    void callsRacingCloseEitherFinishOrAreRefused() throws Exception {
        Fake fake = new Fake();
        Guarded<Fake> guarded = guard(fake);
        AtomicInteger sawFreed = new AtomicInteger();
        AtomicInteger finished = new AtomicInteger();
        AtomicInteger refused = new AtomicInteger();
        CountDownLatch started = new CountDownLatch(8);
        try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int t = 0; t < 8; t++) {
                pool.submit(() -> {
                    started.countDown();
                    while (true) {
                        try {
                            guarded.call(f -> {
                                if (f.freed) {
                                    sawFreed.incrementAndGet();
                                }
                                return null;
                            });
                            finished.incrementAndGet();
                        } catch (IllegalStateException closed) {
                            refused.incrementAndGet();
                            return;
                        }
                    }
                });
            }
            await(started);
            guarded.close();
        }
        assertEquals(0, sawFreed.get());
        assertEquals(8, refused.get());
        assertEquals(1, fake.frees.get());
    }
}
