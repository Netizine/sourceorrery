package ai.sourceorrery.internal;

import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * A native handle that is freed only while no call is using it.
 *
 * <p>Every {@link #call} holds a read lock for the whole native call, so any
 * number of platform or virtual threads use the handle at once (the
 * {@code java.util.concurrent} locks do not pin a virtual thread).
 * {@link #close} takes the write lock: once it has been called every new
 * call fails with {@link IllegalStateException}, the calls already running
 * finish, the handle is freed exactly once, and only then does it return.
 * Freeing never overlaps a call, whatever the timing.
 *
 * @param <H> the handle
 */
public final class Guarded<H> {
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Consumer<H> free;
    private final String closedMessage;
    /** Guarded by {@link #lock}; {@code null} once freed. */
    private H handle;
    private volatile boolean closing;

    /**
     * Guard {@code handle}, freed with {@code free}; a call after close fails
     * with {@code closedMessage}.
     */
    public Guarded(H handle, Consumer<H> free, String closedMessage) {
        this.handle = Objects.requireNonNull(handle, "handle");
        this.free = Objects.requireNonNull(free, "free");
        this.closedMessage = Objects.requireNonNull(closedMessage, "closedMessage");
    }

    /** Run {@code call} with the handle, which stays allocated until it returns. */
    public <T> T call(Function<H, T> call) {
        if (closing) {
            throw new IllegalStateException(closedMessage);
        }
        ReentrantReadWriteLock.ReadLock read = lock.readLock();
        read.lock();
        try {
            if (handle == null) {
                throw new IllegalStateException(closedMessage);
            }
            return call.apply(handle);
        } finally {
            read.unlock();
        }
    }

    /**
     * Refuse new calls, wait for the running ones, free the handle once.
     * Idempotent. A call cannot close its own handle: that would wait for
     * itself.
     */
    public void close() {
        if (lock.getReadHoldCount() > 0) {
            throw new IllegalStateException("a call cannot close the handle it is using");
        }
        closing = true;
        ReentrantReadWriteLock.WriteLock write = lock.writeLock();
        write.lock();
        try {
            H current = handle;
            handle = null;
            if (current != null) {
                free.accept(current);
            }
        } finally {
            write.unlock();
        }
    }

    /** True once {@link #close} has been called. */
    public boolean isClosed() {
        return closing;
    }

    /** True while a thread waits on the lock: a close waiting for calls (tests). */
    boolean hasWaiters() {
        return lock.hasQueuedThreads();
    }
}
