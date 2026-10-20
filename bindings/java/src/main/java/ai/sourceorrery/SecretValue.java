package ai.sourceorrery;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Consumer;

import ai.sourceorrery.internal.Native;

/**
 * A secret value kept in native memory until {@link #close()} zeroises it.
 * {@link #expose()} and {@link #exposeText()} return copies the application
 * owns (a Java {@code String} cannot be wiped: keep it short-lived);
 * {@link #use(Consumer)} hands out a copy and wipes it afterwards.
 * {@link #toString()} prints {@code [REDACTED]}.
 */
public final class SecretValue implements AutoCloseable {
    private final Object gate = new Object();
    private long address;
    private long length;

    SecretValue(Native.RawBytes raw) {
        this.address = raw.address();
        this.length = raw.length();
    }

    /** Length in bytes; 0 once closed. */
    public int length() {
        synchronized (gate) {
            return address == 0 ? 0 : Math.toIntExact(length);
        }
    }

    /** True once {@link #close()} has run. */
    public boolean isClosed() {
        synchronized (gate) {
            return address == 0;
        }
    }

    /** A copy of the bytes. */
    public byte[] expose() {
        synchronized (gate) {
            if (address == 0) {
                throw new IllegalStateException("SecretValue is closed; its bytes were zeroised");
            }
            return new Native.RawBytes(address, length).copy();
        }
    }

    /** The value decoded as UTF-8. */
    public String exposeText() {
        return new String(expose(), StandardCharsets.UTF_8);
    }

    /** Hand a copy of the bytes to {@code consumer} and wipe the copy afterwards. */
    public void use(Consumer<byte[]> consumer) {
        byte[] copy = expose();
        try {
            consumer.accept(copy);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    /** Zeroise and free the native bytes. Idempotent. */
    @Override
    public void close() {
        synchronized (gate) {
            if (address != 0) {
                Native.freeBytes(address, length);
                address = 0;
                length = 0;
            }
        }
    }

    @Override
    public String toString() {
        return "[REDACTED]";
    }
}
