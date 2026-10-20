package ai.sourceorrery;

import ai.sourceorrery.internal.Native;

/** Information about the loaded native library. */
public final class SourceOrrery {
    private SourceOrrery() {}

    /** Contract version of the core ({@code "1"} for this package). */
    public static String contractVersion() {
        return Native.contractVersion();
    }

    /** Version of the C ABI the library was built with. */
    public static int abiVersion() {
        return Native.abiVersion();
    }
}
