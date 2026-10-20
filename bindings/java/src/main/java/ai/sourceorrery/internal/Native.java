package ai.sourceorrery.internal;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

import ai.sourceorrery.SourceOrreryException;

/**
 * Downcalls into the read-only part of the SourceOrrery C ABI through the
 * Foreign Function and Memory API (Java 22+). Only {@code so_reader_*} and
 * {@code so_project_*} functions are bound, so code built on this class
 * cannot write to a vault.
 *
 * <p>The library is found in the directory named by
 * {@code SOURCEORRERY_NATIVE_DIR}, else extracted from the jar resource
 * {@code /ai/sourceorrery/native/<os>-<arch>/<file>}, else loaded from
 * {@code java.library.path}.
 *
 * <p>Error state in the C ABI is per OS thread; every helper here reads it
 * right after the call that failed, with no blocking operation in between,
 * so a virtual thread stays on its carrier for both.
 */
public final class Native {
    private Native() {}

    /** so_bytes { uint8_t *ptr; size_t len; } on a 64-bit platform. */
    public static final StructLayout SO_BYTES = MemoryLayout.structLayout(
            ValueLayout.ADDRESS.withName("ptr"), ValueLayout.JAVA_LONG.withName("len"));
    private static final VarHandle BYTES_PTR = SO_BYTES.varHandle(MemoryLayout.PathElement.groupElement("ptr"));
    private static final VarHandle BYTES_LEN = SO_BYTES.varHandle(MemoryLayout.PathElement.groupElement("len"));

    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup LOOKUP = load();

    private static final FunctionDescriptor STATUS_OF_STRINGS_OUT_HANDLE = FunctionDescriptor.of(
            ValueLayout.JAVA_INT,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS);

    private static final MethodHandle SO_ABI_VERSION = downcall("so_abi_version", FunctionDescriptor.of(ValueLayout.JAVA_INT));
    private static final MethodHandle SO_CONTRACT_VERSION = downcall("so_contract_version", FunctionDescriptor.of(ValueLayout.ADDRESS));
    private static final MethodHandle SO_BYTES_FREE = downcall("so_bytes_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    private static final MethodHandle SO_LAST_ERROR_CODE = downcall("so_last_error_code", FunctionDescriptor.of(ValueLayout.ADDRESS));
    private static final MethodHandle SO_LAST_ERROR_MESSAGE = downcall("so_last_error_message", FunctionDescriptor.of(ValueLayout.ADDRESS));
    private static final MethodHandle SO_LAST_ERROR_HINT = downcall("so_last_error_hint", FunctionDescriptor.of(ValueLayout.ADDRESS));
    private static final MethodHandle SO_READER_OPEN = downcall("so_reader_open", STATUS_OF_STRINGS_OUT_HANDLE);
    private static final MethodHandle SO_READER_CLOSE = downcall("so_reader_close", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    private static final MethodHandle SO_READER_DESCRIPTOR = downcall("so_reader_descriptor",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SO_READER_GET = downcall("so_reader_get", FunctionDescriptor.of(
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SO_READER_PROPERTIES = downcall("so_reader_properties", FunctionDescriptor.of(
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS));
    private static final MethodHandle SO_READER_RESOLVE = downcall("so_reader_resolve", FunctionDescriptor.of(
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
            ValueLayout.ADDRESS, ValueLayout.JAVA_LONG,
            ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SO_PROJECT_LOAD = downcall("so_project_load", STATUS_OF_STRINGS_OUT_HANDLE);
    private static final MethodHandle SO_PROJECT_COUNT = downcall("so_project_count",
            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    private static final MethodHandle SO_PROJECT_INFO = downcall("so_project_info",
            FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SO_PROJECT_ENTRY = downcall("so_project_entry", FunctionDescriptor.of(
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SO_PROJECT_FREE = downcall("so_project_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    private static MethodHandle downcall(String name, FunctionDescriptor descriptor) {
        MemorySegment symbol = LOOKUP.find(name)
                .orElseThrow(() -> new UnsatisfiedLinkError("sourceorrery_ffi does not export " + name));
        return LINKER.downcallHandle(symbol, descriptor);
    }

    private static SymbolLookup load() {
        String file = fileName();
        String fromEnv = System.getenv("SOURCEORRERY_NATIVE_DIR");
        if (fromEnv != null && !fromEnv.isEmpty()) {
            Path candidate = Path.of(fromEnv, file);
            if (Files.isRegularFile(candidate)) {
                System.load(candidate.toAbsolutePath().toString());
                return SymbolLookup.loaderLookup();
            }
        }
        String resource = "/ai/sourceorrery/native/" + platform() + "/" + file;
        try (InputStream stream = Native.class.getResourceAsStream(resource)) {
            if (stream != null) {
                Path dir = Files.createTempDirectory("sourceorrery-native");
                Path extracted = dir.resolve(file);
                Files.copy(stream, extracted, StandardCopyOption.REPLACE_EXISTING);
                extracted.toFile().deleteOnExit();
                dir.toFile().deleteOnExit();
                System.load(extracted.toAbsolutePath().toString());
                return SymbolLookup.loaderLookup();
            }
        } catch (IOException e) {
            throw new UnsatisfiedLinkError("cannot extract " + resource + ": " + e.getMessage());
        }
        System.loadLibrary("sourceorrery_ffi");
        return SymbolLookup.loaderLookup();
    }

    private static String fileName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) {
            return "sourceorrery_ffi.dll";
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return "libsourceorrery_ffi.dylib";
        }
        return "libsourceorrery_ffi.so";
    }

    /** {@code <os>-<arch>} as the jar's native resource directories are named. */
    public static String platform() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String osName = os.contains("win") ? "windows" : (os.contains("mac") || os.contains("darwin")) ? "macos" : "linux";
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        String archName = switch (arch) {
            case "amd64", "x86_64" -> "x86_64";
            case "aarch64", "arm64" -> "aarch64";
            default -> arch;
        };
        return osName + "-" + archName;
    }

    // ---- helpers ----------------------------------------------------------

    private static MemorySegment utf8(Arena arena, String text) {
        if (text == null) {
            return MemorySegment.NULL;
        }
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        MemorySegment segment = arena.allocate(Math.max(bytes.length, 1));
        MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0, bytes.length);
        return segment;
    }

    private static long utf8Length(String text) {
        return text == null ? 0 : text.getBytes(StandardCharsets.UTF_8).length;
    }

    private static MemorySegment bytes(Arena arena, byte[] data) {
        if (data == null) {
            return MemorySegment.NULL;
        }
        MemorySegment segment = arena.allocate(Math.max(data.length, 1));
        MemorySegment.copy(data, 0, segment, ValueLayout.JAVA_BYTE, 0, data.length);
        return segment;
    }

    private static String cString(MemorySegment pointer) {
        if (pointer == null || pointer.equals(MemorySegment.NULL)) {
            return null;
        }
        return pointer.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_8);
    }

    private static void check(int status) {
        if (status == 0) {
            return;
        }
        try {
            String code = cString((MemorySegment) SO_LAST_ERROR_CODE.invokeExact());
            String message = cString((MemorySegment) SO_LAST_ERROR_MESSAGE.invokeExact());
            String hint = cString((MemorySegment) SO_LAST_ERROR_HINT.invokeExact());
            if (code == null) {
                code = status == 2 ? "internal" : "unknown";
            }
            throw SourceOrreryException.forCode(code, message == null ? "unknown error" : message, hint == null ? "" : hint);
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException("cannot read the native error state", t);
        }
    }

    /** A copy of a caller-owned buffer, which is then freed. */
    private static byte[] take(MemorySegment slot) {
        MemorySegment ptr = (MemorySegment) BYTES_PTR.get(slot, 0L);
        long len = (long) BYTES_LEN.get(slot, 0L);
        byte[] copy = ptr.equals(MemorySegment.NULL) ? new byte[0] : ptr.reinterpret(len).toArray(ValueLayout.JAVA_BYTE);
        free(slot);
        return copy;
    }

    private static String takeString(MemorySegment slot) {
        return new String(take(slot), StandardCharsets.UTF_8);
    }

    private static void free(MemorySegment slot) {
        try {
            SO_BYTES_FREE.invokeExact(slot);
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    /** Zeroise and free a buffer given its raw address and length. */
    public static void freeBytes(long address, long length) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment slot = arena.allocate(SO_BYTES);
            BYTES_PTR.set(slot, 0L, MemorySegment.ofAddress(address));
            BYTES_LEN.set(slot, 0L, length);
            free(slot);
        }
    }

    /** A value buffer handed out by the library: raw address and length. */
    public record RawBytes(long address, long length) {
        /** A copy of the bytes. */
        public byte[] copy() {
            if (address == 0) {
                return new byte[0];
            }
            return MemorySegment.ofAddress(address).reinterpret(length).toArray(ValueLayout.JAVA_BYTE);
        }
    }

    private static RawBytes detach(MemorySegment slot) {
        MemorySegment ptr = (MemorySegment) BYTES_PTR.get(slot, 0L);
        long len = (long) BYTES_LEN.get(slot, 0L);
        return new RawBytes(ptr.address(), len);
    }

    /** Metadata JSON plus the value of a read. */
    public record SecretParts(String propertiesJson, RawBytes value) {}

    // ---- exported operations ---------------------------------------------

    public static int abiVersion() {
        try {
            return (int) SO_ABI_VERSION.invokeExact();
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static String contractVersion() {
        try {
            return cString((MemorySegment) SO_CONTRACT_VERSION.invokeExact());
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static MemorySegment readerOpen(String vault, String optionsJson, byte[] passphrase) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) SO_READER_OPEN.invokeExact(
                    utf8(arena, vault), utf8Length(vault),
                    utf8(arena, optionsJson), utf8Length(optionsJson),
                    bytes(arena, passphrase), (long) (passphrase == null ? 0 : passphrase.length),
                    out);
            check(status);
            return out.get(ValueLayout.ADDRESS, 0);
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static void readerClose(MemorySegment handle) {
        try {
            SO_READER_CLOSE.invokeExact(handle);
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static String readerDescriptor(MemorySegment handle) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(SO_BYTES);
            check((int) SO_READER_DESCRIPTOR.invokeExact(handle, out));
            return takeString(out);
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static SecretParts readerGet(MemorySegment handle, String name, String version) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment props = arena.allocate(SO_BYTES);
            MemorySegment value = arena.allocate(SO_BYTES);
            check((int) SO_READER_GET.invokeExact(handle,
                    utf8(arena, name), utf8Length(name),
                    utf8(arena, version), utf8Length(version),
                    props, value));
            return new SecretParts(takeString(props), detach(value));
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static String readerProperties(MemorySegment handle, String name, String version) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment props = arena.allocate(SO_BYTES);
            check((int) SO_READER_PROPERTIES.invokeExact(handle,
                    utf8(arena, name), utf8Length(name),
                    utf8(arena, version), utf8Length(version),
                    props));
            return takeString(props);
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static SecretParts readerResolve(MemorySegment handle, String reference) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment props = arena.allocate(SO_BYTES);
            MemorySegment value = arena.allocate(SO_BYTES);
            check((int) SO_READER_RESOLVE.invokeExact(handle,
                    utf8(arena, reference), utf8Length(reference),
                    props, value));
            return new SecretParts(takeString(props), detach(value));
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static MemorySegment projectLoad(String manifest, String optionsJson, byte[] passphrase) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(ValueLayout.ADDRESS);
            int status = (int) SO_PROJECT_LOAD.invokeExact(
                    utf8(arena, manifest), utf8Length(manifest),
                    utf8(arena, optionsJson), utf8Length(optionsJson),
                    bytes(arena, passphrase), (long) (passphrase == null ? 0 : passphrase.length),
                    out);
            check(status);
            return out.get(ValueLayout.ADDRESS, 0);
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static long projectCount(MemorySegment handle) {
        try {
            return (long) SO_PROJECT_COUNT.invokeExact(handle);
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static String projectInfo(MemorySegment handle) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(SO_BYTES);
            check((int) SO_PROJECT_INFO.invokeExact(handle, out));
            return takeString(out);
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static SecretParts projectEntry(MemorySegment handle, long index) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment entry = arena.allocate(SO_BYTES);
            MemorySegment value = arena.allocate(SO_BYTES);
            check((int) SO_PROJECT_ENTRY.invokeExact(handle, index, entry, value));
            return new SecretParts(takeString(entry), detach(value));
        } catch (SourceOrreryException e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    public static void projectFree(MemorySegment handle) {
        try {
            SO_PROJECT_FREE.invokeExact(handle);
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }
}
