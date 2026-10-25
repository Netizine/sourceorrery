using System.Text.Json;
using SourceOrrery.Native;

namespace SourceOrrery;

/// <summary>
/// A read-only, thread-safe handle on one vault, unlocked the way the CLI
/// unlocks it: OS credential store, then <see cref="OpenOptions.RecoveryKey"/>,
/// <c>SOURCEORRERY_RECOVERY_KEY</c>, then <see cref="OpenOptions.RecoveryKeyFile"/>
/// / <c>SOURCEORRERY_RECOVERY_KEY_FILE</c>. Never prompts.
/// </summary>
public sealed unsafe class SecretReader : IDisposable
{
    private readonly ReaderHandle handle;
    private int disposed;

    private SecretReader(ReaderHandle handle, string vaultName)
    {
        this.handle = handle;
        VaultName = vaultName;
    }

    /// <summary>Name of the vault this reader is bound to.</summary>
    public string VaultName { get; }

    /// <summary>True once disposed.</summary>
    public bool IsClosed => Volatile.Read(ref disposed) != 0;

    /// <summary>Open <paramref name="vault"/>; see the class remarks for the unlock order.</summary>
    public static SecretReader Open(string vault, OpenOptions? options = null)
    {
        Interop.RequireAbi();
        ArgumentNullException.ThrowIfNull(vault);
        options ??= new OpenOptions();
        var name = NativeLibraryLoader.Utf8(vault)!;
        var json = NativeLibraryLoader.Utf8(options.ToJson())!;
        var recoveryKey = NativeLibraryLoader.Utf8(options.RecoveryKey);
        nint opened = nint.Zero;
        try
        {
            fixed (byte* namePtr = name)
            fixed (byte* jsonPtr = json)
            fixed (byte* keyPtr = recoveryKey)
            {
                Interop.Check(NativeMethods.so_reader_open(
                    namePtr, (nuint)name.Length,
                    jsonPtr, (nuint)json.Length,
                    keyPtr, (nuint)(recoveryKey?.Length ?? 0),
                    &opened));
            }
        }
        finally
        {
            // The library keeps its own copy; a wrong recovery key must be cleared too.
            Array.Clear(recoveryKey ?? Array.Empty<byte>());
        }
        return new SecretReader(new ReaderHandle(opened), vault);
    }

    /// <summary>The newest accessible version of <paramref name="name"/> (enabled, inside its time window), or exactly <paramref name="version"/>.</summary>
    public Secret Get(string name, string? version = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameBytes = NativeLibraryLoader.Utf8(name)!;
        var versionBytes = NativeLibraryLoader.Utf8(version);
        SoBytes props = default;
        SoBytes value = default;
        ThrowIfClosed();
        fixed (byte* namePtr = nameBytes)
        fixed (byte* versionPtr = versionBytes)
        {
            Interop.Check(NativeMethods.so_reader_get(
                handle,
                namePtr, (nuint)nameBytes.Length,
                versionPtr, (nuint)(versionBytes?.Length ?? 0),
                &props, &value));
        }
        return Interop.TakeSecret(ref props, value);
    }

    /// <summary>Metadata only; policy is not applied, so disabled and expired versions can be inspected.</summary>
    public SecretProperties GetProperties(string name, string? version = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameBytes = NativeLibraryLoader.Utf8(name)!;
        var versionBytes = NativeLibraryLoader.Utf8(version);
        SoBytes props = default;
        ThrowIfClosed();
        fixed (byte* namePtr = nameBytes)
        fixed (byte* versionPtr = versionBytes)
        {
            Interop.Check(NativeMethods.so_reader_properties(
                handle,
                namePtr, (nuint)nameBytes.Length,
                versionPtr, (nuint)(versionBytes?.Length ?? 0),
                &props));
        }
        return SecretProperties.Parse(Interop.TakeString(ref props));
    }

    /// <summary>Resolve <c>sourceorrery://vault/name[/version]</c>; the vault must be this reader's.</summary>
    public Secret Resolve(string reference)
    {
        ArgumentNullException.ThrowIfNull(reference);
        var referenceBytes = NativeLibraryLoader.Utf8(reference)!;
        SoBytes props = default;
        SoBytes value = default;
        ThrowIfClosed();
        fixed (byte* referencePtr = referenceBytes)
        {
            Interop.Check(NativeMethods.so_reader_resolve(
                handle, referencePtr, (nuint)referenceBytes.Length, &props, &value));
        }
        return Interop.TakeSecret(ref props, value);
    }

    /// <summary>Non-sensitive description of the vault (name, id, path, protectors).</summary>
    public VaultDescriptor GetDescriptor()
    {
        ThrowIfClosed();
        return Descriptor(handle);
    }

    /// <summary>The descriptor through <paramref name="reader"/>.</summary>
    internal static VaultDescriptor Descriptor(ReaderHandle reader)
    {
        SoBytes json = default;
        Interop.Check(NativeMethods.so_reader_descriptor(reader, &json));
        var dto = JsonSerializer.Deserialize(Interop.TakeString(ref json), SourceOrreryJsonContext.Default.VaultDescriptorDto)
            ?? throw new SourceOrreryException("empty descriptor", "storage");
        return new VaultDescriptor
        {
            Name = dto.Name,
            Id = dto.Id,
            Backend = dto.Backend,
            Path = dto.Path,
            CreatedOn = dto.CreatedOn,
            RecoveryLevel = dto.RecoveryLevel ?? "recoverable",
            RetentionDays = dto.RetentionDays,
            Protectors = dto.Protectors ?? new List<string>(),
        };
    }

    /// <summary>
    /// Release the vault; the key held in memory is zeroised. Idempotent. A call
    /// already running on another thread finishes first; later calls throw
    /// <see cref="ObjectDisposedException"/>.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) == 0)
        {
            handle.Dispose();
        }
    }

    /// <inheritdoc />
    public override string ToString() => $"SecretReader(vault='{VaultName}')";

    /// <summary>
    /// The native handle. Each call passes it to its import, which keeps it
    /// open for that call; see <see cref="ReaderHandle"/>.
    /// </summary>
    internal ReaderHandle Handle => handle;

    /// <summary>
    /// Refuse a call once disposed. A call already running holds the handle
    /// open, so the handle alone would not refuse a new one.
    /// </summary>
    private void ThrowIfClosed() => ObjectDisposedException.ThrowIf(IsClosed, this);
}

internal static unsafe class Interop
{
    /// <summary>
    /// C ABI version the <c>NativeMethods</c> declarations follow: <c>SO_ABI_VERSION</c>
    /// in the <c>sourceorrery.h</c> this package was written against.
    /// </summary>
    internal const uint AbiVersion = 2;

    /// <summary>Refuse a library built for another C ABI version before anything is opened (ADR 0007).</summary>
    internal static void RequireAbi()
    {
        var mismatch = AbiMismatch(NativeMethods.so_abi_version());
        if (mismatch is not null)
        {
            throw mismatch;
        }
    }

    /// <summary>
    /// The exception for a library whose C ABI version is <paramref name="found"/>, or <c>null</c>
    /// when it matches <see cref="AbiVersion"/>. Its code, <c>abi_mismatch</c>, is produced by the
    /// SDK itself, never by the core.
    /// </summary>
    internal static SourceOrreryException? AbiMismatch(uint found)
    {
        if (found == AbiVersion)
        {
            return null;
        }
        return new SourceOrreryException(
            $"the SourceOrrery native library implements C ABI version {found}; this SDK was built for version {AbiVersion}",
            "abi_mismatch",
            "install the sourceorrery-ffi library of the release this SDK version belongs to");
    }

    /// <summary>Throw the typed exception for the last error when <paramref name="status"/> is not OK.</summary>
    public static void Check(int status)
    {
        if (status == NativeMethods.StatusOk)
        {
            return;
        }
        var code = NativeLibraryLoader.ReadCString(NativeMethods.so_last_error_code()) ?? (status == 2 ? "internal" : "unknown");
        var message = NativeLibraryLoader.ReadCString(NativeMethods.so_last_error_message()) ?? "unknown error";
        var hint = NativeLibraryLoader.ReadCString(NativeMethods.so_last_error_hint()) ?? "";
        throw SourceOrreryException.ForCode(code, message, hint);
    }

    /// <summary>
    /// A secret from a read's two buffers. The value is owned before the
    /// metadata is parsed, so a parse failure still zeroises it.
    /// </summary>
    public static Secret TakeSecret(ref SoBytes props, SoBytes value)
    {
        var secretValue = new SecretValue(value);
        try
        {
            return new Secret(SecretProperties.Parse(TakeString(ref props)), secretValue);
        }
        catch
        {
            secretValue.Dispose();
            throw;
        }
    }

    /// <summary>Copy a UTF-8 buffer into a string and free it.</summary>
    public static string TakeString(ref SoBytes bytes)
    {
        try
        {
            return bytes.Ptr == null ? "" : System.Text.Encoding.UTF8.GetString(bytes.Ptr, checked((int)bytes.Len));
        }
        finally
        {
            fixed (SoBytes* slot = &bytes)
            {
                NativeMethods.so_bytes_free(slot);
            }
        }
    }

    /// <summary>Contract version of the core the loaded library implements.</summary>
    public static string ContractVersion() => NativeLibraryLoader.ReadCString(NativeMethods.so_contract_version()) ?? "";
}

/// <summary>Information about the loaded native library.</summary>
public static class SourceOrreryNative
{
    /// <summary>Contract version of the core (<c>"1"</c> for this package).</summary>
    public static string ContractVersion => Interop.ContractVersion();

    /// <summary>Version of the C ABI the library was built with.</summary>
    public static uint AbiVersion => NativeMethods.so_abi_version();
}
