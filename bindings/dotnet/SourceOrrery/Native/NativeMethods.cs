// P/Invoke declarations for the SourceOrrery C ABI, one per function in
// crates/sourceorrery-ffi/include/sourceorrery.h. Strings go in as UTF-8
// (ptr, len) pairs, never NUL-terminated; a null pointer with length 0 is
// "absent". Data comes out as caller-owned SoBytes released with
// so_bytes_free. Every fallible call returns an so_status.

using System.Runtime.InteropServices;

namespace SourceOrrery.Native;

internal static unsafe partial class NativeMethods
{
    public const string LibraryName = "sourceorrery_ffi";

    /// <summary><c>SO_ABI_VERSION</c> of the header these declarations follow.</summary>
    public const uint AbiVersion = 1;

    /// <summary><c>SO_STATUS_OK</c>.</summary>
    public const int StatusOk = 0;

    /// <summary><c>SO_STATUS_ERROR</c>.</summary>
    public const int StatusError = 1;

    /// <summary><c>SO_STATUS_PANIC</c>: a Rust panic was caught; the code is <c>internal</c>.</summary>
    public const int StatusPanic = 2;

    static NativeMethods()
    {
        NativeLibraryLoader.Register();
    }

    [LibraryImport(LibraryName)]
    public static partial uint so_abi_version();

    [LibraryImport(LibraryName)]
    public static partial byte* so_contract_version();

    [LibraryImport(LibraryName)]
    public static partial void so_bytes_free(ref SoBytes bytes);

    [LibraryImport(LibraryName)]
    public static partial byte* so_last_error_code();

    [LibraryImport(LibraryName)]
    public static partial byte* so_last_error_message();

    [LibraryImport(LibraryName)]
    public static partial void so_last_error_clear();

    [LibraryImport(LibraryName)]
    public static partial int so_vault_create(
        byte* home, nuint homeLen,
        byte* name, nuint nameLen,
        byte* optionsJson, nuint optionsJsonLen,
        byte* passphrase, nuint passphraseLen,
        out nint outHandle);

    [LibraryImport(LibraryName)]
    public static partial int so_vault_open(
        byte* home, nuint homeLen,
        byte* name, nuint nameLen,
        byte* passphrase, nuint passphraseLen,
        out nint outHandle);

    [LibraryImport(LibraryName)]
    public static partial void so_vault_close(nint handle);

    [LibraryImport(LibraryName)]
    public static partial int so_vault_descriptor(VaultHandle handle, ref SoBytes outJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_set(
        VaultHandle handle,
        byte* name, nuint nameLen,
        byte* value, nuint valueLen,
        byte* optionsJson, nuint optionsJsonLen,
        ref SoBytes outPropertiesJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_get(
        VaultHandle handle,
        byte* name, nuint nameLen,
        byte* version, nuint versionLen,
        ref SoBytes outPropertiesJson,
        ref SoBytes outValue);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_get_properties(
        VaultHandle handle,
        byte* name, nuint nameLen,
        byte* version, nuint versionLen,
        ref SoBytes outPropertiesJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_list(VaultHandle handle, ref SoBytes outJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_versions(
        VaultHandle handle,
        byte* name, nuint nameLen,
        ref SoBytes outJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_update(
        VaultHandle handle,
        byte* name, nuint nameLen,
        byte* version, nuint versionLen,
        byte* updateJson, nuint updateJsonLen,
        ref SoBytes outPropertiesJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_delete(
        VaultHandle handle,
        byte* name, nuint nameLen,
        ref SoBytes outDeletedJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_get_deleted(
        VaultHandle handle,
        byte* name, nuint nameLen,
        ref SoBytes outDeletedJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_list_deleted(VaultHandle handle, ref SoBytes outJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_recover(
        VaultHandle handle,
        byte* name, nuint nameLen,
        ref SoBytes outPropertiesJson);

    [LibraryImport(LibraryName)]
    public static partial int so_secret_purge(
        VaultHandle handle,
        byte* name, nuint nameLen);

    [LibraryImport(LibraryName)]
    public static partial int so_audit_events(
        VaultHandle handle,
        byte* queryJson, nuint queryJsonLen,
        ref SoBytes outJson);
}
