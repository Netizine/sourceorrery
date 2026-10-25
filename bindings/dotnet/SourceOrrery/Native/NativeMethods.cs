// P/Invoke declarations for the read-only part of the SourceOrrery C ABI
// (crates/sourceorrery-ffi/include/sourceorrery.h). Only so_reader_* and
// so_project_* functions are declared, so this assembly cannot write to a
// vault.

using System.Runtime.InteropServices;

namespace SourceOrrery.Native;

/// <summary>Caller-owned buffer; release with <see cref="NativeMethods.so_bytes_free"/>.</summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct SoBytes
{
    public byte* Ptr;
    public nuint Len;
}

internal static unsafe partial class NativeMethods
{
    public const string LibraryName = "sourceorrery_ffi";
    public const int StatusOk = 0;

    static NativeMethods()
    {
        NativeLibraryLoader.Register();
    }

    [LibraryImport(LibraryName)]
    public static partial uint so_abi_version();

    [LibraryImport(LibraryName)]
    public static partial nint so_contract_version();

    [LibraryImport(LibraryName)]
    public static partial void so_bytes_free(SoBytes* bytes);

    [LibraryImport(LibraryName)]
    public static partial nint so_last_error_code();

    [LibraryImport(LibraryName)]
    public static partial nint so_last_error_message();

    [LibraryImport(LibraryName)]
    public static partial nint so_last_error_hint();

    [LibraryImport(LibraryName)]
    public static partial int so_reader_open(
        byte* name, nuint nameLen,
        byte* optionsJson, nuint optionsJsonLen,
        byte* recoveryKey, nuint recoveryKeyLen,
        nint* outHandle);

    [LibraryImport(LibraryName)]
    public static partial void so_reader_close(nint handle);

    [LibraryImport(LibraryName)]
    public static partial int so_reader_descriptor(ReaderHandle handle, SoBytes* outJson);

    [LibraryImport(LibraryName)]
    public static partial int so_reader_get(
        ReaderHandle handle,
        byte* name, nuint nameLen,
        byte* version, nuint versionLen,
        SoBytes* outPropertiesJson, SoBytes* outValue);

    [LibraryImport(LibraryName)]
    public static partial int so_reader_properties(
        ReaderHandle handle,
        byte* name, nuint nameLen,
        byte* version, nuint versionLen,
        SoBytes* outPropertiesJson);

    [LibraryImport(LibraryName)]
    public static partial int so_reader_resolve(
        ReaderHandle handle,
        byte* reference, nuint referenceLen,
        SoBytes* outPropertiesJson, SoBytes* outValue);

    [LibraryImport(LibraryName)]
    public static partial int so_project_load(
        byte* manifestPath, nuint manifestPathLen,
        byte* optionsJson, nuint optionsJsonLen,
        byte* recoveryKey, nuint recoveryKeyLen,
        nint* outHandle);

    [LibraryImport(LibraryName)]
    public static partial nuint so_project_count(nint handle);

    [LibraryImport(LibraryName)]
    public static partial int so_project_info(nint handle, SoBytes* outJson);

    [LibraryImport(LibraryName)]
    public static partial int so_project_entry(nint handle, nuint index, SoBytes* outEntryJson, SoBytes* outValue);

    [LibraryImport(LibraryName)]
    public static partial void so_project_free(nint handle);
}
