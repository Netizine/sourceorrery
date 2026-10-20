using SourceOrrery.Native;

namespace SourceOrrery;

/// <summary>Information about the loaded native library.</summary>
public static class SourceOrreryLibrary
{
    /// <summary>The C ABI version this assembly was written against (<c>SO_ABI_VERSION</c>).</summary>
    public const uint ExpectedAbiVersion = NativeMethods.AbiVersion;

    /// <summary>Environment variable naming a directory to load <c>sourceorrery_ffi</c> from.</summary>
    public const string NativeDirectoryVariable = NativeLibraryLoader.NativeDirVariable;

    /// <summary>Version of the C ABI the loaded library was built with.</summary>
    public static uint AbiVersion => NativeMethods.so_abi_version();

    /// <summary>Version of the SourceOrrery contract (<c>sourceorrery_core::CONTRACT_VERSION</c>) the library implements.</summary>
    public static string ContractVersion => Interop.ContractVersion();

    /// <summary>Throw <see cref="SourceOrreryException"/> (<c>abi_mismatch</c>) unless the loaded library speaks this assembly's ABI.</summary>
    public static void EnsureCompatible()
    {
        Interop.EnsureCompatible();
    }
}
