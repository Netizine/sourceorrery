using System.Reflection;
using System.Runtime.InteropServices;

namespace SourceOrrery.Native;

/// <summary>
/// Finds <c>sourceorrery_ffi</c>. An explicit <c>SOURCEORRERY_NATIVE_DIR</c>
/// wins; then <c>runtimes/&lt;rid&gt;/native</c> next to the application (the
/// NuGet layout); then the application directory itself; and finally the
/// runtime's default search.
/// </summary>
internal static class NativeLibraryLoader
{
    /// <summary>Environment variable naming a directory that holds the native library.</summary>
    public const string NativeDirVariable = "SOURCEORRERY_NATIVE_DIR";

    private static int registered;

    /// <summary>Install the resolver once; called before the first P/Invoke.</summary>
    internal static void Register()
    {
        if (Interlocked.Exchange(ref registered, 1) == 1)
        {
            return;
        }
        NativeLibrary.SetDllImportResolver(typeof(NativeLibraryLoader).Assembly, Resolve);
    }

    /// <summary>File name of the native library on this platform.</summary>
    public static string FileName()
    {
        if (OperatingSystem.IsWindows())
        {
            return "sourceorrery_ffi.dll";
        }
        if (OperatingSystem.IsMacOS())
        {
            return "libsourceorrery_ffi.dylib";
        }
        return "libsourceorrery_ffi.so";
    }

    private static nint Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != NativeMethods.LibraryName)
        {
            return nint.Zero;
        }
        _ = assembly; // probing is relative to the application, not the assembly (single-file apps have no location)
        foreach (var candidate in Candidates())
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }
        return nint.Zero; // the runtime's default probing
    }

    private static IEnumerable<string> Candidates()
    {
        var fileName = FileName();
        var fromEnv = Environment.GetEnvironmentVariable(NativeDirVariable);
        if (!string.IsNullOrEmpty(fromEnv))
        {
            yield return Path.Combine(fromEnv, fileName);
        }

        var baseDir = AppContext.BaseDirectory;
        yield return Path.Combine(baseDir, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", fileName);
        var portable = PortableRid();
        if (!string.Equals(portable, RuntimeInformation.RuntimeIdentifier, StringComparison.Ordinal))
        {
            yield return Path.Combine(baseDir, "runtimes", portable, "native", fileName);
        }
        yield return Path.Combine(baseDir, fileName);
    }

    private static string PortableRid()
    {
        var os = OperatingSystem.IsWindows() ? "win" : OperatingSystem.IsMacOS() ? "osx" : "linux";
        var arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            var other => other.ToString().ToLowerInvariant(),
        };
        return $"{os}-{arch}";
    }
}
