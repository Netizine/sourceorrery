using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace SourceOrrery.Native;

/// <summary>
/// Finds <c>sourceorrery_ffi</c>: the directory named by
/// <c>SOURCEORRERY_NATIVE_DIR</c>, then <c>runtimes/&lt;rid&gt;/native</c> next to
/// this assembly (the NuGet layout), then the assembly directory, then the
/// runtime's default search.
/// </summary>
internal static class NativeLibraryLoader
{
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

    private static nint Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != NativeMethods.LibraryName)
        {
            return nint.Zero;
        }
        foreach (var candidate in Candidates(assembly))
        {
            if (File.Exists(candidate) && NativeLibrary.TryLoad(candidate, out var handle))
            {
                return handle;
            }
        }
        return nint.Zero; // fall back to the default probing
    }

    private static IEnumerable<string> Candidates(Assembly assembly)
    {
        _ = assembly;
        var fileName = FileName();
        var fromEnv = Environment.GetEnvironmentVariable(NativeDirVariable);
        if (!string.IsNullOrEmpty(fromEnv))
        {
            yield return Path.Combine(fromEnv, fileName);
        }
        var baseDir = AppContext.BaseDirectory;
        yield return Path.Combine(baseDir, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", fileName);
        yield return Path.Combine(baseDir, "runtimes", PortableRid(), "native", fileName);
        yield return Path.Combine(baseDir, fileName);
    }

    private static string FileName()
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

    /// <summary>UTF-8 text of a NUL-terminated string, or null.</summary>
    public static string? ReadCString(nint text)
    {
        return text == nint.Zero ? null : Marshal.PtrToStringUTF8(text);
    }

    /// <summary>UTF-8 bytes of <paramref name="text"/> (no terminator), or null.</summary>
    public static byte[]? Utf8(string? text)
    {
        return text == null ? null : Encoding.UTF8.GetBytes(text);
    }
}
