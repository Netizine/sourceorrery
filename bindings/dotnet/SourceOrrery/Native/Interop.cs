using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace SourceOrrery.Native;

/// <summary>Glue between the raw ABI and the managed types.</summary>
internal static unsafe class Interop
{
    private static int abiChecked;

    /// <summary>
    /// Compare the loaded library's <c>so_abi_version()</c> with the version
    /// this assembly was written against, once per process.
    /// </summary>
    public static void EnsureCompatible()
    {
        if (Volatile.Read(ref abiChecked) == 1)
        {
            return;
        }
        var actual = NativeMethods.so_abi_version();
        if (actual != NativeMethods.AbiVersion)
        {
            throw new SourceOrreryException(
                "abi_mismatch",
                $"the native sourceorrery_ffi library implements C ABI version {actual}; this assembly was built for version {NativeMethods.AbiVersion}");
        }
        Volatile.Write(ref abiChecked, 1);
    }

    /// <summary>
    /// Throw the typed exception for the thread's last error when
    /// <paramref name="status"/> is not <c>SO_STATUS_OK</c>. The code and
    /// message are read immediately: they are valid only until the next call
    /// on this thread.
    /// </summary>
    public static void Check(int status)
    {
        if (status == NativeMethods.StatusOk)
        {
            return;
        }
        var code = ReadCString(NativeMethods.so_last_error_code())
            ?? (status == NativeMethods.StatusPanic ? "internal" : "unknown");
        var message = ReadCString(NativeMethods.so_last_error_message())
            ?? "the native library reported an error without a message";
        NativeMethods.so_last_error_clear();
        throw SourceOrreryException.FromCode(code, message);
    }

    /// <summary>UTF-8 text of a NUL-terminated string, or null for a null pointer.</summary>
    public static string? ReadCString(byte* text)
    {
        return text == null ? null : Marshal.PtrToStringUTF8((nint)text);
    }

    /// <summary>Contract version of the core the loaded library implements.</summary>
    public static string ContractVersion()
    {
        return ReadCString(NativeMethods.so_contract_version()) ?? string.Empty;
    }

    /// <summary>Deserialise a JSON buffer the library returned, then free it.</summary>
    public static T TakeJson<T>(ref SoBytes bytes, JsonTypeInfo<T> typeInfo)
    {
        try
        {
            if (bytes.IsEmpty)
            {
                throw new SourceOrreryException("internal", "the native library returned an empty document");
            }
            return JsonSerializer.Deserialize(bytes.AsSpan(), typeInfo)
                ?? throw new SourceOrreryException("internal", "the native library returned a null document");
        }
        catch (JsonException ex)
        {
            throw new SourceOrreryException("internal", $"cannot read the native library's response: {ex.Message}", ex);
        }
        finally
        {
            NativeMethods.so_bytes_free(ref bytes);
        }
    }

    /// <summary>Serialise a request document for the library.</summary>
    public static Utf8Arg ToJson<T>(T? value, JsonTypeInfo<T> typeInfo)
        where T : class
    {
        return value is null ? default : new Utf8Arg(JsonSerializer.Serialize(value, typeInfo));
    }

    /// <summary>
    /// A UTF-8 argument for the ABI. The bytes carry one trailing <c>0</c>
    /// that is not counted in <see cref="Length"/>, so an empty string still
    /// pins to a non-null address and reaches the library as "present but
    /// empty" rather than "absent". A null string is the absent argument
    /// (<c>NULL</c>, 0).
    /// </summary>
    public readonly struct Utf8Arg
    {
        private readonly byte[]? bytes;

        public Utf8Arg(string? text)
        {
            if (text is null)
            {
                bytes = null;
                return;
            }
            var count = Encoding.UTF8.GetByteCount(text);
            bytes = new byte[count + 1];
            Encoding.UTF8.GetBytes(text, bytes);
        }

        /// <summary>The array to pin; null for the absent argument.</summary>
        public byte[]? Bytes => bytes;

        /// <summary>Length of the UTF-8 text, excluding the trailing <c>0</c>.</summary>
        public nuint Length => bytes is null ? 0 : (nuint)(bytes.Length - 1);

        /// <summary>Zeroise the buffer (for passphrases and values).</summary>
        public void Wipe()
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }
}
