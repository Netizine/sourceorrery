using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SourceOrrery.Json;
using SourceOrrery.Native;

namespace SourceOrrery;

/// <summary>
/// An unlocked SourceOrrery vault with the <c>SecretClient</c> contract of
/// the Rust core: immutable versions, policy on retrieval, soft delete with
/// recovery and purge, and a metadata-only audit trail. One instance may be
/// used from several threads at once. Dispose it to lock the vault and
/// zeroise the key held in memory.
/// </summary>
public sealed unsafe class SecretClient : IDisposable
{
    private static SourceOrreryJsonContext Json => SourceOrreryJsonContext.Default;

    private readonly VaultHandle handle;

    /// <summary>
    /// Open and unlock <paramref name="vaultName"/>. The OS credential store
    /// is tried first; if it cannot unlock the vault, <paramref name="passphrase"/>
    /// is tried once. With a null passphrase the call fails with
    /// <see cref="VaultLockedException"/> when the credential store cannot
    /// unlock the vault. Failed unlock attempts are audited.
    /// </summary>
    public SecretClient(string vaultName, string? passphrase = null, SecretClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(vaultName);
        Interop.EnsureCompatible();
        var home = new Interop.Utf8Arg(options?.Home);
        var name = new Interop.Utf8Arg(vaultName);
        var pass = new Interop.Utf8Arg(passphrase);
        try
        {
            nint raw;
            fixed (byte* homePtr = home.Bytes)
            fixed (byte* namePtr = name.Bytes)
            fixed (byte* passPtr = pass.Bytes)
            {
                Interop.Check(NativeMethods.so_vault_open(
                    homePtr, home.Length,
                    namePtr, name.Length,
                    passPtr, pass.Length,
                    out raw));
            }
            handle = new VaultHandle(raw);
        }
        finally
        {
            pass.Wipe();
        }
        VaultName = vaultName;
    }

    private SecretClient(VaultHandle handle, string vaultName)
    {
        this.handle = handle;
        VaultName = vaultName;
    }

    /// <summary>Name of the vault this client is bound to.</summary>
    public string VaultName { get; }

    /// <summary>True once <see cref="Dispose"/> has run.</summary>
    public bool IsClosed => handle.IsClosed;

    /// <summary>
    /// Create a vault and return an open client for it. With a passphrase the
    /// vault gets a passphrase protector; with null it gets an OS-keyring
    /// protector (<c>unsupported</c> where no credential store is available).
    /// An empty passphrase is rejected.
    /// </summary>
    public static SecretClient CreateVault(string vaultName, string? passphrase = null, VaultCreateOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(vaultName);
        Interop.EnsureCompatible();
        var home = new Interop.Utf8Arg(options?.Home);
        var name = new Interop.Utf8Arg(vaultName);
        var optionsJson = Interop.ToJson(options, Json.VaultCreateOptions);
        var pass = new Interop.Utf8Arg(passphrase);
        try
        {
            nint raw;
            fixed (byte* homePtr = home.Bytes)
            fixed (byte* namePtr = name.Bytes)
            fixed (byte* optionsPtr = optionsJson.Bytes)
            fixed (byte* passPtr = pass.Bytes)
            {
                Interop.Check(NativeMethods.so_vault_create(
                    homePtr, home.Length,
                    namePtr, name.Length,
                    optionsPtr, optionsJson.Length,
                    passPtr, pass.Length,
                    out raw));
            }
            return new SecretClient(new VaultHandle(raw), vaultName);
        }
        finally
        {
            pass.Wipe();
        }
    }

    /// <summary>Non-sensitive description of the vault: name, id, backend, path, protectors.</summary>
    public VaultDescriptor GetVaultDescriptor()
    {
        SoBytes json = default;
        Interop.Check(NativeMethods.so_vault_descriptor(handle, ref json));
        return Interop.TakeJson(ref json, Json.VaultDescriptor);
    }

    /// <summary>
    /// Create a new immutable version of <paramref name="name"/> holding
    /// <paramref name="value"/>. The bytes are copied; the native copy is
    /// zeroised before the call returns. Clear your own buffer afterwards.
    /// </summary>
    public SecretProperties SetSecret(string name, ReadOnlySpan<byte> value, SetSecretOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameArg = new Interop.Utf8Arg(name);
        var optionsJson = Interop.ToJson(options, Json.SetSecretOptions);
        SoBytes props = default;
        fixed (byte* namePtr = nameArg.Bytes)
        fixed (byte* valuePtr = value)
        fixed (byte* optionsPtr = optionsJson.Bytes)
        {
            Interop.Check(NativeMethods.so_secret_set(
                handle,
                namePtr, nameArg.Length,
                valuePtr, (nuint)value.Length,
                optionsPtr, optionsJson.Length,
                ref props));
        }
        return Interop.TakeJson(ref props, Json.SecretProperties);
    }

    /// <summary>
    /// Create a new version holding the UTF-8 encoding of <paramref name="value"/>.
    /// The encoded buffer is zeroised after the call; the string itself
    /// cannot be, so prefer the byte overload for values you control.
    /// </summary>
    public SecretProperties SetSecret(string name, string value, SetSecretOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(value);
        var bytes = Encoding.UTF8.GetBytes(value);
        try
        {
            return SetSecret(name, bytes, options);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Retrieve a version's value and metadata. A null <paramref name="version"/>
    /// selects the newest accessible version (enabled and inside its time
    /// window); an explicit version must itself be accessible. Policy
    /// refusals are <see cref="SecretPolicyException"/>. Dispose the result
    /// as soon as the value has been used.
    /// </summary>
    public Secret GetSecret(string name, string? version = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameArg = new Interop.Utf8Arg(name);
        var versionArg = new Interop.Utf8Arg(version);
        SoBytes props = default;
        SoBytes value = default;
        fixed (byte* namePtr = nameArg.Bytes)
        fixed (byte* versionPtr = versionArg.Bytes)
        {
            Interop.Check(NativeMethods.so_secret_get(
                handle,
                namePtr, nameArg.Length,
                versionPtr, versionArg.Length,
                ref props,
                ref value));
        }
        try
        {
            var properties = Interop.TakeJson(ref props, Json.SecretProperties);
            return new Secret(properties, new SecretValue(value));
        }
        catch
        {
            NativeMethods.so_bytes_free(ref value);
            throw;
        }
    }

    /// <summary>Metadata only. Policy is not applied, so disabled and expired versions can be inspected.</summary>
    public SecretProperties GetSecretProperties(string name, string? version = null)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameArg = new Interop.Utf8Arg(name);
        var versionArg = new Interop.Utf8Arg(version);
        SoBytes props = default;
        fixed (byte* namePtr = nameArg.Bytes)
        fixed (byte* versionPtr = versionArg.Bytes)
        {
            Interop.Check(NativeMethods.so_secret_get_properties(
                handle,
                namePtr, nameArg.Length,
                versionPtr, versionArg.Length,
                ref props));
        }
        return Interop.TakeJson(ref props, Json.SecretProperties);
    }

    /// <summary>Metadata of the newest version of every live secret.</summary>
    public IReadOnlyList<SecretProperties> ListPropertiesOfSecrets()
    {
        SoBytes json = default;
        Interop.Check(NativeMethods.so_secret_list(handle, ref json));
        return Interop.TakeJson(ref json, Json.ListSecretProperties);
    }

    /// <summary>Metadata of every version of <paramref name="name"/>, newest first.</summary>
    public IReadOnlyList<SecretProperties> ListPropertiesOfSecretVersions(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameArg = new Interop.Utf8Arg(name);
        SoBytes json = default;
        fixed (byte* namePtr = nameArg.Bytes)
        {
            Interop.Check(NativeMethods.so_secret_versions(handle, namePtr, nameArg.Length, ref json));
        }
        return Interop.TakeJson(ref json, Json.ListSecretProperties);
    }

    /// <summary>
    /// Change the metadata of one version, never its value. A null
    /// <paramref name="version"/> selects the newest. An update that changes
    /// nothing is rejected with <c>invalid_argument</c>.
    /// </summary>
    public SecretProperties UpdateSecretProperties(string name, string? version, UpdateSecretProperties update)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(update);
        var nameArg = new Interop.Utf8Arg(name);
        var versionArg = new Interop.Utf8Arg(version);
        var updateJson = Interop.ToJson(update, Json.UpdateSecretProperties);
        SoBytes props = default;
        fixed (byte* namePtr = nameArg.Bytes)
        fixed (byte* versionPtr = versionArg.Bytes)
        fixed (byte* updatePtr = updateJson.Bytes)
        {
            Interop.Check(NativeMethods.so_secret_update(
                handle,
                namePtr, nameArg.Length,
                versionPtr, versionArg.Length,
                updatePtr, updateJson.Length,
                ref props));
        }
        return Interop.TakeJson(ref props, Json.SecretProperties);
    }

    /// <summary>Soft-delete all versions of <paramref name="name"/>. In a purgeable vault deletion is immediate.</summary>
    public DeletedSecret DeleteSecret(string name)
    {
        return Named(name, &NativeMethods.so_secret_delete, Json.DeletedSecret);
    }

    /// <summary>Inspect a soft-deleted secret.</summary>
    public DeletedSecret GetDeletedSecret(string name)
    {
        return Named(name, &NativeMethods.so_secret_get_deleted, Json.DeletedSecret);
    }

    /// <summary>All soft-deleted secrets.</summary>
    public IReadOnlyList<DeletedSecret> ListDeletedSecrets()
    {
        SoBytes json = default;
        Interop.Check(NativeMethods.so_secret_list_deleted(handle, ref json));
        return Interop.TakeJson(ref json, Json.ListDeletedSecret);
    }

    /// <summary>Undo a soft delete; returns the properties of the newest restored version.</summary>
    public SecretProperties RecoverDeletedSecret(string name)
    {
        return Named(name, &NativeMethods.so_secret_recover, Json.SecretProperties);
    }

    /// <summary>Permanently remove a soft-deleted secret. <c>not_deleted</c> for a live secret, <c>not_found</c> for an unknown one.</summary>
    public void PurgeDeletedSecret(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameArg = new Interop.Utf8Arg(name);
        fixed (byte* namePtr = nameArg.Bytes)
        {
            Interop.Check(NativeMethods.so_secret_purge(handle, namePtr, nameArg.Length));
        }
    }

    /// <summary>The metadata-only audit trail, newest first. A null query returns the newest 1000 events.</summary>
    public IReadOnlyList<AuditEvent> GetAuditEvents(AuditQuery? query = null)
    {
        var queryJson = Interop.ToJson(query, Json.AuditQuery);
        SoBytes json = default;
        fixed (byte* queryPtr = queryJson.Bytes)
        {
            Interop.Check(NativeMethods.so_audit_events(handle, queryPtr, queryJson.Length, ref json));
        }
        return Interop.TakeJson(ref json, Json.ListAuditEvent);
    }

    /// <summary>Lock the vault: the key held in memory is zeroised once no call is in progress. Idempotent.</summary>
    public void Dispose()
    {
        handle.Dispose();
    }

    /// <inheritdoc />
    public override string ToString()
    {
        return $"SecretClient(vault='{VaultName}')";
    }

    /// <summary>Call a <c>(handle, name, out)</c> shaped function.</summary>
    private T Named<T>(
        string name,
        delegate*<VaultHandle, byte*, nuint, ref SoBytes, int> call,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo)
    {
        ArgumentNullException.ThrowIfNull(name);
        var nameArg = new Interop.Utf8Arg(name);
        SoBytes json = default;
        fixed (byte* namePtr = nameArg.Bytes)
        {
            Interop.Check(call(handle, namePtr, nameArg.Length, ref json));
        }
        return Interop.TakeJson(ref json, typeInfo);
    }
}
