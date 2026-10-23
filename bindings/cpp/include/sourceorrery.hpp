// SourceOrrery C++ SDK: a header-only RAII wrapper over the read-only part
// of the C ABI (sourceorrery.h). Requires C++17.
//
//   #include <sourceorrery.hpp>
//   auto reader = sourceorrery::Reader::open("development");
//   auto secret = reader.get("database-password");
//   connect(secret.value.text());          // the value is zeroised when `secret` dies
//
// Only so_reader_* / so_project_* functions are used, so a program built on
// this header cannot write to a vault. Every failure is a
// sourceorrery::Error (or a subclass chosen by the stable code) carrying
// code(), what() and hint(); none of them ever contains a value.
//
// Licensed under MIT OR Apache-2.0.
#ifndef SOURCEORRERY_HPP
#define SOURCEORRERY_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sourceorrery.h"

namespace sourceorrery {

/// Category of an Error, one per stable code.
enum class ErrorKind {
    NotFound,
    VersionNotFound,
    Deleted,
    Disabled,
    NotYetValid,
    Expired,
    InvalidName,
    InvalidArgument,
    PermissionDenied,
    Locked,
    VaultNotFound,
    MigrationRequired,
    VaultMismatch,
    Manifest,
    Crypto,
    Storage,
    Io,
    Unsupported,
    Unauthenticated,
    ProviderUnavailable,
    Internal,
    Other,
};

inline ErrorKind kind_for_code(std::string_view code) noexcept {
    if (code == "not_found") return ErrorKind::NotFound;
    if (code == "version_not_found") return ErrorKind::VersionNotFound;
    if (code == "deleted") return ErrorKind::Deleted;
    if (code == "disabled") return ErrorKind::Disabled;
    if (code == "not_yet_valid") return ErrorKind::NotYetValid;
    if (code == "expired") return ErrorKind::Expired;
    if (code == "invalid_name") return ErrorKind::InvalidName;
    if (code == "invalid_argument") return ErrorKind::InvalidArgument;
    if (code == "permission_denied") return ErrorKind::PermissionDenied;
    if (code == "locked") return ErrorKind::Locked;
    if (code == "vault_not_found") return ErrorKind::VaultNotFound;
    if (code == "migration_required") return ErrorKind::MigrationRequired;
    if (code == "vault_mismatch") return ErrorKind::VaultMismatch;
    if (code == "manifest") return ErrorKind::Manifest;
    if (code == "crypto") return ErrorKind::Crypto;
    if (code == "storage") return ErrorKind::Storage;
    if (code == "io") return ErrorKind::Io;
    if (code == "unsupported") return ErrorKind::Unsupported;
    if (code == "unauthenticated") return ErrorKind::Unauthenticated;
    if (code == "provider_unavailable") return ErrorKind::ProviderUnavailable;
    if (code == "internal") return ErrorKind::Internal;
    return ErrorKind::Other;
}

/// A failed call. what() is "<message>. <hint>" (or just the message).
class Error : public std::runtime_error {
public:
    Error(std::string code, std::string message, std::string hint)
        : std::runtime_error(hint.empty() ? message : message + ". " + hint),
          code_(std::move(code)),
          message_(std::move(message)),
          hint_(std::move(hint)),
          kind_(kind_for_code(code_)) {}

    /// Stable, append-only code (`not_found`, `locked`, ...).
    const std::string& code() const noexcept { return code_; }
    /// What went wrong, without the hint.
    const std::string& message() const noexcept { return message_; }
    /// What to do about it; empty when nothing specific applies.
    const std::string& hint() const noexcept { return hint_; }
    ErrorKind kind() const noexcept { return kind_; }
    /// True when retrying later could succeed without administrative action:
    /// `not_yet_valid` and `provider_unavailable`.
    bool transient() const noexcept {
        return kind_ == ErrorKind::NotYetValid || kind_ == ErrorKind::ProviderUnavailable;
    }
    /// True for `disabled`, `not_yet_valid` and `expired`.
    bool policy() const noexcept {
        return kind_ == ErrorKind::Disabled || kind_ == ErrorKind::NotYetValid ||
               kind_ == ErrorKind::Expired;
    }

private:
    std::string code_;
    std::string message_;
    std::string hint_;
    ErrorKind kind_;
};

/// `vault_not_found`.
class VaultNotFoundError : public Error { using Error::Error; };
/// `locked`.
class VaultLockedError : public Error { using Error::Error; };
/// `migration_required`.
class MigrationRequiredError : public Error { using Error::Error; };
/// `vault_mismatch`: the file found for the vault holds another vault.
class VaultMismatchError : public Error { using Error::Error; };
/// `not_found` and `version_not_found`.
class SecretNotFoundError : public Error { using Error::Error; };
/// `deleted`.
class SecretDeletedError : public Error { using Error::Error; };
/// `disabled`, `not_yet_valid`, `expired`.
class PolicyError : public Error { using Error::Error; };
/// `crypto`.
class IntegrityError : public Error { using Error::Error; };
/// `unsupported`: this platform or build lacks what the operation needs (an
/// OS credential store, a remote provider).
class UnsupportedError : public Error { using Error::Error; };
/// `unauthenticated`: the remote provider has no credentials for this
/// process, or they expired; they come from the provider's own environment,
/// never from the manifest.
class UnauthenticatedError : public Error { using Error::Error; };
/// `provider_unavailable`: the remote provider could not be reached or
/// answered with a server error. Transient.
class ProviderUnavailableError : public Error { using Error::Error; };
/// `invalid_argument`, `invalid_name`.
class InvalidArgumentError : public Error { using Error::Error; };
/// `manifest`.
class ManifestError : public Error { using Error::Error; };

namespace detail {

inline std::string c_string(const char* text) { return text == nullptr ? std::string() : std::string(text); }

/// Throw the error of the last call on this thread, as the subclass for
/// its code. `status` is the value the call returned.
[[noreturn]] inline void throw_last_error(so_status status) {
    std::string code = c_string(so_last_error_code());
    std::string message = c_string(so_last_error_message());
    std::string hint = c_string(so_last_error_hint());
    if (code.empty()) {
        code = status == SO_STATUS_PANIC ? "internal" : "unknown";
    }
    switch (kind_for_code(code)) {
    case ErrorKind::VaultNotFound: throw VaultNotFoundError(code, message, hint);
    case ErrorKind::Locked: throw VaultLockedError(code, message, hint);
    case ErrorKind::MigrationRequired: throw MigrationRequiredError(code, message, hint);
    case ErrorKind::VaultMismatch: throw VaultMismatchError(code, message, hint);
    case ErrorKind::NotFound:
    case ErrorKind::VersionNotFound: throw SecretNotFoundError(code, message, hint);
    case ErrorKind::Deleted: throw SecretDeletedError(code, message, hint);
    case ErrorKind::Disabled:
    case ErrorKind::NotYetValid:
    case ErrorKind::Expired: throw PolicyError(code, message, hint);
    case ErrorKind::Crypto: throw IntegrityError(code, message, hint);
    case ErrorKind::Unsupported: throw UnsupportedError(code, message, hint);
    case ErrorKind::Unauthenticated: throw UnauthenticatedError(code, message, hint);
    case ErrorKind::ProviderUnavailable: throw ProviderUnavailableError(code, message, hint);
    case ErrorKind::InvalidArgument:
    case ErrorKind::InvalidName: throw InvalidArgumentError(code, message, hint);
    case ErrorKind::Manifest: throw ManifestError(code, message, hint);
    default: throw Error(code, message, hint);
    }
}

inline void check(so_status status) {
    if (status != SO_STATUS_OK) throw_last_error(status);
}

/// The error for a library whose C ABI version is `found`, or none when it
/// matches the `SO_ABI_VERSION` of the header this SDK was compiled
/// against. Its code, `abi_mismatch`, is produced by the SDK itself, never
/// by the core (ADR 0007).
inline std::optional<Error> abi_mismatch(uint32_t found) {
    if (found == SO_ABI_VERSION) return std::nullopt;
    return Error("abi_mismatch",
                 "the SourceOrrery native library implements C ABI version " + std::to_string(found) +
                     "; this SDK was built for version " + std::to_string(SO_ABI_VERSION),
                 "install the sourceorrery-ffi library of the release this SDK version belongs to");
}

/// Refuse a library built for another C ABI version before anything is opened.
inline void require_abi() {
    if (auto err = abi_mismatch(so_abi_version())) throw *err;
}

inline const uint8_t* ptr(std::string_view text) noexcept {
    return text.empty() ? nullptr : reinterpret_cast<const uint8_t*>(text.data());
}

inline const uint8_t* opt_ptr(const std::optional<std::string>& text) noexcept {
    return text ? ptr(*text) : nullptr;
}

inline size_t opt_len(const std::optional<std::string>& text) noexcept { return text ? text->size() : 0; }

/// Escape a string for a JSON document.
inline std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 2);
    out.push_back('"');
    for (char c : text) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
                out += buf;
            } else {
                out.push_back(c);
            }
        }
    }
    out.push_back('"');
    return out;
}

/// A caller-owned buffer, zeroised and freed on destruction.
class Buffer {
public:
    Buffer() noexcept : bytes_{nullptr, 0} {}
    ~Buffer() { so_bytes_free(&bytes_); }
    Buffer(Buffer&& other) noexcept : bytes_(other.bytes_) { other.bytes_ = so_bytes{nullptr, 0}; }
    Buffer& operator=(Buffer&& other) noexcept {
        if (this != &other) {
            so_bytes_free(&bytes_);
            bytes_ = other.bytes_;
            other.bytes_ = so_bytes{nullptr, 0};
        }
        return *this;
    }
    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    so_bytes* slot() noexcept { return &bytes_; }
    const uint8_t* data() const noexcept { return bytes_.ptr; }
    size_t size() const noexcept { return bytes_.len; }
    bool empty() const noexcept { return bytes_.ptr == nullptr; }
    std::string_view view() const noexcept {
        return bytes_.ptr == nullptr ? std::string_view()
                                     : std::string_view(reinterpret_cast<const char*>(bytes_.ptr), bytes_.len);
    }
    void clear() noexcept { so_bytes_free(&bytes_); }

private:
    so_bytes bytes_;
};

} // namespace detail

/// A secret value, zeroised when it is destroyed or closed. Movable, not
/// copyable: copy the bytes out deliberately with text() or data().
class SecretValue {
public:
    SecretValue() = default;
    SecretValue(SecretValue&&) noexcept = default;
    SecretValue& operator=(SecretValue&&) noexcept = default;
    SecretValue(const SecretValue&) = delete;
    SecretValue& operator=(const SecretValue&) = delete;

    const uint8_t* data() const noexcept { return buffer_.data(); }
    size_t size() const noexcept { return buffer_.size(); }
    bool closed() const noexcept { return buffer_.empty(); }
    /// A view of the bytes, valid until close() or destruction.
    std::string_view view() const noexcept { return buffer_.view(); }
    /// A copy of the bytes as a string. The copy is the caller's to wipe.
    std::string text() const { return std::string(buffer_.view()); }
    /// Zeroise the bytes. Idempotent.
    void close() noexcept { buffer_.clear(); }

private:
    friend class Reader;
    friend class Project;
    explicit SecretValue(detail::Buffer&& buffer) noexcept : buffer_(std::move(buffer)) {}
    detail::Buffer buffer_;
};

/// Read a top-level string field from a JSON object document (enough for
/// the flat `SecretProperties` fields such as "version" or "name"). Returns
/// nullopt when the field is absent or not a string.
inline std::optional<std::string> json_string_field(std::string_view json, std::string_view field) {
    const std::string key = detail::json_escape(field);
    size_t depth = 0;
    bool in_string = false;
    for (size_t i = 0; i < json.size(); ++i) {
        char c = json[i];
        if (in_string) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') in_string = false;
            continue;
        }
        if (c == '{' || c == '[') { ++depth; continue; }
        if (c == '}' || c == ']') { --depth; continue; }
        if (c == '"' && depth == 1 && json.compare(i, key.size(), key) == 0) {
            size_t j = i + key.size();
            while (j < json.size() && (json[j] == ' ' || json[j] == '\t' || json[j] == '\n' || json[j] == '\r')) ++j;
            if (j >= json.size() || json[j] != ':') { in_string = true; continue; }
            ++j;
            while (j < json.size() && (json[j] == ' ' || json[j] == '\t' || json[j] == '\n' || json[j] == '\r')) ++j;
            if (j >= json.size() || json[j] != '"') return std::nullopt;
            std::string out;
            for (++j; j < json.size(); ++j) {
                char d = json[j];
                if (d == '"') return out;
                if (d == '\\' && j + 1 < json.size()) {
                    char e = json[++j];
                    switch (e) {
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': out += "\\u"; break; // left encoded; names never contain escapes
                    default: out.push_back(e);
                    }
                    continue;
                }
                out.push_back(d);
            }
            return std::nullopt;
        }
        if (c == '"') in_string = true;
    }
    return std::nullopt;
}

/// A version's metadata (as the core's JSON document) and its value.
struct Secret {
    /// `SecretProperties` as JSON: vault, name, version, enabled,
    /// content_type, tags, not_before, expires_on, created_on, updated_on,
    /// recovery_level. Parse it with your JSON library, or use
    /// json_string_field() for the flat string fields.
    std::string properties_json;
    SecretValue value;

    std::string version() const { return json_string_field(properties_json, "version").value_or(""); }
    std::string name() const { return json_string_field(properties_json, "name").value_or(""); }
};

/// How to find and unlock a vault. Defaults reproduce the CLI.
struct OpenOptions {
    /// Directory holding the `vaults/` folder; nullopt honours SOURCEORRERY_HOME.
    std::optional<std::string> home;
    /// A passphrase tried before the environment sources.
    std::optional<std::string> passphrase;
    /// A file holding the passphrase; replaces SOURCEORRERY_PASSPHRASE_FILE.
    std::optional<std::string> passphrase_file;
    /// Consult SOURCEORRERY_PASSPHRASE and SOURCEORRERY_PASSPHRASE_FILE.
    bool environment = true;
    /// The sourceorrery.toml whose `[vaults.<name>]` tables say which vaults
    /// are remote and where; nullopt uses the nearest one above the current
    /// directory. A vault with a table is opened at its provider instead of
    /// as a local file. Credentials come from the provider's own
    /// environment, never from the manifest.
    std::optional<std::string> manifest;

    std::string to_json() const {
        std::string json = "{";
        if (home) json += "\"home\":" + detail::json_escape(*home) + ",";
        if (passphrase_file) json += "\"passphrase_file\":" + detail::json_escape(*passphrase_file) + ",";
        if (manifest) json += "\"manifest\":" + detail::json_escape(*manifest) + ",";
        json += std::string("\"environment\":") + (environment ? "true" : "false") + "}";
        return json;
    }
};

/// A read-only vault handle. Movable, not copyable; usable from several
/// threads at once. Closing it zeroises the vault key held in memory.
class Reader {
public:
    /// Open `vault`: OS credential store, then options.passphrase, then
    /// SOURCEORRERY_PASSPHRASE, then the passphrase file. Never prompts.
    static Reader open(std::string_view vault, const OpenOptions& options = {}) {
        detail::require_abi();
        const std::string json = options.to_json();
        so_reader* handle = nullptr;
        detail::check(so_reader_open(detail::ptr(vault), vault.size(), detail::ptr(json), json.size(),
                                     detail::opt_ptr(options.passphrase), detail::opt_len(options.passphrase),
                                     &handle));
        return Reader(handle, std::string(vault));
    }

    Reader() = default;
    ~Reader() { close(); }
    Reader(Reader&& other) noexcept : handle_(other.handle_), vault_(std::move(other.vault_)) { other.handle_ = nullptr; }
    Reader& operator=(Reader&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = other.handle_;
            vault_ = std::move(other.vault_);
            other.handle_ = nullptr;
        }
        return *this;
    }
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;

    const std::string& vault_name() const noexcept { return vault_; }
    bool closed() const noexcept { return handle_ == nullptr; }

    /// The newest accessible version of `name`, or exactly `version`.
    Secret get(std::string_view name, std::optional<std::string_view> version = std::nullopt) const {
        detail::Buffer props;
        detail::Buffer value;
        detail::check(so_reader_get(require(), detail::ptr(name), name.size(),
                                    version ? detail::ptr(*version) : nullptr, version ? version->size() : 0,
                                    props.slot(), value.slot()));
        return Secret{std::string(props.view()), SecretValue(std::move(value))};
    }

    /// Metadata only (JSON); policy is not applied.
    std::string properties_json(std::string_view name, std::optional<std::string_view> version = std::nullopt) const {
        detail::Buffer props;
        detail::check(so_reader_properties(require(), detail::ptr(name), name.size(),
                                           version ? detail::ptr(*version) : nullptr, version ? version->size() : 0,
                                           props.slot()));
        return std::string(props.view());
    }

    /// Resolve `sourceorrery://vault/name[/version]`; the vault must be this reader's.
    Secret resolve(std::string_view reference) const {
        detail::Buffer props;
        detail::Buffer value;
        detail::check(so_reader_resolve(require(), detail::ptr(reference), reference.size(), props.slot(), value.slot()));
        return Secret{std::string(props.view()), SecretValue(std::move(value))};
    }

    /// Non-sensitive description of the vault (JSON).
    std::string descriptor_json() const {
        detail::Buffer out;
        detail::check(so_reader_descriptor(require(), out.slot()));
        return std::string(out.view());
    }

    /// Release the vault. Idempotent.
    void close() noexcept {
        so_reader_close(handle_);
        handle_ = nullptr;
    }

private:
    Reader(so_reader* handle, std::string vault) noexcept : handle_(handle), vault_(std::move(vault)) {}
    const so_reader* require() const {
        if (handle_ == nullptr) throw Error("invalid_argument", "reader is closed", "");
        return handle_;
    }
    so_reader* handle_ = nullptr;
    std::string vault_;
};

/// One secret resolved from a project manifest.
struct ProjectSecret {
    std::string name;
    std::string env;
    std::string reference;
    bool required = true;
    /// The entry's `properties` and the whole entry as JSON.
    std::string entry_json;
    SecretValue value;
};

/// The secrets a sourceorrery.toml declares, resolved like `sourceorrery run`.
class Project {
public:
    /// Load `manifest` (nullopt: the nearest sourceorrery.toml above the
    /// current directory). Options apply to every vault the manifest names.
    static Project load(std::optional<std::string> manifest = std::nullopt, const OpenOptions& options = {}) {
        detail::require_abi();
        const std::string json = options.to_json();
        so_project* handle = nullptr;
        detail::check(so_project_load(detail::opt_ptr(manifest), detail::opt_len(manifest), detail::ptr(json),
                                      json.size(), detail::opt_ptr(options.passphrase),
                                      detail::opt_len(options.passphrase), &handle));
        Project project;
        detail::Buffer info;
        if (so_project_info(handle, info.slot()) != SO_STATUS_OK) {
            so_project_free(handle);
            detail::throw_last_error(SO_STATUS_ERROR);
        }
        project.name_ = json_string_field(info.view(), "name").value_or("");
        project.manifest_path_ = json_string_field(info.view(), "manifest_path").value_or("");
        const size_t count = so_project_count(handle);
        for (size_t i = 0; i < count; ++i) {
            detail::Buffer entry;
            detail::Buffer value;
            if (so_project_entry(handle, i, entry.slot(), value.slot()) != SO_STATUS_OK) {
                so_project_free(handle);
                detail::throw_last_error(SO_STATUS_ERROR);
            }
            ProjectSecret secret;
            secret.entry_json = std::string(entry.view());
            secret.name = json_string_field(secret.entry_json, "name").value_or("");
            secret.env = json_string_field(secret.entry_json, "env").value_or("");
            secret.reference = json_string_field(secret.entry_json, "reference").value_or("");
            secret.required = secret.entry_json.find("\"required\":true") != std::string::npos;
            secret.value = SecretValue(std::move(value));
            project.secrets_.push_back(std::move(secret));
        }
        so_project_free(handle);
        return project;
    }

    const std::string& name() const noexcept { return name_; }
    const std::string& manifest_path() const noexcept { return manifest_path_; }
    /// Every secret that resolved, in manifest order.
    const std::vector<ProjectSecret>& secrets() const noexcept { return secrets_; }
    size_t size() const noexcept { return secrets_.size(); }

    /// The entry declared as `[secrets.<name>]`, if it resolved.
    const ProjectSecret* get(std::string_view name) const noexcept {
        for (const auto& s : secrets_) if (s.name == name) return &s;
        return nullptr;
    }

    /// The value delivered in environment variable `env`, if any.
    const SecretValue* env(std::string_view variable) const noexcept {
        for (const auto& s : secrets_) if (s.env == variable) return &s.value;
        return nullptr;
    }

    /// Zeroise every value.
    void close() noexcept { for (auto& s : secrets_) s.value.close(); }

private:
    std::string name_;
    std::string manifest_path_;
    std::vector<ProjectSecret> secrets_;
};

/// Contract version of the core the loaded library implements.
inline std::string contract_version() { return detail::c_string(so_contract_version()); }

} // namespace sourceorrery

#endif // SOURCEORRERY_HPP
