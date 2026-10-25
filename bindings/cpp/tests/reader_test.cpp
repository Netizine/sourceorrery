// The C++ SDK against the vault created by scripts/ci/fixture-vault.sh.
// Plain assertions: exits non-zero on the first failure.
#define _CRT_SECURE_NO_WARNINGS 1 // std::getenv on MSVC
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "sourceorrery.hpp"

namespace so = sourceorrery;

static int failures = 0;

#define CHECK(cond)                                                                        \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::cerr << __FILE__ << ':' << __LINE__ << ": CHECK failed: " #cond << '\n'; \
            ++failures;                                                                    \
        }                                                                                  \
    } while (0)

template <typename E, typename F>
static void expect_throw(F&& f, const char* code, const std::string& hint_contains = "") {
    try {
        f();
        std::cerr << "expected " << code << " to be thrown\n";
        ++failures;
    } catch (const so::Error& err) {
        if (dynamic_cast<const E*>(&err) == nullptr) {
            std::cerr << "wrong error class for " << err.code() << ": " << err.what() << '\n';
            ++failures;
            return;
        }
        CHECK(err.code() == code);
        if (!hint_contains.empty()) CHECK(err.hint().find(hint_contains) != std::string::npos);
    }
}

static std::string env(const char* name) {
    const char* value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

int main() {
    // An SDK refuses a library built for another C ABI version with a typed
    // error (ADR 0007); the installed library matches.
    CHECK(so_abi_version() == SO_ABI_VERSION);
    CHECK(!so::detail::abi_mismatch(SO_ABI_VERSION).has_value());
    {
        auto mismatch = so::detail::abi_mismatch(SO_ABI_VERSION + 1);
        CHECK(mismatch.has_value());
        CHECK(mismatch->code() == "abi_mismatch");
        CHECK(std::string(mismatch->what()).find(std::to_string(SO_ABI_VERSION + 1)) != std::string::npos);
    }

    const std::string home = env("SOURCEORRERY_HOME");
    const std::string recovery_key = env("SOURCEORRERY_RECOVERY_KEY");
    const std::string vault = env("SOURCEORRERY_TEST_VAULT");
    const std::string manifest = env("SOURCEORRERY_TEST_MANIFEST");
    const std::string old_version = env("SOURCEORRERY_TEST_OLD_VERSION");
    if (home.empty() || vault.empty() || manifest.empty() || old_version.empty()) {
        std::cerr << "run scripts/ci/fixture-vault.sh first\n";
        return 2;
    }
    const std::string latest = "ci-secret-value";
    const std::string first = "first-version";

    CHECK(so::contract_version() == "2");

    // Unlocked through SOURCEORRERY_RECOVERY_KEY from the environment.
    auto reader = so::Reader::open(vault);
    CHECK(reader.vault_name() == vault);
    {
        auto secret = reader.get("database-password");
        CHECK(secret.value.text() == latest);
        CHECK(secret.value.view() == latest);
        CHECK(secret.value.size() == latest.size());
        CHECK(secret.name() == "database-password");
        CHECK(so::json_string_field(secret.properties_json, "vault") == vault);
        CHECK(so::json_string_field(secret.properties_json, "content_type") == std::string("text/plain"));
        CHECK(secret.properties_json.find(latest) == std::string::npos);
        secret.value.close();
        CHECK(secret.value.closed());
        CHECK(secret.value.size() == 0);
    }
    {
        auto old = reader.get("database-password", old_version);
        CHECK(old.value.text() == first);
        CHECK(old.version() == old_version);
        CHECK(so::json_string_field(reader.properties_json("database-password", old_version), "version") == old_version);
        CHECK(so::json_string_field(reader.properties_json("database-password"), "version") != old_version);
    }
    {
        CHECK(reader.resolve("sourceorrery://" + vault + "/database-password").value.text() == latest);
        CHECK(reader.resolve("sourceorrery://" + vault + "/database-password/" + old_version).value.text() == first);
        expect_throw<so::InvalidArgumentError>([&] { reader.resolve("sourceorrery://other-vault/database-password"); }, "invalid_argument");
        expect_throw<so::InvalidArgumentError>([&] { reader.resolve("not-a-reference"); }, "invalid_argument");
    }
    {
        CHECK(reader.get("rotated-key").value.text() == "old");
        const std::string newest = so::json_string_field(reader.properties_json("rotated-key"), "version").value_or("");
        CHECK(reader.properties_json("rotated-key").find("\"enabled\":false") != std::string::npos);
        expect_throw<so::PolicyError>([&] { reader.get("rotated-key", newest); }, "disabled", "--enable");
        expect_throw<so::PolicyError>([&] { reader.get("expired-token"); }, "expired", "Policy");
        expect_throw<so::PolicyError>([&] { reader.get("future-token"); }, "not_yet_valid");
        try { reader.get("future-token"); } catch (const so::Error& err) { CHECK(err.transient()); CHECK(err.policy()); }
        expect_throw<so::SecretDeletedError>([&] { reader.get("deleted-secret"); }, "deleted", "secret recover deleted-secret");
    }
    {
        expect_throw<so::SecretNotFoundError>([&] { reader.get("missing"); }, "not_found", "sourceorrery secret set missing --vault " + vault);
        try { reader.get("missing"); } catch (const so::Error& err) {
            CHECK(err.message() == "secret 'missing' was not found");
            CHECK(std::string(err.what()).rfind(err.message() + ". ", 0) == 0);
            CHECK(err.kind() == so::ErrorKind::NotFound);
        }
        expect_throw<so::SecretNotFoundError>([&] { reader.get("database-password", "deadbeef"); }, "version_not_found", "secret versions database-password");
        expect_throw<so::InvalidArgumentError>([&] { reader.get("bad_name"); }, "invalid_name");
    }
    {
        expect_throw<so::VaultNotFoundError>([] { so::Reader::open("no-such-vault"); }, "vault_not_found", "sourceorrery vault create no-such-vault");
        so::OpenOptions wrong;
        wrong.recovery_key = "wrong-recovery-key";
        wrong.environment = false;
        expect_throw<so::VaultLockedError>([&] { so::Reader::open(vault, wrong); }, "locked", "recovery_key option: tried");
        try { so::Reader::open(vault, wrong); } catch (const so::Error& err) {
            CHECK(err.hint().find("SOURCEORRERY_RECOVERY_KEY: not set") != std::string::npos);
            CHECK(std::string(err.what()).find("wrong-recovery-key") == std::string::npos);
        }
        so::OpenOptions explicit_options;
        explicit_options.home = home;
        explicit_options.recovery_key = recovery_key;
        explicit_options.environment = false;
        auto other = so::Reader::open(vault, explicit_options);
        CHECK(so::json_string_field(other.descriptor_json(), "name") == vault);
        CHECK(other.descriptor_json().find("\"recovery\"") != std::string::npos);
        other.close();
        CHECK(other.closed());
        expect_throw<so::Error>([&] { other.get("database-password"); }, "invalid_argument");
        other.close();
    }
    {
        std::vector<std::thread> workers;
        std::vector<int> thread_failures(4, 0);
        for (int t = 0; t < 4; ++t) {
            workers.emplace_back([&, t] {
                for (int i = 0; i < 5; ++i) {
                    if (reader.get("database-password").value.text() != latest) ++thread_failures[t];
                }
                try { reader.get("missing"); ++thread_failures[t]; } catch (const so::SecretNotFoundError&) {}
            });
        }
        for (auto& w : workers) w.join();
        for (int f : thread_failures) CHECK(f == 0);
    }
    {
        auto project = so::Project::load(manifest);
        CHECK(project.name() == "ci-project");
        CHECK(project.manifest_path().find("sourceorrery.toml") != std::string::npos);
        CHECK(project.size() == 2);
        CHECK(project.env("DATABASE_PASSWORD") != nullptr && project.env("DATABASE_PASSWORD")->text() == latest);
        CHECK(project.env("ROTATED") != nullptr && project.env("ROTATED")->text() == "old");
        CHECK(project.get("missing-optional") == nullptr);
        CHECK(project.get("expired-token") == nullptr);
        const auto* entry = project.get("rotated-key");
        CHECK(entry != nullptr && entry->required && entry->env == "ROTATED");
        CHECK(entry != nullptr && entry->reference == "sourceorrery://" + vault + "/rotated-key");
        project.close();
        CHECK(project.env("ROTATED")->closed());
        expect_throw<so::ManifestError>([&] { so::Project::load(manifest + ".missing"); }, "manifest");
        so::OpenOptions wrong;
        wrong.recovery_key = recovery_key + "-wrong";
        wrong.environment = false;
        expect_throw<so::VaultLockedError>([&] { so::Project::load(manifest, wrong); }, "locked");
    }

    {
        // The remote provider codes have their own kinds and classes.
        CHECK(so::kind_for_code("unauthenticated") == so::ErrorKind::Unauthenticated);
        CHECK(so::kind_for_code("provider_unavailable") == so::ErrorKind::ProviderUnavailable);
        const so::UnauthenticatedError unauthenticated("unauthenticated", "m", "h");
        CHECK(!unauthenticated.transient());
        CHECK(!unauthenticated.policy());
        const so::ProviderUnavailableError unavailable("provider_unavailable", "m", "h");
        CHECK(unavailable.transient());
        CHECK(!unavailable.policy());
        CHECK(std::string(unavailable.what()) == "m. h");
    }

    if (failures != 0) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "C++ SDK: all checks passed\n";
    return 0;
}
