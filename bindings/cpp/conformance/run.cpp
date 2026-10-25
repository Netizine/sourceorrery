// Conformance runner for the C++ SDK (tests/conformance/sdk/README.md):
// one scenario per invocation, observations as key<TAB>value lines.
// Metadata is printed as the core's JSON; the harness derives the fields.
//
//   run <op> [key=value ...]
#define _CRT_SECURE_NO_WARNINGS 1 // std::getenv on MSVC
#include <cstdlib>
#include <iostream>
#include <map>
#include <optional>
#include <string>

#include "sourceorrery.hpp"

namespace so = sourceorrery;

static void line(const std::string& key, const std::string& value) { std::cout << key << '\t' << value << '\n'; }

static void secret_lines(const so::Secret& secret) {
    line("value", secret.value.text());
    line("properties_json", secret.properties_json);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: run <op> [key=value ...]\n";
        return 2;
    }
    const std::string op = argv[1];
    std::map<std::string, std::string> kv;
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto eq = arg.find('=');
        if (eq != std::string::npos) kv[arg.substr(0, eq)] = arg.substr(eq + 1);
    }
    auto get = [&](const char* key) -> std::optional<std::string> {
        auto it = kv.find(key);
        return it == kv.end() ? std::nullopt : std::optional<std::string>(it->second);
    };
    std::string vault = get("vault").value_or("");
    if (vault.empty()) {
        const char* env = std::getenv("SOURCEORRERY_TEST_VAULT");
        vault = env == nullptr ? "development" : env;
    }
    so::OpenOptions options;
    options.home = get("home");
    options.recovery_key = get("recovery_key");
    options.recovery_key_file = get("recovery_key_file");
    options.environment = get("environment") != std::optional<std::string>("false");

    try {
        if (op == "load") {
            auto project = so::Project::load(get("manifest"), options);
            line("outcome", "ok");
            line("project.name", project.name());
            line("project.count", std::to_string(project.size()));
            size_t i = 0;
            for (const auto& secret : project.secrets()) {
                line("entry." + std::to_string(i) + ".json", secret.entry_json);
                line("entry." + std::to_string(i) + ".value", secret.value.text());
                ++i;
            }
            return 0;
        }
        auto reader = so::Reader::open(vault, options);
        if (op == "open") {
            line("outcome", "ok");
            line("descriptor_json", reader.descriptor_json());
        } else if (op == "get") {
            auto secret = get("version") ? reader.get(*get("name"), *get("version")) : reader.get(*get("name"));
            line("outcome", "ok");
            secret_lines(secret);
        } else if (op == "get-newest-explicit") {
            const auto newest = so::json_string_field(reader.properties_json(*get("name")), "version").value_or("");
            auto secret = reader.get(*get("name"), newest);
            line("outcome", "ok");
            secret_lines(secret);
        } else if (op == "properties") {
            auto json = get("version") ? reader.properties_json(*get("name"), *get("version")) : reader.properties_json(*get("name"));
            line("outcome", "ok");
            line("properties_json", json);
        } else if (op == "resolve") {
            auto secret = reader.resolve(*get("reference"));
            line("outcome", "ok");
            secret_lines(secret);
        } else {
            std::cerr << "unknown scenario op '" << op << "'\n";
            return 2;
        }
    } catch (const so::Error& err) {
        line("outcome", "error");
        line("code", err.code());
        line("message", err.message());
        line("hint", err.hint());
        line("transient", err.transient() ? "true" : "false");
        line("type", typeid(err).name());
    }
    return 0;
}
