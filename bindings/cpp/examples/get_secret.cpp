/*
 * Read one secret and report its size, never its value.
 *
 * Build against the C header and the shared library (see bindings/cpp/README.md):
 *   c++ -std=c++17 -I bindings/cpp/include -I crates/sourceorrery-ffi/include
 *       bindings/cpp/examples/get_secret.cpp -L target/release -lsourceorrery_ffi -o get_secret
 *   get_secret [VAULT] [SECRET]
 */
#include <cstdio>
#include <iostream>

#include "sourceorrery.hpp"

int main(int argc, char** argv) {
    const std::string vault = argc > 1 ? argv[1] : "development";
    const std::string name = argc > 2 ? argv[2] : "database-password";
    try {
        // Unlocked by the OS credential store, then SOURCEORRERY_PASSPHRASE,
        // then SOURCEORRERY_PASSPHRASE_FILE; never a prompt.
        auto reader = sourceorrery::Reader::open(vault);
        auto secret = reader.get(name);  // newest accessible version
        std::cout << name << " version " << secret.version() << " from vault " << vault << ": "
                  << secret.value.size() << " bytes\n";
        return 0;  // `secret.value` is zeroised here
    } catch (const sourceorrery::Error& err) {
        // err.code() is stable; what() is the message plus a hint. No values.
        std::cerr << "error [" << err.code() << "]: " << err.what() << '\n';
        return 1;
    }
}
