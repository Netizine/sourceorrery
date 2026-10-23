# SourceOrrery C++ SDK

A header-only RAII wrapper (C++17) over the read-only part of the C ABI.

```cpp
#include <sourceorrery.hpp>

auto reader = sourceorrery::Reader::open("development");
auto secret = reader.get("database-password");
connect(secret.value.text());   // zeroised when `secret` goes out of scope
```

`OpenOptions::manifest` names the `sourceorrery.toml` whose
`[vaults.<name>]` tables say which vaults are remote and at which provider
(default: the nearest one above the current directory); a vault with such a
table is opened at its provider instead of as a local file, and
`UnauthenticatedError` / `ProviderUnavailableError` (transient) report its
failures. Credentials come from the provider's own environment, never from
the manifest: HashiCorp Vault is the first provider, and its credential
comes from `VAULT_TOKEN` or the other sources
[the provider documents](../../docs/providers/hashicorp-vault.md).

Take `include/sourceorrery.hpp` and `crates/sourceorrery-ffi/include/sourceorrery.h`
(both ship in the `sourceorrery-ffi-<version>-<target>` release archive next
to the shared library) and link `sourceorrery_ffi`. `CMakeLists.txt` builds
the example and the test; see the comment at its top.

Documentation: <https://sourceorrery.ai/sdks/cpp/>.
