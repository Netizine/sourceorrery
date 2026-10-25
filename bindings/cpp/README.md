# SourceOrrery C++ SDK

A header-only RAII wrapper (C++17) over the read-only part of the C ABI.

```cpp
#include <sourceorrery.hpp>

auto reader = sourceorrery::Reader::open("development");
auto secret = reader.get("database-password");
connect(secret.value.text());   // zeroised when `secret` goes out of scope
```

A secret that one of the vault's connections stores (HashiCorp Vault, AWS
Secrets Manager or Azure Key Vault) is read at that provider by the same
calls, with the credentials the connection stores or the ones the
provider's own tools find in the environment
([providers](../../docs/providers/)); `UnauthenticatedError` /
`ProviderUnavailableError` (transient) report a provider's failures.

Take `include/sourceorrery.hpp` and `crates/sourceorrery-ffi/include/sourceorrery.h`
(both ship in the `sourceorrery-ffi-<version>-<target>` release archive next
to the shared library) and link `sourceorrery_ffi`. `CMakeLists.txt` builds
the example and the test; see the comment at its top.

Documentation: <https://sourceorrery.ai/sdks/cpp/>.
