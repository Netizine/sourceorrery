# SourceOrrery C++ SDK

A header-only RAII wrapper (C++17) over the read-only part of the C ABI.

## Before you start: the CLI

### Option 1: Set up with the CLI

This SDK is read-only. Use the separately installed `sourceorrery` CLI to
create vaults and set secret values. Follow the
[CLI installation guide](https://sourceorrery.ai/getting-started/#install), then:

```bash
sourceorrery setup
sourceorrery secret set database-password --vault development
```

The SDK does not install the CLI. Your application reads the vault through
the native library and does not need a CLI process running alongside it.

### Option 2: Set up with an AI coding agent

```bash
sourceorrery init --integration all
```

Use your existing coding agent and ask: "Set up SourceOrrery for this
project without showing secret values." Replace `all` with your agent's
name to install only its skills. The agent handles the manifest, code and
launch commands; you create vaults and enter values privately.
The [agent setup guide](https://sourceorrery.ai/guides/ai-agents/)
also covers updating skills from the repository independently of the CLI.

## Read a secret

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
([providers](https://sourceorrery.ai/providers/)); `UnauthenticatedError` /
`ProviderUnavailableError` (transient) report a provider's failures.

Take `include/sourceorrery.hpp` and `crates/sourceorrery-ffi/include/sourceorrery.h`
(both ship in the `sourceorrery-ffi-<version>-<target>` release archive next
to the shared library) and link `sourceorrery_ffi`. `CMakeLists.txt` builds
the example and the test; see the comment at its top.

Documentation: <https://sourceorrery.ai/sdks/cpp/>.
