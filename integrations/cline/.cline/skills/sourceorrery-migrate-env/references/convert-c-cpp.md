# Converting C and C++ code

Both use the C ABI from the `sourceorrery-ffi-<version>-<target>` archive
on the GitHub release (shared and static libraries, `sourceorrery.h`,
and the header-only C++17 wrapper `sourceorrery.hpp`). Link
`sourceorrery_ffi` and put the shared library on the loader path:
https://sourceorrery.ai/sdks/c/ and https://sourceorrery.ai/sdks/cpp/

## C++

```cpp
// secrets.hpp
#pragma once
#include <sourceorrery.hpp>
#include <stdexcept>
#include <string>

namespace secrets {

inline const sourceorrery::Project& project() {
    static const sourceorrery::Project loaded = sourceorrery::Project::load(); // nearest sourceorrery.toml
    return loaded;
}

/// The value delivered as environment variable `name`.
inline std::string get(const char* name) {
    const sourceorrery::SecretValue* value = project().env(name);
    if (value == nullptr) throw std::runtime_error(std::string(name) + " is not available from sourceorrery.toml");
    return value->text();
}

}  // namespace secrets
```

| Before | After |
|--------|-------|
| `std::getenv("DATABASE_URL")` | `secrets::get("DATABASE_URL")` (check for null where the old code did) |

## C

Reading through the C ABI means owning buffers (`so_project_load`,
`so_project_entry`, `so_bytes_free`); the C guide has the complete
program. For a small C program the simplest conversion is often none:
keep `getenv` and start it with `sourceorrery run -- ./program`.

## Build files

Add the include directory and the library to CMake, Make or Meson. A
build that only *uses* a variable at run time does not change.
