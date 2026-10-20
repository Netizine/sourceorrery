# ADR 0006: One binding technology per language

**Status:** accepted · **Date:** 2026-10-20

## Context

ADR 0005 fixes *what* the SDKs expose. This record fixes *how* each one
reaches the Rust core, choosing in each language the most widely adopted
native-binding technology that needs no extra runtime, so that the thin
layer stays thin and the packages install the way that language's users
expect.

Two routes exist: a native extension built from the Rust crates (the
host's own extension API, one build per platform and runtime) or a call
into the C ABI (one shared library per platform, loaded by the language's
foreign-function facility). The first gives the most idiomatic packages
where mature tooling exists; the second keeps the binding to a few hundred
lines and needs no compiler on the user's machine.

## Decision

| Language | Technology | Package | Why |
|----------|------------|---------|-----|
| Rust | the `sourceorrery` crate, directly over `sourceorrery-storage` | crates.io `sourceorrery` | It *is* the client every other binding wraps. |
| Python | PyO3 + maturin, abi3 wheels for 3.11+ | PyPI `sourceorrery` | The de facto standard for Rust extensions; one wheel per platform for every Python version; maturin builds, tests and publishes. |
| JavaScript / TypeScript | napi-rs 3 with the generated loader and hand-written types for the public wrapper | npm `@sourceorrery/sdk` plus one package per platform as optional dependencies | Node-API gives ABI stability across Node versions; napi-rs is the standard Rust toolkit for it and handles the per-platform package layout. |
| Java | Foreign Function and Memory API (`java.lang.foreign`, final in Java 22) over the C ABI | Maven Central `ai.sourceorrery:sourceorrery` | Part of the JDK; no JNI glue, no second native library to build. JNA would add a runtime dependency; JNI would add C to maintain. The jar embeds the shared library per platform. |
| .NET | `LibraryImport` source-generated P/Invoke (.NET 8+) over the C ABI | NuGet `SourceOrrery` with `runtimes/<rid>/native` | Trimming- and AOT-safe, no runtime marshalling, the layout NuGet already understands. |
| Go | cgo over the C ABI, header vendored in the module | pkg.go.dev `github.com/netizine/sourceorrery/bindings/go` | The one supported way to call C from Go; the module needs only the shared library on the linker path. |
| C | the cbindgen header itself | the `sourceorrery-ffi-<version>-<target>` release archive | Nothing to add. |
| C++ | a header-only C++17 RAII wrapper over the C header | the same archive (`sourceorrery.hpp`) | No build system to adopt; RAII gives zeroise-on-scope-exit for free. |
| PHP | the built-in FFI extension (PHP 8.2+) over a vendored subset of the C declarations | Packagist `sourceorrery/sourceorrery` | Bundled with PHP; no extension to compile or load. |

Common rules:

* Metadata crosses as the core's JSON shape; values cross as bytes.
  Bindings parse JSON with the language's own facility (a dependency-free
  reader where the standard library has none: Java and C++).
* Thread-local error state (`so_last_error_*`) is read on the thread that
  made the call: Go pins its OS thread for each call; Java reads the state
  immediately with no blocking operation in between; the others are
  single-threaded per call by construction.
* The native extension crates (Python, Node) live outside the Cargo
  workspace, as their own workspace roots with their own lock files, so
  `cargo test --workspace` never needs a Python or Node toolchain and the
  packaging tools build them with the features they need.
* Native libraries ship inside the packages where the ecosystem supports
  it (npm platform packages, NuGet `runtimes/`, the jar) and from the
  GitHub Release archives otherwise (Go, C, C++, PHP), always built by the
  same release workflow from the same commit.

## Consequences

* Adding a platform means adding it to the native build matrix once; every
  C-ABI binding picks it up from the archive, Python and Node need a
  matrix entry each.
* The Rust crates stay the compatibility contract (`CONTRACT_VERSION`);
  generator versions can change without changing the meaning of a call.
* Java requires Java 22 or newer and `--enable-native-access`; PHP
  requires the FFI extension enabled for the CLI SAPI (the default); Go
  users need a C toolchain. The per-language pages state these up front.
