# Language bindings

Milestone 2. Nothing here yet by design: the first release establishes the
contract that every binding will implement.

## Plan

| Language | Technology | Tier |
|----------|------------|------|
| Rust | `sourceorrery-core` + `sourceorrery-storage` crates | First-class |
| C# / .NET | C ABI via Interoptopus / P/Invoke | First-class |
| Python | PyO3 + Maturin wheels | First-class |
| Node.js / TypeScript | napi-rs | First-class |
| Java / Kotlin | JNI or Java FFM; UniFFI for Kotlin | First-class |
| Swift | UniFFI | First-class |
| Everything else | Stable C ABI (`sourceorrery-ffi`, `cbindgen`) or the local broker protocol | Community |

## Contract

Every binding exposes the same `SecretClient` surface as
`sourceorrery_core::SecretClient`, maps `SecretError::code()` to idiomatic
exceptions, and must pass the scenarios in `tests/conformance` through its
own language. A binding that cannot pass them does not ship.

Secret values cross the boundary as bytes with explicit length and are
zeroised on the Rust side as soon as the call returns. Bindings must offer a
scoped accessor (callback / `using` / context manager) in addition to a plain
value getter, and document that once a plaintext value is in application
memory the application can disclose it.
