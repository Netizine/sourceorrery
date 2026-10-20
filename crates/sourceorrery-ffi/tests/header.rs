//! The committed C header must match what cbindgen generates from the source.
//!
//! `build.rs` rewrites the header on every build, so this fails only when
//! the source tree was not writable at build time or the header was edited
//! by hand. CI also diffs the committed file after a build.

use std::path::PathBuf;

#[test]
fn committed_header_is_current() {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config =
        cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")).expect("cbindgen.toml");
    let bindings = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
        .expect("cbindgen can parse the crate");
    let mut generated = Vec::new();
    bindings.write(&mut generated);

    let header = crate_dir.join("include").join("sourceorrery.h");
    let committed = std::fs::read(&header).expect("include/sourceorrery.h exists");
    assert!(
        committed == generated,
        "{} is stale: run `cargo build -p sourceorrery-ffi` and commit the result",
        header.display()
    );
}
