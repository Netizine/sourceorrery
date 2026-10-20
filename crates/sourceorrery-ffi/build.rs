//! Regenerates `include/sourceorrery.h` from the `extern "C"` surface.
//!
//! The header is written only when its content changes, so a clean checkout
//! builds without touching the working tree. If the source directory is not
//! writable (a packaged crate, a read-only checkout) the failure is reported
//! as a warning and the committed header is used as is; the
//! `committed_header_is_current` test and the CI header check still catch a
//! stale header.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src");

    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let header_path = crate_dir.join("include").join("sourceorrery.h");

    let config = match cbindgen::Config::from_file(crate_dir.join("cbindgen.toml")) {
        Ok(config) => config,
        Err(err) => {
            println!("cargo:warning=sourceorrery-ffi: cannot read cbindgen.toml: {err}");
            return;
        }
    };
    let bindings = match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => bindings,
        Err(err) => {
            println!("cargo:warning=sourceorrery-ffi: header generation failed: {err}");
            return;
        }
    };

    let mut generated = Vec::new();
    bindings.write(&mut generated);
    let current = std::fs::read(&header_path).unwrap_or_default();
    if current == generated {
        return;
    }
    let written = std::fs::create_dir_all(header_path.parent().expect("include dir"))
        .and_then(|()| std::fs::write(&header_path, &generated));
    if let Err(err) = written {
        println!(
            "cargo:warning=sourceorrery-ffi: cannot update {}: {err}",
            header_path.display()
        );
    }
}
