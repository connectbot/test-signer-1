fn main() {
    println!("cargo:rerun-if-env-changed=SIGNER_SOURCE_REVISION");
    let revision =
        std::env::var("SIGNER_SOURCE_REVISION").unwrap_or_else(|_| "development-unmeasured".into());
    assert!(
        revision == "development-unmeasured"
            || (revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit())),
        "invalid signer source revision"
    );
    println!("cargo:rustc-env=SIGNER_SOURCE_REVISION={revision}");
    println!("cargo:rerun-if-env-changed=HERMIT_MANIFEST_DIR");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("hermit") {
        let kernel = std::env::var_os("HERMIT_MANIFEST_DIR").expect(
            "Build the signer with scripts/build-hermit.py: a strict-entropy kernel is required",
        );
        let entropy = std::path::PathBuf::from(kernel).join("src/syscalls/entropy.rs");
        let source =
            std::fs::read_to_string(&entropy).expect("Cannot read Hermit entropy implementation");
        assert!(
            source.contains("ANDROID_SIGNER_STRICT_ENTROPY")
                && !source.contains("Fallback to a naive implementation"),
            "Unpatched entropy kernel: use scripts/build-hermit.py"
        );
        println!("cargo:rerun-if-changed={}", entropy.display());
    }
}
