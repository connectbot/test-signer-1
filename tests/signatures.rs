use android_signer::{
    apk::{self, Hybrid, Profile},
    archive::{self, Entries, Entry},
    crypto::SigningKey,
    jar,
    lineage::{DEFAULT_FLAGS, DEFAULT_LIMIT, Lineage},
    transparency,
};
use std::{process::Command, sync::LazyLock};
struct Fixtures {
    dir: tempfile::TempDir,
}
static FIXTURES: LazyLock<Fixtures> = LazyLock::new(|| {
    let dir = tempfile::tempdir().unwrap();
    for (name, algorithm) in [
        ("a", "RSA"),
        ("b", "RSA"),
        ("c", "RSA"),
        ("hybrid", "RSA"),
        ("pqc", "ML-DSA-65"),
        ("pqc2", "ML-DSA-65"),
        ("hybrid2", "RSA"),
        ("transparency", "RSA"),
    ] {
        let pem = dir.path().join(format!("{name}.key.pem"));
        let mut command = Command::new("openssl");
        command
            .args(["genpkey", "-algorithm", algorithm, "-out"])
            .arg(&pem);
        if algorithm == "RSA" {
            command.args([
                "-pkeyopt",
                if name.starts_with("hybrid") {
                    "rsa_keygen_bits:4096"
                } else {
                    "rsa_keygen_bits:2048"
                },
            ]);
        }
        assert!(command.output().unwrap().status.success());
        let der = dir.path().join(format!("{name}.pk8"));
        assert!(
            Command::new("openssl")
                .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
                .arg(&pem)
                .args(["-outform", "DER", "-out"])
                .arg(&der)
                .output()
                .unwrap()
                .status
                .success()
        );
        let cert = dir.path().join(format!("{name}.pem"));
        assert!(
            Command::new("openssl")
                .args(["req", "-new", "-x509", "-key"])
                .arg(&pem)
                .args(["-out"])
                .arg(&cert)
                .args(["-days", "10950", "-subj", &format!("/CN=Test-{name}")])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    Fixtures { dir }
});
fn key(name: &str) -> SigningKey {
    SigningKey::load(
        &FIXTURES.dir.path().join(format!("{name}.pk8")),
        &FIXTURES.dir.path().join(format!("{name}.pem")),
    )
    .unwrap()
}
fn reference(path: &std::path::Path, sdk: u32) {
    reference_expected(path, sdk, None);
}
fn reference_expected(path: &std::path::Path, sdk: u32, expected_signer: Option<&str>) {
    let Some(mut classpath) = std::env::var_os("ANDROID_SIGNER_REFERENCE_CLASSES") else {
        return;
    };
    if sdk < 37
        && let Some(legacy) = std::env::var_os("ANDROID_SIGNER_LEGACY_CLASSES")
    {
        classpath = legacy;
    }
    let java = std::env::var_os("ANDROID_SIGNER_JAVA").unwrap_or_else(|| "java".into());
    let mut command = Command::new(java);
    command
        .arg("-cp")
        .arg(classpath)
        .args(["Reference", "apk"])
        .arg(path)
        .arg(sdk.to_string());
    if let Some(fingerprint) = expected_signer {
        command.arg(fingerprint);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "Android reference rejected API {sdk}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
fn original() -> Entries {
    if let Some(path) = std::env::var_os("ANDROID_SIGNER_REFERENCE_APK") {
        let mut entries = archive::read(&std::fs::read(path).unwrap()).unwrap();
        entries.retain(|n, _| !n.starts_with("META-INF/"));
        entries
    } else {
        Entries::from([
            (
                "AndroidManifest.xml".into(),
                Entry {
                    bytes: b"manifest-test".to_vec(),
                    stored: false,
                },
            ),
            (
                "classes.dex".into(),
                Entry {
                    bytes: b"dex-test".to_vec(),
                    stored: false,
                },
            ),
        ])
    }
}
#[test]
fn rotation_signatures_match_android() {
    let a = key("a");
    let b = key("b");
    let c = key("c");
    let chain = Lineage::root(&a)
        .append(&a, &b, DEFAULT_FLAGS)
        .unwrap()
        .append(&b, &c, DEFAULT_FLAGS)
        .unwrap();
    let bytes = chain.file().unwrap();
    assert_eq!(Lineage::read(&bytes, DEFAULT_LIMIT).unwrap(), chain);
    let unsigned = archive::write(&original(), true).unwrap();
    for sdk in [28, 33] {
        let profile = Profile {
            original: &a,
            current: &c,
            lineage: &chain,
            rotation_min_sdk: sdk,
            hybrid: None,
        };
        let signed = apk::sign(&unsigned, &profile).unwrap();
        assert_eq!(apk::sign(&unsigned, &profile).unwrap(), signed);
        let path = FIXTURES.dir.path().join(format!("classical-{sdk}.apk"));
        std::fs::write(&path, &signed).unwrap();
        for platform in [24, 28, 32, 33, 36, 37] {
            let expected = if platform >= sdk {
                c.fingerprint()
            } else {
                a.fingerprint()
            };
            reference_expected(&path, platform, Some(&expected));
        }
        let mut corrupted = signed;
        corrupted[30] ^= 1;
        assert!(apk::verify_output(&corrupted, &profile).is_err());
    }
    if let Some(classes) = std::env::var_os("ANDROID_SIGNER_REFERENCE_CLASSES") {
        let path = FIXTURES.dir.path().join("lineage.bin");
        std::fs::write(&path, &bytes).unwrap();
        let java = std::env::var_os("ANDROID_SIGNER_JAVA").unwrap_or_else(|| "java".into());
        let out = Command::new(java)
            .arg("-cp")
            .arg(classes)
            .args(["Reference", "lineage"])
            .arg(path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[test]
fn hybrid_and_repeated_rotation_match_android() {
    let a = key("a");
    let c = key("c");
    let r = key("hybrid");
    let p = key("pqc");
    let history = Lineage::root(&a).append(&a, &c, DEFAULT_FLAGS).unwrap();
    let rsa_history = history.append(&c, &r, DEFAULT_FLAGS).unwrap();
    let pqc_history = history.append(&c, &p, DEFAULT_FLAGS).unwrap();
    let unsigned = archive::write(&original(), true).unwrap();
    let profile = Profile {
        original: &a,
        current: &c,
        lineage: &history,
        rotation_min_sdk: 33,
        hybrid: Some(Hybrid {
            classical: &r,
            pqc: &p,
            classical_lineage: &rsa_history,
            pqc_lineage: &pqc_history,
        }),
    };
    let signed = apk::sign(&unsigned, &profile).unwrap();
    let path = FIXTURES.dir.path().join("hybrid.apk");
    std::fs::write(&path, &signed).unwrap();
    for sdk in [24, 28, 32, 33, 36, 37] {
        reference(&path, sdk);
    }
    assert_eq!(apk::sign(&unsigned, &profile).unwrap(), signed);
    let effective = rsa_history.append(&r, &p, DEFAULT_FLAGS).unwrap();
    let r2 = key("hybrid2");
    let p2 = key("pqc2");
    let rh = effective.append(&p, &r2, DEFAULT_FLAGS).unwrap();
    let ph = effective.append(&p, &p2, DEFAULT_FLAGS).unwrap();
    let profile2 = Profile {
        original: &a,
        current: &c,
        lineage: &history,
        rotation_min_sdk: 33,
        hybrid: Some(Hybrid {
            classical: &r2,
            pqc: &p2,
            classical_lineage: &rh,
            pqc_lineage: &ph,
        }),
    };
    let signed2 = apk::sign(&unsigned, &profile2).unwrap();
    let path2 = FIXTURES.dir.path().join("hybrid2.apk");
    std::fs::write(&path2, &signed2).unwrap();
    reference(&path2, 37);
    let mut bad = ph.clone();
    bad.nodes[0].flags ^= 4;
    let broken = Profile {
        original: &a,
        current: &c,
        lineage: &history,
        rotation_min_sdk: 33,
        hybrid: Some(Hybrid {
            classical: &r2,
            pqc: &p2,
            classical_lineage: &rh,
            pqc_lineage: &bad,
        }),
    };
    assert!(apk::sign(&unsigned, &broken).is_err());
}
#[test]
fn jar_transparency_and_tamper_detection() {
    let upload = key("a");
    let transparency_key = key("transparency");
    let mut entries = Entries::from([(
        "base/dex/classes.dex".into(),
        Entry {
            bytes: b"dex-test".to_vec(),
            stored: false,
        },
    )]);
    let statement = transparency::Statement {
        version: 1,
        code_related_file: vec![transparency::CodeFile {
            path: Some("base/dex/classes.dex".into()),
            bundletool_repo_path: None,
            kind: "DEX".into(),
            apk_path: None,
            sha256: android_signer::sha256(b"dex-test"),
        }],
    };
    let jwt = transparency::sign(&statement, &transparency_key).unwrap();
    transparency::verify(&jwt, &statement, &transparency_key.certificate).unwrap();
    archive::add(&mut entries, transparency::BUNDLE_PATH, jwt).unwrap();
    jar::sign(&mut entries, &upload).unwrap();
    jar::verify_output(&entries, &upload).unwrap();
    let path = FIXTURES.dir.path().join("signed.aab");
    std::fs::write(&path, archive::write(&entries, false).unwrap()).unwrap();
    let truststore = FIXTURES.dir.path().join("upload-truststore.p12");
    let trust = Command::new("keytool")
        .args(["-importcert", "-noprompt", "-alias", "test-upload", "-file"])
        .arg(FIXTURES.dir.path().join("a.pem"))
        .arg("-keystore")
        .arg(&truststore)
        .args(["-storepass", "test-only-password"])
        .output()
        .unwrap();
    assert!(
        trust.status.success(),
        "{}",
        String::from_utf8_lossy(&trust.stderr)
    );
    let out = Command::new("jarsigner")
        .args(["-verify", "-strict", "-keystore"])
        .arg(&truststore)
        .args(["-storepass", "test-only-password"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("jar verified"),
        "{} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    entries
        .get_mut("base/dex/classes.dex")
        .unwrap()
        .bytes
        .push(1);
    assert!(jar::verify_output(&entries, &upload).is_err());
    let tampered = FIXTURES.dir.path().join("tampered.aab");
    std::fs::write(&tampered, archive::write(&entries, false).unwrap()).unwrap();
    let rejected = Command::new("jarsigner")
        .args(["-verify", "-strict", "-keystore"])
        .arg(&truststore)
        .args(["-storepass", "test-only-password"])
        .arg(tampered)
        .output()
        .unwrap();
    assert!(
        !rejected.status.success(),
        "jarsigner accepted modified signed content"
    );
}
#[test]
fn archive_and_lineage_reject_unsafe_inputs() {
    let a = key("a");
    let b = key("b");
    let chain = Lineage::root(&a).append(&a, &b, DEFAULT_FLAGS).unwrap();
    let mut corrupted = chain.file().unwrap();
    let end = corrupted.len() - 1;
    corrupted[end] ^= 1;
    assert!(Lineage::read(&corrupted, DEFAULT_LIMIT).is_err());
    assert!(Lineage::read(&chain.file().unwrap(), 1).is_err());
    assert!(chain.append(&b, &a, DEFAULT_FLAGS).is_err());
    let rollback = Lineage::root(&a).append(&a, &b, DEFAULT_FLAGS | 8).unwrap();
    assert!(rollback.validate(false).is_err());
    let entries = Entries::from([(
        "../key".into(),
        Entry {
            bytes: vec![1],
            stored: true,
        },
    )]);
    let zip = archive::write(&entries, false).unwrap();
    assert!(archive::read(&zip).is_err());
    let compressed = archive::write(
        &Entries::from([(
            "large".into(),
            Entry {
                bytes: vec![0; 4096],
                stored: false,
            },
        )]),
        false,
    )
    .unwrap();
    assert!(archive::read_limited(&compressed, 4095).is_err());
    assert_eq!(
        archive::read_limited(&compressed, 4096).unwrap()["large"]
            .bytes
            .len(),
        4096
    );
}
#[test]
fn sixty_four_certificate_history() {
    // Distinct certificates exercise Android's identity history independently of
    // expensive key generation; production rotation uses provisioned new keys.
    let mut previous = key("a");
    let mut chain = Lineage::root(&previous);
    for i in 1..64 {
        let source = if i % 2 == 0 { "a" } else { "b" };
        let cert = FIXTURES.dir.path().join(format!("chain-{i}.pem"));
        assert!(
            Command::new("openssl")
                .args(["req", "-new", "-x509", "-key"])
                .arg(FIXTURES.dir.path().join(format!("{source}.key.pem")))
                .args(["-out"])
                .arg(&cert)
                .args(["-days", "10950", "-subj", &format!("/CN=Chain-{i}")])
                .output()
                .unwrap()
                .status
                .success()
        );
        let next =
            SigningKey::load(&FIXTURES.dir.path().join(format!("{source}.pk8")), &cert).unwrap();
        chain = chain.append(&previous, &next, DEFAULT_FLAGS).unwrap();
        previous = next;
        if [3, 10, 64].contains(&chain.nodes.len()) {
            let bytes = chain.file().unwrap();
            assert_eq!(Lineage::read(&bytes, DEFAULT_LIMIT).unwrap(), chain);
        }
    }
    assert_eq!(chain.nodes.len(), 64);
}

#[test]
fn bundletool_verifies_native_transparency_and_bundle_signature() {
    let Some(fixture) = std::env::var_os("ANDROID_SIGNER_REFERENCE_AAB") else {
        return;
    };
    let tool = std::env::var_os("ANDROID_SIGNER_BUNDLETOOL")
        .expect("bundletool is required with AAB fixture");
    let java = std::env::var_os("ANDROID_SIGNER_JAVA").unwrap_or_else(|| "java".into());
    let upload = key("a");
    let transparency_key = key("transparency");
    let mut entries = archive::read(&std::fs::read(fixture).unwrap()).unwrap();
    let identity = android_signer::manifest::identity(
        &entries["base/manifest/AndroidManifest.xml"].bytes,
        true,
    )
    .unwrap();
    assert_eq!(identity.package, "test.example");
    assert_eq!(identity.min_sdk, 24);
    let statement = transparency::statement(&entries, None).unwrap();
    let jwt = transparency::sign(&statement, &transparency_key).unwrap();
    archive::add(&mut entries, transparency::BUNDLE_PATH, jwt.clone()).unwrap();
    jar::sign(&mut entries, &upload).unwrap();
    let aab = FIXTURES.dir.path().join("bundletool-signed.aab");
    std::fs::write(&aab, archive::write(&entries, false).unwrap()).unwrap();
    for command in ["validate", "check-transparency"] {
        let mut run = Command::new(&java);
        run.args(["-jar"])
            .arg(&tool)
            .arg(command)
            .arg(format!("--bundle={}", aab.display()));
        if command == "check-transparency" {
            run.arg("--mode=bundle").arg(format!(
                "--transparency-key-certificate={}",
                FIXTURES.dir.path().join("transparency.pem").display()
            ));
        }
        let output = run.output().unwrap();
        assert!(
            output.status.success(),
            "bundletool {command}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut apk_entries = original();
    transparency::check_apk(&statement, &apk_entries).unwrap();
    archive::add(&mut apk_entries, transparency::APK_PATH, jwt).unwrap();
    let lineage = Lineage::root(&upload);
    let profile = Profile {
        original: &upload,
        current: &upload,
        lineage: &lineage,
        rotation_min_sdk: 33,
        hybrid: None,
    };
    let signed = apk::sign(&archive::write(&apk_entries, true).unwrap(), &profile).unwrap();
    let apk_zip = FIXTURES.dir.path().join("transparency-apks.zip");
    let zip_entries = Entries::from([(
        "base.apk".into(),
        Entry {
            bytes: signed,
            stored: true,
        },
    )]);
    std::fs::write(&apk_zip, archive::write(&zip_entries, false).unwrap()).unwrap();
    let out = Command::new(java)
        .arg("-jar")
        .arg(tool)
        .args(["check-transparency", "--mode=apk"])
        .arg(format!("--apk-zip={}", apk_zip.display()))
        .arg(format!(
            "--transparency-key-certificate={}",
            FIXTURES.dir.path().join("transparency.pem").display()
        ))
        .arg(format!(
            "--apk-signing-key-certificate={}",
            FIXTURES.dir.path().join("a.pem").display()
        ))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "bundletool APK check: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn receipt_dsse_is_authenticated_and_domain_separated() {
    let key = key("a");
    let receipt = serde_json::json!({"version":2,"job":{"profile":"oss","run_id":42},"inputs":{"apk":"a".repeat(64)},"outputs":[{"name":"app-signed.apk","sha256":"b".repeat(64),"bytes":123}]});
    let envelope = android_signer::receipt::sign(&receipt, &key).unwrap();
    assert_eq!(
        android_signer::receipt::verify(&envelope, &key.certificate, &key.fingerprint()).unwrap(),
        receipt
    );
    let other = self::key("b");
    assert!(
        android_signer::receipt::verify(&envelope, &other.certificate, &other.fingerprint())
            .is_err()
    );
    let mut altered: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    altered["payloadType"] = serde_json::json!("application/json");
    assert!(
        android_signer::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
    use base64::Engine;
    let mut altered: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    altered["payload"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode(b"{}"));
    assert!(
        android_signer::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
    altered["signatures"][0]["keyid"] = serde_json::json!(other.fingerprint());
    assert!(
        android_signer::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
    // Ordinary RSA signatures over JSON cannot be substituted for DSSE PAE.
    let mut altered: serde_json::Value = serde_json::from_slice(&envelope).unwrap();
    let payload = base64::engine::general_purpose::STANDARD
        .decode(altered["payload"].as_str().unwrap())
        .unwrap();
    altered["signatures"][0]["sig"] = serde_json::json!(
        base64::engine::general_purpose::STANDARD.encode(
            key.sign(android_signer::crypto::RSA_SHA256, &payload)
                .unwrap()
        )
    );
    assert!(
        android_signer::receipt::verify(
            &serde_json::to_vec(&altered).unwrap(),
            &key.certificate,
            &key.fingerprint()
        )
        .is_err()
    );
}
