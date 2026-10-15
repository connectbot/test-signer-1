static INIT: std::sync::Once = std::sync::Once::new();
fn initialize() {
    INIT.call_once(|| android_signer::initialize_crypto().unwrap());
}
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};

#[test]
fn genuine_public_and_private_bundles_with_rustcrypto() {
    initialize();
    let cases = [
        (
            include_str!("fixtures/public-trusted-root.json"),
            include_str!("fixtures/github-public.sigstore.json"),
            "54303491a8418fbed24344b513546182c29b43bf282ceb433af65e2299f9271f",
            false,
        ),
        (
            include_str!("fixtures/github-trusted-root.json"),
            include_str!("fixtures/github-private.sigstore.json"),
            "76f1fe8593bf227cca2c089e3c16dc95014a8d3e89c5dd220530469ca043c428",
            true,
        ),
    ];
    for (root, bundle, digest, private) in cases {
        let root = TrustedRoot::from_json(root).unwrap();
        let bundle = Bundle::from_json(bundle).unwrap();
        // Fixture identity is not used to authorize a production signing request.
        // The pipeline separately enforces its configured workflow and CI claims.
        let mut policy = if private {
            VerificationPolicy::any_identity()
                .require_identity("https://dotcom.releases.github.com")
        } else {
            VerificationPolicy::new(
                "https://github.com/prefix-dev/sigstore-example/.github/workflows/action.yaml@refs/heads/main",
                "https://token.actions.githubusercontent.com",
            )
        };
        if private {
            policy = policy.skip_tlog_unsafe().skip_sct();
        }
        let verifier = Verifier::new(&root).unwrap();
        let verified = verifier
            .verify(Sha256Hash::from_hex(digest).unwrap(), &bundle, &policy)
            .unwrap();
        assert!(verified.certificate_verified());
        assert!(!verified.verified_timestamps().is_empty());
        assert!(
            verifier
                .verify(Sha256Hash::new([0; 32]), &bundle, &policy)
                .is_err()
        );
        let wrong_identity = policy.require_identity(
            "https://github.com/untrusted/repo/.github/workflows/build.yml@refs/heads/main",
        );
        assert!(
            verifier
                .verify(
                    Sha256Hash::from_hex(digest).unwrap(),
                    &bundle,
                    &wrong_identity
                )
                .is_err()
        );
    }
}

// Cryptographic bundle interoperability is tested above; these adversarial
// claim tests exercise the application's authorization after that verification.
#[test]
fn reusable_builder_and_caller_are_authorized_independently() {
    use serde_json::{Value, json};
    let config: android_signer::config::Config =
        serde_json::from_str(include_str!("../config/signer.example.json")).unwrap();
    let mut repo = config.repositories[0].clone();
    repo.name = "owner/app".into();
    repo.id = 42;
    repo.callers = std::collections::BTreeMap::from([(
        ".github/workflows/release.yml".into(),
        vec!["a".repeat(64)],
    )]);
    repo.builder.repository = "trusted/builders".into();
    repo.builder.workflow = ".github/workflows/android.yml".into();
    repo.builder.refs = vec!["refs/tags/v1".into()];
    repo.refs = vec!["refs/heads/main".into(), "refs/tags/v*".into()];
    repo.events = vec!["push".into()];
    let sha = "b".repeat(40);
    let builder_sha = "c".repeat(40);
    let caller = "https://github.com/owner/app/.github/workflows/release.yml@refs/heads/main";
    let builder = "https://github.com/trusted/builders/.github/workflows/android.yml@refs/tags/v1";
    let invocation = "https://github.com/owner/app/actions/runs/100/attempts/2";
    let mut claims = sigstore_crypto::FulcioCiClaims::default();
    claims.source_repository_uri = Some("https://github.com/owner/app".into());
    claims.source_repository_identifier = Some("42".into());
    claims.source_repository_digest = Some(sha.clone());
    claims.source_repository_ref = Some("refs/heads/main".into());
    claims.build_config_uri = Some(caller.into());
    claims.build_config_digest = Some(sha.clone());
    claims.build_signer_uri = Some(builder.into());
    claims.build_signer_digest = Some(builder_sha);
    claims.run_invocation_uri = Some(invocation.into());
    claims.runner_environment = Some("github-hosted".into());
    claims.build_trigger = Some("push".into());
    claims.source_repository_visibility_at_signing = Some("public".into());
    let statement = json!({"predicate":{"buildDefinition":{"buildType":"https://actions.github.io/buildtypes/workflow/v1","externalParameters":{"workflow":{"path":".github/workflows/release.yml","repository":"https://github.com/owner/app","ref":"refs/heads/main"}},"internalParameters":{"github":{"repository_id":"42","runner_environment":"github-hosted","event_name":"push"}},"resolvedDependencies":[{"uri":"git+https://github.com/owner/app@refs/heads/main","digest":{"gitCommit":sha}}]},"runDetails":{"builder":{"id":builder},"metadata":{"invocationId":invocation}}}});
    let verify = |s: &Value, c: &sigstore_crypto::FulcioCiClaims| {
        android_signer::attestation::validate_claims(s, c, &repo, &sha, 100, 2)
    };
    verify(&statement, &claims).unwrap();
    for pointer in [
        "/predicate/buildDefinition/externalParameters/workflow/path",
        "/predicate/buildDefinition/externalParameters/workflow/ref",
        "/predicate/runDetails/builder/id",
        "/predicate/runDetails/metadata/invocationId",
        "/predicate/buildDefinition/resolvedDependencies/0/digest/gitCommit",
        "/predicate/buildDefinition/internalParameters/github/repository_id",
        "/predicate/buildDefinition/buildType",
    ] {
        let mut bad = statement.clone();
        *bad.pointer_mut(pointer).unwrap() = json!("attacker");
        assert!(verify(&bad, &claims).is_err(), "accepted {pointer}");
    }
    let mut bad = statement.clone();
    bad["predicate"]["buildDefinition"]["externalParameters"]["script"] = json!("arbitrary");
    assert!(verify(&bad, &claims).is_err());
    let mut bad = claims.clone();
    bad.build_signer_uri = Some(caller.into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.build_config_uri = Some(builder.into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.run_invocation_uri = Some(invocation.replace("attempts/2", "attempts/1"));
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.source_repository_identifier = Some("43".into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.runner_environment = Some("self-hosted".into());
    assert!(verify(&statement, &bad).is_err());
    let mut bad = claims.clone();
    bad.build_signer_digest = None;
    assert!(verify(&statement, &bad).is_err());
    assert!(android_signer::config::ref_allowed(
        &repo.refs,
        "refs/tags/v1.2.3"
    ));
    assert!(!android_signer::config::ref_allowed(
        &repo.refs,
        "refs/heads/attacker"
    ));
}

#[test]
fn genuine_connectbot_reusable_provenance_satisfies_application_policy() {
    use android_signer::{
        attestation,
        config::{Config, TrustRoot},
    };
    initialize();
    let config: Config =
        serde_json::from_str(include_str!("../config/connectbot.example.json")).unwrap();
    let mut repo = config.repositories[0].clone();
    let root_bytes = include_bytes!("fixtures/public-trusted-root.json");
    let dir = tempfile::tempdir().unwrap();
    let root_file = dir.path().join("root.json");
    std::fs::write(&root_file, root_bytes).unwrap();
    let mut trust = TrustRoot {
        file: root_file,
        sha256: android_signer::sha256(root_bytes),
        valid_until: android_signer::config::now().unwrap() + 3600,
    };
    let bundle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/connectbot-reusable.sigstore.json")).unwrap();
    let digest = "ebf7e098d9860b6e959bb049c6180b4da873768a554984a3022796994a9e771a";
    let commit = "500982cdc99e469d5591b5d2e1dc5ba798289a76";
    let result =
        attestation::verify_digest(digest, &bundle, &repo, &trust, commit, 38365824978, 1).unwrap();
    assert_eq!(result["caller"], ".github/workflows/ci.yml");
    assert_eq!(
        result["builder"],
        "https://github.com/connectbot/connectbot/.github/workflows/ci-build.yml@refs/heads/main"
    );
    assert!(
        attestation::verify_digest(digest, &bundle, &repo, &trust, commit, 38365824978, 2).is_err()
    );
    assert!(
        attestation::verify_digest(
            &"0".repeat(64),
            &bundle,
            &repo,
            &trust,
            commit,
            38365824978,
            1
        )
        .is_err()
    );
    repo.builder.workflow = ".github/workflows/ci.yml".into();
    assert!(
        attestation::verify_digest(digest, &bundle, &repo, &trust, commit, 38365824978, 1).is_err()
    );
    repo.builder.workflow = ".github/workflows/ci-build.yml".into();
    trust.valid_until = 1;
    assert!(
        attestation::verify_digest(digest, &bundle, &repo, &trust, commit, 38365824978, 1).is_err()
    );
}
