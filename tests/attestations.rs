use sigstore_trust_root::TrustedRoot;
use sigstore_types::{Bundle, Sha256Hash};
use sigstore_verify::{VerificationPolicy, Verifier};

#[test]
fn genuine_public_and_private_bundles_with_rustcrypto() {
    android_signer::initialize_crypto().unwrap();
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
