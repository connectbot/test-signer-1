# Public interoperability data

Copied from [sigstore/sigstore-rust at f950b1b683560aadf7737539f8d7eaa656a9f0c0](https://github.com/sigstore/sigstore-rust/tree/f950b1b683560aadf7737539f8d7eaa656a9f0c0): its `sigstore-verify` test bundles and `sigstore-trust-root` embedded roots.

`github-public.sigstore.json` is the upstream conda attestation signed by a GitHub Actions workflow under public Sigstore trust. `github-private.sigstore.json` is an upstream GitHub private-trust timestamped attestation whose certificate identifies `dotcom.releases.github.com`; it is not a GitHub Actions workflow identity.

These bundles exercise the RustCrypto provider, certificate chains, DSSE binding, public transparency-log evidence, private timestamp verification, and rejection of wrong digests/identities. They do not demonstrate acceptance by this application's stricter SLSA/workflow/run policy. No private signing keys are included. The historical roots are test fixtures, not production trust provisioning.

`connectbot-reusable.sigstore.json` is the public `provenance-oss.json` release
asset from ConnectBot v1.11.1 (asset SHA-256
`c91578d65438e4d780556447351d85b65c0b31d528534dd041078bbb2b562af2`).
It attests unsigned APK/AAB hashes from commit
`500982cdc99e469d5591b5d2e1dc5ba798289a76`, GitHub Actions run
`38365824978`, attempt 1, with caller `ci.yml` and reusable builder `ci-build.yml`.
The application verifier exercises its real certificate, DSSE, transparency
evidence and full caller/builder/run policy. Workflow content pins are checked
separately by the network pipeline and cannot be established from this fixture
alone. This historical evidence is not a test of the new live deployment.
