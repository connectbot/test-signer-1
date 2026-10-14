# Public interoperability data

Copied from [sigstore/sigstore-rust at f950b1b683560aadf7737539f8d7eaa656a9f0c0](https://github.com/sigstore/sigstore-rust/tree/f950b1b683560aadf7737539f8d7eaa656a9f0c0): its `sigstore-verify` test bundles and `sigstore-trust-root` embedded roots.

`github-public.sigstore.json` is the upstream conda attestation signed by a GitHub Actions workflow under public Sigstore trust. `github-private.sigstore.json` is an upstream GitHub private-trust timestamped attestation whose certificate identifies `dotcom.releases.github.com`; it is not a GitHub Actions workflow identity.

These bundles exercise the RustCrypto provider, certificate chains, DSSE binding, public transparency-log evidence, private timestamp verification, and rejection of wrong digests/identities. They do not demonstrate acceptance by this application's stricter SLSA/workflow/run policy. No private signing keys are included. The historical roots are test fixtures, not production trust provisioning.
