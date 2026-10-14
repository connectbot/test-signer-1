# Hermit Android signing appliance

A Rust HTTPS webhook service linked with Hermit into one bootable image. The guest downloads unsigned APK/AAB files from an allowlisted GitHub Actions run, verifies GitHub's Sigstore provenance for each original file, adds code transparency, signs and verifies both outputs, and uploads them to a **draft GitHub release**. A separate HTTPS collector stores its queue, signing intents, results, and upload receipts durably.

Signing is implemented in Rust using Android-compatible formats. `bundletool`, `apksigner`/apksig, `jarsigner`, a JVM, a shell, and Linux are not in the guest. Java tools are independent host-side interoperability checks. No signing keys are compiled into the image.

## Build and test

Use Rust 1.99.0, Python 3.12+, and the pinned inputs in [toolchain-pins.json](config/toolchain-pins.json). From this directory:

```sh
python3 scripts/build-hermit.py
cargo build --locked --features admin,collector --bin signer-admin --bin audit-collector
cargo test --locked --all-features
cargo clippy --all-features --all-targets -- -D warnings
```

The build helper verifies downloaded hashes, installs Hermit std into an isolated sysroot, and prepares a checked local kernel copy. It never patches the shared Cargo checkout. The image is `target/x86_64-unknown-hermit/release/signer`; its loader is `dist/hermit-loader`. Both are public deployment artifacts. The helper installs the kernel's pinned nightly toolchain through rustup. Ordinary host tests require OpenSSL with ML-DSA-65 support and `jarsigner` on PATH.

Independent Android checks require JDK 25 and Android SDK platform/build-tools 36:

```sh
python3 scripts/test-android.py \
  --java-home /path/to/jdk-25 \
  --android-sdk /path/to/android-sdk
python3 tests/qemu-smoke.py --loader dist/hermit-loader --tcg
```

The reference helper compiles pinned Android 17 apksig source, uses the pinned older verifier for pre-37 platforms, creates matching real AAPT2 manifests, and verifies signatures, lineages, transparency, and bundle structure. Without the helper's environment, the optional external Android checks return early; ordinary `cargo test` is not evidence that those reference checks ran. The QEMU smoke test creates disposable keys, uses a temporary read-only filesystem export, and tests TLS, collector activation/readiness, and webhook authentication. It never contacts GitHub. Its unsandboxed virtiofsd option is limited to these disposable local fixtures.

## Configure the service

Copy [signer.example.json](config/signer.example.json) into a protected host directory as `config.json`. Replace every placeholder: repository numeric ID and full name, package, GitHub App ID, workflow, exact refs, artifact names/files, key fingerprints, lineage hashes, and trust material. Example expiry `0` deliberately fails startup.

The default artifact limit is 64 MiB and applies to downloads, original files, and aggregate ZIP expansion, including the nested APK/AAB. Start with 2 GiB guest memory at that limit; increase memory and test peak usage before raising it. Signing keeps inputs and outputs in memory.

Provision the following into that directory:

- Signing keys as unencrypted PKCS#8 PEM/DER, and corresponding X.509 certificates as PEM/DER. Classical APK, AAB upload, and transparency keys are RSA, at least 2048 bits. Keep the transparency key separate from every current/historical APK and upload key.
- GitHub App RSA private key, a webhook secret of at least 32 bytes, and a separate audit bearer token of at least 32 printable bytes. Share only the audit token with the collector.
- TLS server certificate/key, the collector CA certificate, public Sigstore and/or GitHub private trusted-root JSON, and the authorized APK lineage files.

A certificate fingerprint is SHA-256 of its **DER certificate**, not PEM text or the SPKI. File pins are SHA-256 of the exact bytes. Generate certificate fingerprints with:

```sh
openssl x509 -in apk-a.pem -outform DER -out apk-a.der
sha256sum apk-a.der apk-lineage.bin sigstore-public.json
```

Fetch fresh trusted roots through Sigstore's authenticated trust distribution outside the guest. Pin their bytes and choose an operator-reviewed `valid_until` for this deployment. Replace them before expiry, increment the affected repository policy revisions, and reboot the appliance. The fixtures under `tests/fixtures` are historical interoperability data, not production trust provisioning. Private attestations require a verified RFC3161 timestamp against the private trusted root; they do not bypass certificate, DSSE, timestamp, identity, or CI claim checks.

For the webhook secret, use a printable value and write exactly those bytes to the file, without a trailing newline; enter the same value in GitHub's webhook settings.

Install the GitHub App on only the selected repositories. Grant repository **Actions: read**, **Artifact attestations: read**, **Contents: read/write**, and metadata access. Subscribe it to `workflow_run`; configure its webhook at `https://signer.example.net:8443/webhooks/github` with the provisioned secret. Protect the approved workflow and branches against untrusted edits. The signer checks workflow identity, ref, repository immutable ID, commit, run/attempt, event, runner class, and repository visibility. Direct same-repository workflows are supported; reusable/cross-repository workflows need a separate policy design.

Use [android-build.example.yml](config/android-build.example.yml) as a producer template. It attests **each APK/AAB file**, then uploads unsigned artifacts. An attestation for only the GitHub ZIP or source commit is insufficient. The APK and AAB must have matching package/version, minSdk at least 24, and matching DEX/native code. Do not pre-sign or pre-add transparency. Do not post-process code after the attested build. The template's project setup/output paths need adapting; it is not installed into any repository automatically.

Code transparency follows Android's JWT format and covers DEX/native libraries, not resources/assets/manifests. Android itself does not enforce transparency at installation. `sharedUserId` is rejected. Archive generation must either be explicitly disabled in BundleConfig, or have `archive_resource` provisioned with the exact bundletool version, resource path, source file, and hash that bundletool expects. APKs with code transformed from the AAB are rejected rather than given an unrelated transparency statement. Publish the transparency certificate fingerprint through a trusted channel independently of downloaded artifacts. See [Android's code transparency guide](https://developer.android.com/guide/app-bundle/code-transparency).

## External durable collector

Run the `audit-collector` host binary with `AUDIT_CONFIG` pointing to a completed [collector.example.json](config/collector.example.json). Create its database directory with owner-only permissions. Terminate TLS in the collector itself; issue a server certificate matching the signer's configured audit hostname. The signer verifies that certificate and authenticates every ledger operation with its bearer token.

The collector uses SQLite WAL and `synchronous=FULL`. Back up the database through SQLite's backup mechanism, including its committed state; do not copy an active DB without considering WAL. Keep ledger state across guest reboots, policy updates, and key rotations. Restoring an older ledger snapshot can undo its replay/rotation protections.

Routes: authenticated `GET /v1/health`, `POST /v1/policies`, `POST /v1/jobs`, `POST /v1/claim`, `POST /v1/jobs/{id}/events`, `POST /v1/jobs/{id}/finish`, and `GET /v1/jobs/{id}`. The last route returns job state and the ordered hash-linked audit events. Collector JSON requests are limited to 4 MiB to accommodate long certificate histories; the public webhook remains limited to 256 KiB. Deploy one logical signer configuration containing all repositories served by a collector; claims are global, not partitioned by appliance identity.

A job is deduplicated by repository/run/attempt/full policy hash. Leases expire after five minutes and are renewed every 30 seconds. Recovery records interrupted signing as uncertain; it may deterministically re-sign the same bytes. The collector bounds retries to six attempts, checks active policy on mutations, and prevents policy revision/lineage regression. It acknowledges a signing intent before the corresponding key operation and acknowledges verified results before upload. During collector outages, new signing cannot proceed. Hash links help detect edits relative to a trusted retained anchor; they do not make a compromised collector independently tamper-proof. Retain/replicate audit anchors according to your audit requirements.

A draft release has a job-specific tag/marker and the attested commit as its target. Repeated uploads accept only assets with matching name, size, and GitHub SHA-256; conflicting assets fail. Outputs include `app-signed.apk`, `app-signed.aab`, the transparency JWT/certificate, APK lineage files, and `signing-receipt.json`. Inspect the ledger/receipt and independently verify outputs before publishing a release. The service never publishes one.

## Key rotation and long histories

The host-only `signer-admin` CLI uses clap and does not require a serial port. The guest starts automatically using `/root/config.json`; `SIGNER_CONFIG` can select another startup path where boot environment support is configured. Serial is for kernel/application diagnostics.

Initialize A, append A→B, then B→C offline:

```sh
target/debug/signer-admin init --key apk-a.pk8 --cert apk-a.pem --out lineage-a.bin
target/debug/signer-admin append --input lineage-a.bin \
  --old-key apk-a.pk8 --old-cert apk-a.pem \
  --new-key apk-b.pk8 --new-cert apk-b.pem --out lineage-ab.bin
target/debug/signer-admin append --input lineage-ab.bin \
  --old-key apk-b.pk8 --old-cert apk-b.pem \
  --new-key apk-c.pk8 --new-cert apk-c.pem --out lineage-abc.bin
target/debug/signer-admin inspect --input lineage-abc.bin
```

Preserve the full chain. There is no three-key/count cap; the default byte guard is 1 MiB, configurable up to 16 MiB. Tests exercise 64 certificates. The CLI refuses to overwrite output files. `import --input ... --expected-root <DER-certificate-sha256> --out ...` validates an apksigner lineage against an independently authorized root. Default capabilities include installed data, shared UID, permission, and authentication; rollback is disabled and requires explicit authorization in both the CLI and service policy.

Set `original_key` to A, `current_key` to the latest classical head, and update the pinned lineage/hash. Increment that repository's policy `revision` on every signing-policy change. The policy digest includes the resolved key certificate fingerprints, trust-root pin/expiry, and artifact/lineage limits as well as repository rules. Replacing key material under the same role name therefore requires a new revision too. Keep A available for the API24 v2 signer; older classical private keys other than that required original and the current head can be removed from the online appliance once the next proofs are prepared. Historical certificates/proofs remain in the lineage. Upload-key and transparency-key rotation are separate operational processes, not APK proof-of-rotation.

Default `rotation_min_sdk: 33` preserves the original v3 signer for API28–32 and uses the rotated signer in v3.1 for API33+. Set 28 only for an existing deployment whose classical rotation intentionally starts at API28. There is no APK v1 signing.

For Android 17/API37 hybrid signing, provision fresh RSA-4096 and ML-DSA-65 PKCS#8 keys/certificates, then:

```sh
target/debug/signer-admin hybrid --input lineage-abc.bin \
  --old-key apk-c.pk8 --old-cert apk-c.pem \
  --rsa-key hybrid-rsa-b.pk8 --rsa-cert hybrid-rsa-b.pem \
  --pqc-key hybrid-pqc-b.pk8 --pqc-cert hybrid-pqc-b.pem \
  --out-directory hybrid-b
```

This produces two sibling terminal proofs and an independently signed RSA→PQC effective chain. Add those key roles to `keys` and fill [hybrid.example.json](config/hybrid.example.json) into `signing.hybrid`. Classical signing remains available for older Android versions; v3.2 contains both hybrid signers. For a later hybrid generation, use the previous `effective-lineage.bin` as input and its terminal PQC key as `--old-key`, with fresh RSA/PQC keys. Keep complete ancestry and increment policy revision. The previous effective chain can also authorize additional classical fallback transitions; all configured histories must remain compatible.

## QEMU and Proxmox

The tested QEMU profile is `pc`/i440fx, one vCPU, modern VirtIO PCI networking and read-only VirtIO FS, and direct loader/image boot:

```sh
python3 scripts/run-qemu.py --secrets /protected/android-signer --memory 2G
```

The helper uses KVM and `-cpu host`; `--tcg` is for local testing. **RDSEED must be exposed.** The checked kernel removes insecure entropy fallback; the application also rejects CPUs without RDSEED and tests OS entropy before loading keys. A VirtIO RNG device alone does not fix entropy for this pinned kernel. The guest's clock must be valid for TLS/provenance/trust expiry. Use a correct host RTC and keep the host synchronized.

Keep the secret directory private to the host/service identity and export it with `virtiofsd --readonly` and namespace isolation. The mount tag `root` becomes `/root` in Hermit. The helper forwards only localhost TCP8443; production networking/ingress must expose the HTTPS webhook endpoint deliberately. `/healthz` checks the process; `/readyz` also checks trust expiry and the ledger connection. Allow outbound HTTPS to GitHub API/upload hosts, GitHub artifact storage, and the collector, plus required DNS.

For Proxmox, use a **new dedicated VM** with one core, `cpu: host`, 2 GiB fixed memory, ballooning disabled, SeaBIOS, an i440fx machine, VirtIO networking, and serial diagnostics. Host-side `args` must direct-boot the loader with `-kernel` and the signer with `-initrd`, and attach the read-only filesystem socket with shared memory. An example fragment is in [proxmox.example.conf](config/proxmox.example.conf); prepare the host filesystem service before starting the VM and inspect `qm showcmd` for the actual QEMU arguments. This fragment has not been deployed or validated on your Proxmox cluster. No guest Linux disk, cloud-init, SSH server, or guest agent is needed. Keys live in a host-managed export, so VM backups are not a key-backup plan. Disable migration/snapshots of this signing VM unless your key-handling and external-ledger recovery processes explicitly support them.

`-machine microvm` is not supported by the tested image: the loader reaches Hermit, then APIC initialization panics. It would need an MMIO kernel/device profile and separate validation; do not substitute it in the launch helper yet. See [QEMU microvm documentation](https://www.qemu.org/docs/master/system/i386/microvm.html) and [Proxmox VM options](https://github.com/proxmox/pve-docs/blob/master/generated/qm.1-synopsis.adoc).

## Implementation boundaries

This is a new signing-format implementation. Android reference verification and local guest smoke tests do not establish Play Console acceptance, on-device upgrade/downgrade behavior, or live GitHub end-to-end behavior. Validate those with a disposable repository/application and test keys before provisioning production keys. The external tools and kernel fixes are pinned for review, but RustCrypto's TLS provider is an alpha release and the application is not independently audited.

The checked kernel patches halt on entropy failures, bound kernel TCP connects to 15 seconds, prevent nonblocking socket destruction from waiting on a peer, and convert executor Unix-epoch deadlines into the relative futex durations the kernel expects. A companion scheduler patch ignores a second wake notification for a task that its timer already woke, preventing a futex timeout race from panicking. Nonblocking drop aborts the socket; interrupted clients may need to retry. Queue IDs and matching asset checks support safe retry. The vendored hyper-util patch uses a blocking task for Hermit's synchronous connect and registers the successfully connected stream without the unsupported SO_ERROR query. The vendored socket2 fork also returns unrecognized OS errors rather than panicking. These adaptations are specific to the pinned Hermit kernel and should be re-evaluated on upgrades.
