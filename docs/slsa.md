# SLSA v1 Build Level 3 release pipeline

The trusted platform consists of the reviewed GitHub reusable workflows and
verification helpers, GitHub-hosted ephemeral runners and Sigstore, the Hermit
signing appliance and its hypervisor/operators, and the authenticated durable
collector. Application Gradle tasks execute outside the provenance credential
boundary. The remote signer is an explicit part of the signing transformation;
GitHub provenance alone does not establish the appliance's integrity.

## Flow and identities

1. `ci.yml` or `ci-tags.yml` calls `ci-build.yml`. Its release jobs build without
   OIDC/attestation permissions, signing keys, or shared Gradle caches. There are
   no caller-controlled build commands or `workflow_call` build inputs. Flavors
   and commands are fixed in the reviewed workflow; source/configuration and
   wrapper/dependency versions come from the source commit.
2. Fresh hosted jobs in that reusable workflow attest the exact original APK/AAB
   files, downloaded from immutable artifacts named `unsigned-FLAVOR-ATTEMPT`.
   Output names/digests are the SLSA-permitted tenant-provided fields. No Gradle,
   downloaded executables, application scripts, or caches run in these jobs.
3. GitHub's authenticated `workflow_run: completed` App webhook queues one job
   per signing profile only after the whole source workflow succeeds. The
   signer separately verifies caller and reusable builder certificate claims,
   source/run/attempt/runner/visibility, workflow contents, helper pins, artifact
   IDs/archive hashes, provenance signatures and verified time evidence.
4. Hermit adds code transparency, signs APKs with their full rotation history,
   and signs AABs with the upload key only. It records intents before key use
   and authenticates the resulting transaction with a separate RSA DSSE receipt
   key. Per-profile staging drafts are never automatically published.
5. A `workflow_run` gate dispatches a default-branch finalizer that calls
   `release-attest.yml`. It executes the trusted
   default-branch helper, never the triggering source commit. It verifies both
   receipts, public policy, original provenance, payload preservation, Android
   reference signatures, lineage and transparency before attesting final hashes.
   A separate verified draft contains both variants and evidence. Publication is
   manual. The finalizer has a 30-minute signing wait and a 60-minute job limit.

Finalization can be retried with `workflow_dispatch` on the repository's
default branch, supplying `source_run` and `source_attempt`. The same successful
push-build, repository, provenance, policy, and payload checks apply. This lets
operators recover verification or publication of the draft without rebuilding
already-attested inputs or executing their source in the finalizer. Both the
workflow and helper enforce the default-branch context. GitHub uploads left in
`starter` state without a digest are removed from managed drafts before retry;
conflicting completed assets remain errors. Final provenance uses GitHub's
supported workflow build type, records the dispatch inputs alongside the
default-branch workflow identity, and binds source/receipt/policy dependencies.
The automatic gate dispatches this workflow because that build type supports
`workflow_dispatch`, not `workflow_run`, as the attested execution event.

The certificate SAN and `build_signer_uri` identify the reusable builder;
`build_config_uri` and provenance's external `workflow` identify the caller.
Their commits may differ. Builder/helper files are fetched at the certificate's
builder commit and compared to independent SHA-256 allowlists. Cross-repository
builders require the App installation to read that repository too. Ref patterns
support exact refs and a single trailing `*` for tag prefixes only.

## Deployment and migration

Use `config/connectbot.example.json` for two profiles and the 128 MiB expanded
artifact bound. Provision the bundletool 1.18.3 archive `classes.dex` at the pinned
path/hash; do not modify already-attested bundles. Workflow pins in this example
match the integration files shipped with this change and must be updated after
any reviewed workflow edit.

For an existing configuration:

```
python3 scripts/migrate-config.py old.json new.json --profile oss
```

This deliberately leaves invalid trust-pin placeholders. Replace them, provision
an independent receipt key/certificate, add the second profile, and review the
new policy before booting. The collector accepts a legacy policy only with the
explicit `migrate_legacy_profile` mapping and an increased revision. It preserves
all old events and key history, rejects removal/regression of existing profile
histories, and closes pending/running jobs under the superseded policy. Back up
the SQLite database with SQLite's backup API before upgrading; do not reset it.
Deploy the collector before the new guest. Retain the migration mapping in the
configuration so its policy hash remains stable.

Build the deployed image with `SIGNER_SOURCE_REVISION` set to the full reviewed
40-character source commit. Development builds identify themselves as
`development-unmeasured` and are deliberately rejected by the finalizer. Retain
the loader/image hashes with the deployment record; a receipt's version string
is not a hardware measurement or protection against a compromised hypervisor.

Export the independently reviewed public policy on the provisioning host:

```
cargo run --locked --features admin --bin signer-admin -- export-release-policy \
  --config /secure/config.json --repository connectbot/connectbot \
  --signer-revision FULL_DEPLOYED_SOURCE_COMMIT --out public-policy.json
```

Copy that public file to ConnectBot's `.github/signer-policy.json`. It contains
public certificates/fingerprints and policy metadata only. Protect the reusable
workflows, helper code, tool pins and this policy through repository rules and
review. Set repository variable `ANDROID_SIGNER_ENABLED=true` only when the App,
collector, VM and networking are ready. Install the App with Actions/read,
attestations/read and contents/write; its webhook URL ends in
`/webhooks/github`. No signing credentials are supplied to Actions. The final
workflow disables registry storage records and needs only the listed scoped
permissions. Main and version-tag pushes are eligible; PR/scheduled/fork builds
are not signing requests.

## Final provenance contract

`buildType: urn:android-signer:buildtype:verified-signing:v1` describes the fixed
verification/signing transformation above. `externalParameters.sourceRun` is the
original source-run/attempt URI; `profiles` is the sorted configured profile set.
These are the full behavioral inputs at this workflow interface. Signing policy
and deployed signer source revision are pinned resolved dependencies, alongside
the unsigned APK/AAB hashes, their original attestation hashes, and authenticated
receipt hashes. `internalParameters` records the actual finalizer workflow,
commit and verified transaction/rotation details. The builder and invocation
identify the final reusable workflow/run, not the upstream Android build.

Receipts use in-toto Statement v1 inside DSSE with payload type
`application/vnd.in-toto+json` and predicate type `urn:android-signer:receipt:v2`.
The single RSA PKCS#1 v1.5 SHA-256 signature covers DSSE PAE bytes, with certificate
DER SHA-256 as key ID. The JSON receipt is convenience data; it must equal the
verified DSSE predicate. Rotation proofs affect APK signing only; uploading the
AAB to Play still uses its upload key. Play's subsequent app-signing transform
is outside this provenance boundary.

For a downloaded signed artifact:

```
gh attestation verify oss-app-signed.apk --repo connectbot/connectbot \
  --signer-workflow connectbot/connectbot/.github/workflows/release-attest.yml \
  --deny-self-hosted-runners --format json
```

Also verify the expected finalizer commit/ref (`--source-digest`, `--source-ref`,
`--signer-digest`), original source run and the receipt/dependency chain against
your independently obtained policy. A valid Sigstore signature alone is not
semantic authorization. `signer-admin verify-receipt` verifies an offline DSSE
receipt against an independently pinned DER certificate; it does not authorize
its policy, job or output files by itself.

## Acceptance evidence and remaining gates

Automated checks cover certificate-policy substitutions, public/private Sigstore
cryptography, receipt tampering/domain separation, profile/run/policy
substitution, durable migration/dedup/lease handling, and Android reference
signature/transparency/rotation interoperability. Adversarial authorization
fixtures include synthetic claims after the cryptographic boundary. A genuine
ConnectBot v1.11.1 reusable-workflow bundle passes the full application verifier;
that historical fixture does not test the new live deployment.

Before claiming deployment-level conformance, run the disposable-repository
harness with real GitHub reusable-workflow attestations, both profiles and test
keys, preserve the resulting genuine bundles, and verify them independently with
`gh`. Confirm failed builds/forks cannot reach signing, modified artifacts and
receipts fail, retries are idempotent, and both variants are required for the
final draft. Verify repository controls, ephemeral runner isolation, secret and
cache boundaries, collector persistence/backup, image pins, trust refresh and
patching procedures. Record evidence against each SLSA platform requirement;
passing local tests is not an automatic Level 3 certification.

References: [GitHub reusable workflow guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating),
[SLSA v1 platform requirements](https://slsa.dev/spec/v1.0/requirements),
[SLSA v1 provenance](https://slsa.dev/spec/v1.0/provenance).

## Disposable-repository live harness

For a new organization-owned test App, run
`python3 scripts/register-github-app.py --out /secure/new-test-app-directory`
on the workstation with the browser. The loopback-only helper prepares the
ConnectBot App manifest, checks callback state and writes generated credentials
to a new private directory. Follow its registration URL and install on
`connectbot/test-signer-1` only. It requests Actions/read, attestations/read,
contents/write and workflow_run events, with no OAuth user authorization.
Keep its local registration output out of source control.

The test collector runs separately in beta-cluster using the app-template chart,
a persistent SQLite volume, Recreate updates and VolSync backup integration.
Its private endpoint is `https://signer-audit.their.net`, through `envoy-dmz`
at `10.200.0.7:443`; Envoy validates
backend TLS and the collector requires its bearer token. Flux stores its TLS
key and token encrypted with SOPS. See `deploy/collector/` for the container.

Use a public disposable repository, separate test keys and a collector database
that is not the production ledger. Install the integration on its default branch,
configure its immutable repository ID and workflow hashes in the appliance,
export its public policy into `.github/signer-policy.json`, and install the App
on only that repository. The existing ConnectBot release-metadata job is scoped
to production, but both unsigned build/attestation jobs and the finalizer work
in the test repository. Enable `ANDROID_SIGNER_ENABLED` only after provisioning.
Push a reviewed test commit, wait for source CI/signing/finalization, then run:

```
python3 scripts/slsa-live-test.py --policy /secure/test-public-policy.json \
  --source-run RUN_ID --source-attempt 1 \
  --finalizer-commit FULL_APPROVED_DEFAULT_BRANCH_COMMIT \
  --tools /tmp/signer-reference-tools --report /tmp/signer-live-evidence.json
```

Use JDK 25 and an authenticated GitHub CLI account with access to the draft.
The harness downloads the immutable original artifacts and final release assets,
verifies the final GitHub identity and predicate, the upstream attestations,
authenticated receipts, exact payload preservation, Android signatures, full
lineage and code transparency for both variants. It also requires rejection of
modified APK/AAB bytes, modified receipts and wrong run attempts. It writes an
evidence report only after all checks pass. It never publishes the draft or uses
production keys. Preserve genuine bundles and the report with deployment evidence.
