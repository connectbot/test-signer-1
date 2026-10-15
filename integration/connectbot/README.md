# ConnectBot integration

The `.github` tree contains the reviewed workflow/helper changes for
`~/git/connectbot`. The public policy starts unconfigured and the finalizer is
disabled unless repository variable `ANDROID_SIGNER_ENABLED=true`.

The build no longer accepts caller-controlled `is_push`; it derives eligibility
from GitHub's push event. Source attestation jobs run separately from Gradle.
The webhook comes from the GitHub App after workflow completion. The finalizer
uses the original run/attempt, not its default-branch SHA, to select inputs.

See [deployment and verification instructions](../../docs/slsa.md).
