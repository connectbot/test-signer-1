# Disposable Android signer integration test

This repository tests the Hermit signing appliance with ConnectBot source and
separate test keys. It is not a ConnectBot release channel. Signed releases stay
as drafts for independent verification; none are automatically published.

Source baseline: connectbot/connectbot at
500982cdc99e469d5591b5d2e1dc5ba798289a76 (v1.11.1).

The signer App must be installed on this repository only. Signing stays disabled
until an independently exported public policy replaces the placeholder and
ANDROID_SIGNER_ENABLED is enabled. No private keys belong in this repository or
GitHub Actions secrets.
