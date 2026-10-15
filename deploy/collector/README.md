# External audit collector

Package a separately built Linux `audit-collector` binary with this Dockerfile.
The image contains no TLS keys, audit tokens, configuration or ledger. Mount its
configuration at `/config/collector.json`, TLS certificate/key and bearer token
from a Kubernetes Secret, and a persistent volume at `/data`. Run one replica
with a Recreate update strategy because the ledger uses SQLite.

The ConnectBot integration test runs this service in beta-cluster's `security`
namespace through the app-template chart. Flux keeps its credentials encrypted
with SOPS. The internal Envoy gateway verifies the collector's backend TLS;
the API additionally requires its bearer token on every endpoint. APK signing
keys remain in the Hermit appliance, outside the collector.
