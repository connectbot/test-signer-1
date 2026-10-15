# Proxmox test appliance

Provisioned on `root@10.100.10.13`:

| Setting | Value |
| --- | --- |
| VM | 134 / android-signer-test |
| CPU / RAM | host / 1 vCPU / 2048 MiB, balloon disabled |
| NIC | VirtIO, vmbr0, VLAN 5 |
| MTU | 9000 (advertised to Hermit through VirtIO) |
| MAC | 02:05:53:49:47:01 |
| Reserved IP | 10.100.5.29 |
| Backend DNS | android-signer-test.dmz.la.gs |
| Public webhook | https://signer.their.net/webhooks/github |
| Guest listener | HTTPS 443 |
| Boot files | /var/lib/android-signer/hermit-loader, /var/lib/android-signer/signer |
| Read-only export | /var/lib/android-signer/root |
| virtiofs service | android-signer-virtiofs.service |

The guest has no Linux kernel or disk. Proxmox's QEMU runs the Hermit loader and
app image directly. The read-only virtiofs daemon uses namespace isolation and
exports only the dedicated root directory. Its service is enabled; the test VM
has automatic startup disabled until provisioning is complete.

`provision-host.py` installs a host-local CA and a 90-day server certificate for
`android-signer.internal`. The CA private key stays outside the VM export. The
public CA goes into the Flux `android-signer-ca` ConfigMap; Envoy verifies the
backend certificate and SNI. Renew/replace this provisioning certificate before
expiry and update the public CA pin if its issuer changes. This script does not
install Android keys or GitHub credentials.

With `bootstrap.json` present and operational `config.json` absent, the VM serves
`/healthz` with `mode=provisioning` and `signing_enabled=false`. `/readyz` and
`POST /webhooks/github` return 503. An invalid operational config never falls
back to provisioning. Install a reviewed version 2 config and its test secrets,
collector and GitHub App credentials, then restart the guest to enable signing.
See [the SLSA guide](../../docs/slsa.md) for the deployment gate.

The Flux addition exposes only exact `POST /webhooks/github` publicly. Health and
readiness are available through the internal gateway. The webhook authenticates
GitHub HMAC itself. Browser SSO is not attached. External GETs and other paths do
not reach the appliance. The backend hostname is stored in the existing SOPS
cluster settings; existing values were compared in memory and preserved.

The user provisions DHCP and firewall rules. Allow the beta Envoy backend
connection to VM TCP 443, DHCP/DNS and the appliance's necessary outbound HTTPS
to GitHub/storage and its authenticated collector. Port 80 is unused by this
appliance. Collector networking and GitHub App setup remain separate steps.

MTU 9000 matches this host's physical NIC, OVS bridge and VLAN interfaces. A
8972-byte ICMP payload with IPv4 fragmentation disabled reached the VLAN 5
gateway (9000 bytes including IP/ICMP headers). Internet paths can use smaller
MTUs; jumbo frames must not be assumed for other deployments. Recheck the path
when changing bridges, VLANs or gateways.

The guest also passed five consecutive full-size `ping -M do -s 8972` probes
from pve3 with zero loss, and its CA-verified HTTPS health check passed. This
required the checked VirtIO Ethernet-header fix in `kernel-patches/`: upstream
Hermit advertised 9000 but dropped IP packets larger than 8986 bytes. The beta3
node's physical and Cilium interfaces also report 9000. Connectivity from Envoy
still requires firewall access from the beta nodes to the guest's TCP 443.

Boot arguments are maintained in `configure-vm.py`; it checks the VM name before
changing VM 134. Its memfd-backed RAM is shared only for the local virtiofs
transport. This export/image is local to pve3: do not live-migrate the VM or
restore an old signing ledger without a separately reviewed procedure.
