#!/usr/bin/env python3
"""Run as root on the authorized Proxmox host; installs provisioning TLS only."""
import json
import os
from pathlib import Path
import subprocess

BASE = Path('/var/lib/android-signer')
ROOT = BASE / 'root'
ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
BASE.chmod(0o700)
ROOT.chmod(0o700)
os.umask(0o077)


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


# Keep the CA key outside the VM export. The leaf is not a CA certificate.
if not (BASE / 'ca.key.pem').exists():
    run('openssl', 'req', '-new', '-x509', '-newkey', 'rsa:3072', '-nodes',
        '-keyout', str(BASE / 'ca.key.pem'), '-out', str(BASE / 'ca.pem'),
        '-days', '365', '-subj', '/CN=Android-signer-test-CA',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    if not (ROOT / 'tls.key.pem').exists():
        run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072',
            '-out', str(ROOT / 'tls.key.pem'))
    run('openssl', 'req', '-new', '-key', str(ROOT / 'tls.key.pem'),
        '-out', str(BASE / 'tls.csr'), '-subj', '/CN=android-signer.internal')
    (BASE / 'tls.ext').write_text('subjectAltName=DNS:android-signer.internal\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    run('openssl', 'x509', '-req', '-in', str(BASE / 'tls.csr'), '-CA', str(BASE / 'ca.pem'),
        '-CAkey', str(BASE / 'ca.key.pem'), '-CAcreateserial', '-out', str(ROOT / 'tls.pem'),
        '-days', '90', '-extfile', str(BASE / 'tls.ext'))
if not (ROOT / 'config.json').exists():
    (ROOT / 'bootstrap.json').write_text(json.dumps({'listen': '0.0.0.0:443',
        'tls_certificate': '/root/tls.pem', 'tls_private_key': '/root/tls.key.pem'}) + '\n')
for path in ROOT.iterdir():
    if path.is_file():
        path.chmod(0o600)
Path('/etc/systemd/system/android-signer-virtiofs.service').write_text('''[Unit]
Description=Read-only Hermit Android signer root export
After=local-fs.target
Before=pve-guests.service

[Service]
Type=simple
RuntimeDirectory=android-signer
RuntimeDirectoryMode=0700
ExecStart=/usr/libexec/virtiofsd --socket-path=/run/android-signer/fs.sock --shared-dir=/var/lib/android-signer/root --readonly --sandbox=namespace
Restart=always
RestartSec=1
UMask=0077

[Install]
WantedBy=multi-user.target
''')
run('systemctl', 'daemon-reload')
run('systemctl', 'enable', '--now', 'android-signer-virtiofs.service')
print((BASE / 'ca.pem').read_text())
