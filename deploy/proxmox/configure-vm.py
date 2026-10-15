#!/usr/bin/env python3
"""Configure only the reserved test VM. Does not alter host bridge/firewall/DHCP."""
import subprocess
import time
from pathlib import Path
VMID = '134'
configuration = subprocess.check_output(['qm', 'config', VMID], text=True)
if 'name: android-signer-test\n' not in configuration:
    raise SystemExit('VM ID belongs to another machine')
if subprocess.check_output(['qm', 'status', VMID], text=True).strip() != 'status: stopped':
    raise SystemExit('Stop the test VM before changing boot and network settings')
for name in ['hermit-loader', 'signer']:
    if not (Path('/var/lib/android-signer') / name).is_file():
        raise SystemExit('Missing boot image: ' + name)
args = ('-kernel /var/lib/android-signer/hermit-loader -initrd /var/lib/android-signer/signer '
        '-object memory-backend-memfd,id=signer-ram,size=2147483648,share=on '
        '-numa node,memdev=signer-ram '
        '-chardev socket,id=signerfs,path=/run/android-signer/fs.sock '
        '-device vhost-user-fs-pci,chardev=signerfs,tag=root '
        '-global virtio-net-pci.disable-legacy=on')
subprocess.run(['qm', 'set', VMID, '--args', args], check=True)
# Verified for this VLAN: the Proxmox bridge, physical NIC and routed gateway
# carry 9000-byte IP packets. Keep the reserved DHCP identity unchanged.
subprocess.run(['qm', 'set', VMID, '--net0',
                'virtio=02:05:53:49:47:01,bridge=vmbr0,tag=5,mtu=9000'], check=True)
for _ in range(100):
    if Path('/run/android-signer/fs.sock').exists():
        break
    time.sleep(0.1)
else:
    raise SystemExit('Read-only filesystem socket unavailable')
subprocess.run(['qm', 'start', VMID], check=True)
