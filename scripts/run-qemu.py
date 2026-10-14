#!/usr/bin/env python3
"""Run a read-only secret export and the signer. No disks are attached."""
import argparse, os, pathlib, shutil, subprocess, tempfile, time
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--secrets", required=True, type=pathlib.Path)
p.add_argument("--loader", type=pathlib.Path, default=ROOT / "dist/hermit-loader")
p.add_argument("--image", type=pathlib.Path, default=ROOT / "target/x86_64-unknown-hermit/release/signer")
p.add_argument("--gdb-port", type=int, help="Local guest debugging only")
p.add_argument("--port", type=int, default=8443)
p.add_argument("--memory", default="2G")
p.add_argument("--tcg", action="store_true", help="Local testing without KVM")
p.add_argument("--test-unsandboxed-fs", action="store_true", help="Ephemeral local fixtures only; production uses namespace isolation")
a = p.parse_args()
if not (a.secrets / "config.json").is_file():
    p.error("Secret export must contain config.json")
virtiofsd = shutil.which("virtiofsd") or "/usr/libexec/virtiofsd"
with tempfile.TemporaryDirectory(prefix="android-signer-qemu-") as temporary:
    socket = pathlib.Path(temporary) / "fs.sock"
    daemon = subprocess.Popen([virtiofsd, "--socket-path=" + str(socket), "--shared-dir=" + str(a.secrets.resolve()), "--readonly", "--sandbox=" + ("none" if a.test_unsandboxed_fs else "namespace")])
    try:
        for _ in range(100):
            if socket.exists(): break
            if daemon.poll() is not None: raise SystemExit("virtiofsd failed")
            time.sleep(.05)
        else: raise SystemExit("virtiofsd socket unavailable")
        command = ["qemu-system-x86_64", "-machine", "pc", "-accel", "tcg" if a.tcg else "kvm", "-cpu", "max" if a.tcg else "host", "-smp", "1", "-m", a.memory,
            "-object", "memory-backend-memfd,id=ram,size=" + a.memory + ",share=on", "-numa", "node,memdev=ram", "-nodefaults", "-no-user-config", "-display", "none", "-serial", "stdio", "-no-reboot",
            "-kernel", str(a.loader.resolve()), "-initrd", str(a.image.resolve()),
            "-chardev", "socket,id=fs,path=" + str(socket), "-device", "vhost-user-fs-pci,chardev=fs,tag=root",
            "-netdev", f"user,id=net,hostfwd=tcp:127.0.0.1:{a.port}-:8443", "-device", "virtio-net-pci,netdev=net,disable-legacy=on"]
        if a.gdb_port: command += ["-gdb", f"tcp:127.0.0.1:{a.gdb_port}"]
        raise SystemExit(subprocess.call(command))
    finally:
        daemon.terminate()
        try: daemon.wait(timeout=5)
        except subprocess.TimeoutExpired:
            daemon.kill(); daemon.wait()
