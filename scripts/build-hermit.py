#!/usr/bin/env python3
"""Fetch hash-pinned build inputs and compile the single Hermit guest image."""
import argparse, hashlib, json, os, pathlib, subprocess, tarfile, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--cache", type=pathlib.Path, default=ROOT / "dist")
a = p.parse_args()
a.cache.mkdir(parents=True, exist_ok=True)
pins = json.loads((ROOT / "config/toolchain-pins.json").read_text())
def download(kind, name):
    out = a.cache / name
    if not out.exists():
        with urllib.request.urlopen(pins[kind + "_url"], timeout=120) as response:
            out.write_bytes(response.read())
    if hashlib.sha256(out.read_bytes()).hexdigest() != pins[kind + "_sha256"]:
        raise SystemExit(f"Hash mismatch: {out}")
    return out
archive = download("hermit_std", "hermit-std.tar.gz")
loader = download("loader", "hermit-loader")
std = a.cache / "std"
sysroot = a.cache / "sysroot"
if not (sysroot / "lib/rustlib/x86_64-unknown-hermit/lib").exists():
    std.mkdir(exist_ok=True)
    with tarfile.open(archive) as tar:
        tar.extractall(std, filter="data")
    install = next(std.glob("*/rust-install.sh"))
    subprocess.run(["bash", str(install), "--prefix=" + str(sysroot.resolve()), "--disable-ldconfig"], check=True)
subprocess.run(["rustup", "toolchain", "install", pins["hermit_kernel_toolchain"], "--component", "rust-src", "--component", "llvm-tools"], check=True)
kernel=a.cache/"kernel"
subprocess.run(["python3",str(ROOT/"scripts/prepare-kernel.py"),"--out",str(kernel)],check=True)
subprocess.run(["cargo", "build", "--locked", "--release", "--bin", "signer", "--target", "x86_64-unknown-hermit", "--config", 'target.x86_64-unknown-hermit.rustflags=["--sysroot=' + str(sysroot.resolve()) + '"]'], cwd=ROOT, env={**os.environ,"HERMIT_MANIFEST_DIR":str(kernel.resolve())}, check=True)
image=ROOT / "target/x86_64-unknown-hermit/release/signer"
contents=image.read_bytes()
if b"Fallback to a naive implementation" in contents or b"Android signer: strict entropy profile v1" not in contents or b"Secure entropy unavailable: RDSEED is required" not in contents:
    raise SystemExit("Image contains stale/unpatched code; clean the Hermit and android-signer target artifacts and rebuild")
print("Image:", image)
print("Loader:", loader)
