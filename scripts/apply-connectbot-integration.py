#!/usr/bin/env python3
"""Install the reviewed ConnectBot integration without overwriting local changes."""
import argparse
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
source = ROOT / "integration/connectbot"
changes = []
for original in sorted((source / ".github").rglob("*")):
    if not original.is_file() or "__pycache__" in original.parts:
        continue
    relative = original.relative_to(source)
    target = args.repo / relative
    wanted = original.read_bytes()
    if target.exists():
        current = target.read_bytes()
        if current == wanted:
            continue
        previous = subprocess.run(["git", "show", f"HEAD:{relative.as_posix()}"], cwd=args.repo,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if previous.returncode or current != previous.stdout:
            raise SystemExit(f"Refusing to overwrite local changes: {relative}")
    changes.append((target, wanted))
for target, wanted in changes:
    print(target.relative_to(args.repo))
    if not args.check:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(wanted)
