#!/usr/bin/env python3
"""Copy the pinned upstream kernel and apply checked signing-appliance fixes."""
import argparse, hashlib, json, pathlib, shutil, subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--out",required=True,type=pathlib.Path);a=p.parse_args()
metadata=json.loads(subprocess.check_output(["cargo","metadata","--locked","--format-version","1","--filter-platform","x86_64-unknown-hermit"],cwd=ROOT))
hermit=next(x for x in metadata["packages"] if x["name"]=="hermit")
source=pathlib.Path(hermit["manifest_path"]).parent.parent/"kernel"
pins=json.loads((ROOT/"kernel-patches/upstream-sha256.json").read_text())
for name,expected in pins.items():
    if hashlib.sha256((source/name).read_bytes()).hexdigest()!=expected: raise SystemExit("Upstream kernel differs: "+name)
shutil.copytree(source,a.out,dirs_exist_ok=True,ignore=shutil.ignore_patterns("target",".git"))
for change in json.loads((ROOT/"kernel-patches/replacements.json").read_text()):
    file=a.out/change["file"];text=file.read_text()
    if text.count(change["before"])!=change.get("expected_count",1): raise SystemExit("Patch does not apply exactly: "+str(file))
    file.write_text(text.replace(change["before"],change["after"]))
print(a.out.resolve())
