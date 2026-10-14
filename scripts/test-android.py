#!/usr/bin/env python3
"""Prepare pinned Android reference verifiers and run interoperability tests."""
import argparse, hashlib, json, os, pathlib, subprocess, tarfile, urllib.request, zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument("--cache",type=pathlib.Path,default=ROOT/"dist/reference");p.add_argument("--java-home",type=pathlib.Path,required=True);p.add_argument("--android-sdk",type=pathlib.Path,required=True);p.add_argument("--build-tools",default="36.0.0");p.add_argument("--platform",default="android-36");a=p.parse_args();a.cache.mkdir(parents=True,exist_ok=True)
pins=json.loads((ROOT/"config/toolchain-pins.json").read_text())
def download(kind,name):
    out=a.cache/name
    if not out.exists():
        with urllib.request.urlopen(pins[kind+"_url"],timeout=120) as response: out.write_bytes(response.read())
    if hashlib.sha256(out.read_bytes()).hexdigest()!=pins[kind+"_sha256"]: raise SystemExit("Hash mismatch: "+str(out))
    return out
source=download("apksig_source","apksig-source.tar.gz");legacy=download("apksig_legacy","apksig-legacy.jar");bundletool=download("bundletool","bundletool.jar")
source_dir=a.cache/"source";source_dir.mkdir(exist_ok=True)
with tarfile.open(source) as tar: tar.extractall(source_dir,filter="data")
classes=a.cache/"classes";old_classes=a.cache/"legacy";classes.mkdir(exist_ok=True);old_classes.mkdir(exist_ok=True)
# Optional cloud-KMS modules require unrelated cloud SDKs. Core apksig sources
# are compiled unmodified, including all v3.2 and ML-DSA verification code.
sources=[str(x.resolve()) for x in (source_dir/"src/main/java").rglob("*.java") if "/kms/aws/" not in str(x) and "/kms/gcp/" not in str(x)]
sources.append(str(ROOT/"tests/Reference.java"));arguments=a.cache/"sources.txt";arguments.write_text("\n".join(sources))
subprocess.run([str(a.java_home/"bin/javac"),"-d",str(classes),"@"+str(arguments)],check=True)
subprocess.run([str(a.java_home/"bin/javac"),"-cp",str(legacy),"-d",str(old_classes),str(ROOT/"tests/Reference.java")],check=True)
fixture=source_dir/"src/test/resources/com/android/apksig/golden-aligned-in.apk"
manifest=a.cache/"AndroidManifest.xml"
manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.example" android:versionCode="1" android:versionName="1"><uses-sdk android:minSdkVersion="24" android:targetSdkVersion="36"/><application android:hasCode="true" /></manifest>')
aapt=a.android_sdk/"build-tools"/a.build_tools/"aapt2"
platform=a.android_sdk/"platforms"/a.platform/"android.jar"
proto=a.cache/"proto.apk";apk=a.cache/"unsigned.apk"
for output,extra in [(proto,["--proto-format"]),(apk,[])]:
    subprocess.run([str(aapt),"link",*extra,"-I",str(platform),"--manifest",str(manifest),"-o",str(output)],check=True)
with zipfile.ZipFile(fixture) as original: dex=original.read("classes.dex")
with zipfile.ZipFile(apk,"a") as out: out.writestr("classes.dex",dex)
module=a.cache/"module.zip"
with zipfile.ZipFile(proto) as original,zipfile.ZipFile(module,"w") as out:
    for name in original.namelist(): out.writestr("manifest/AndroidManifest.xml" if name=="AndroidManifest.xml" else name,original.read(name))
    out.writestr("dex/classes.dex",dex)
config=a.cache/"bundle-config.json";config.write_text(json.dumps({"optimizations":{"storeArchive":{"enabled":False}}}))
aab=a.cache/"unsigned.aab"
subprocess.run([str(a.java_home/"bin/java"),"-jar",str(bundletool),"build-bundle","--modules="+str(module),"--config="+str(config),"--output="+str(aab),"--overwrite"],check=True)
env={**os.environ,"ANDROID_SIGNER_REFERENCE_CLASSES":str(classes.resolve()),"ANDROID_SIGNER_LEGACY_CLASSES":str(old_classes.resolve())+os.pathsep+str(legacy.resolve()),"ANDROID_SIGNER_JAVA":str(a.java_home/"bin/java"),"ANDROID_SIGNER_REFERENCE_APK":str(apk.resolve()),"ANDROID_SIGNER_REFERENCE_AAB":str(aab.resolve()),"ANDROID_SIGNER_BUNDLETOOL":str(bundletool.resolve())}
subprocess.run(["cargo","test","--locked","--all-features"],cwd=ROOT,env=env,check=True)
