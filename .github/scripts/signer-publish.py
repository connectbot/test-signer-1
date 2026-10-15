#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Publish independently verified Hermit outputs; never build or sign application code."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

SPEC = importlib.util.spec_from_file_location("signer_release", Path(__file__).with_name("signer-release.py"))
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)
require, digest, load, json_bytes = r.require, r.digest, r.load, r.json_bytes
PROJECT = "api-4664730880327298161-873945"
PACKAGE = "org.connectbot"
SUPPORT = {"mapping.txt", "native-debug-symbols.zip", "build-info.json"}
STABLE = r"v[0-9]+\.[0-9]+\.[0-9]+"
TAG = r"(?:git-|v)[A-Za-z0-9_.+\-]{1,150}"


def source_identity():
    return {"repository": os.environ["GITHUB_REPOSITORY"], "run_id": int(os.environ["GITHUB_RUN_ID"]),
            "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "commit": os.environ["GITHUB_SHA"],
            "ref": os.environ["GITHUB_REF"]}


def build_info(out, profile, version_code_file):
    require(profile in ("oss", "google"), "unsupported release profile")
    source = source_identity()
    require(r.valid_hash(source["commit"], 40), "invalid build commit")
    if source["ref"].startswith("refs/tags/"):
        tag = source["ref"][len("refs/tags/"):]
        title = f"Release {tag}"
    else:
        require(source["ref"] == "refs/heads/main", "unsupported release branch")
        tag = "git-" + r.run("git", "describe", source["commit"]).decode().strip()
        title = tag + ": " + r.run("git", "log", "-1", "--format=%s", source["commit"]).decode().strip()
    require(re.fullmatch(TAG, tag), "unsafe release tag")
    code = int(version_code_file.read_text().strip())
    require(0 < code <= 2100000000, "invalid Android version code")
    out.mkdir(exist_ok=True, parents=True)
    (out / "build-info.json").write_bytes(json_bytes({"version": 1, "source": source, "profile": profile,
        "tag": tag, "title": title[:250], "version_code": code}))


def support_files(policy, source, profile, receipt):
    expected = f"release-support-{profile}-{source['run_attempt']}"
    candidates = [a for a in r.rows(f"repos/{policy['repository']}/actions/runs/{source['id']}/artifacts", "artifacts")
                  if a["name"] == expected and not a["expired"]]
    require(len(candidates) == 1, "release support artifact missing or ambiguous")
    artifact = candidates[0]
    run = artifact["workflow_run"]
    require(run["id"] == source["id"] and run["head_sha"] == source["head_sha"]
            and run["repository_id"] == policy["repository_id"], "release support belongs to another build")
    require(0 < artifact["size_in_bytes"] <= r.MAX_BYTES, "release support archive too large")
    archive = r.run("gh", "api", "--hostname", "github.com", f"repos/{policy['repository']}/actions/artifacts/{artifact['id']}/zip")
    require(artifact["digest"] == f"sha256:{digest(archive)}", "release support archive digest differs")
    files = r.unpack(archive)
    require(set(files) == SUPPORT, "unexpected release support files")
    info = load(files["build-info.json"])
    require(set(info) == {"version", "source", "profile", "tag", "title", "version_code"} and info["version"] == 1, "invalid build metadata")
    require(info["source"] == {"repository": policy["repository"], "run_id": source["id"], "attempt": source["run_attempt"],
            "commit": source["head_sha"], "ref": receipt["provenance"]["aab"]["ref"]}, "build metadata source differs")
    require(info["profile"] == profile and info["version_code"] == receipt["version_code"], "build metadata version/profile differs")
    ref = info["source"]["ref"]
    require(re.fullmatch(TAG, info["tag"]) and isinstance(info["title"], str) and 0 < len(info["title"]) <= 250, "unsafe release metadata")
    if ref.startswith("refs/tags/"):
        require(info["tag"] == ref[len("refs/tags/"):], "release tag differs from attested source ref")
    else:
        require(ref == "refs/heads/main" and info["tag"].startswith("git-"), "unsupported release ref/tag")
    return files, info, artifact


def add_asset(root, assets, name, data):
    require(re.fullmatch(r"[A-Za-z0-9_.+\-]{1,220}", name) and name not in (".", "..") and name not in assets, "unsafe or duplicate release asset")
    require(0 < len(data) <= r.MAX_BYTES, "release asset size outside bounds")
    (root / name).write_bytes(data)
    assets[name] = {"sha256": digest(data), "bytes": len(data)}


def package_release(out, policy_path):
    """Called only after signer-release.prepare has independently verified both profiles."""
    policy = load(policy_path.read_bytes())
    r.validate_policy(policy)
    verification = load((out / "verification.json").read_bytes())
    require(set(verification["profiles"]) == {"oss", "google"} == set(policy["profiles"]), "both ConnectBot profiles required")
    source = r.api(f"repos/{policy['repository']}/actions/runs/{verification['source_run']}/attempts/{verification['source_attempt']}")
    root = out / "publish"
    root.mkdir(exist_ok=False)
    assets, infos, dependencies, versions = {}, [], [], {}
    for profile in ("oss", "google"):
        directory = out / profile
        receipt = load((directory / "signing-receipt.json").read_bytes())
        r.validate_transaction(receipt, policy, source, profile)
        support, info, artifact = support_files(policy, source, profile, receipt)
        for name, data in support.items():
            path = directory / name
            path.write_bytes(data)
            r.verify_provenance(path, directory / "unsigned-aab.sigstore.json", policy, source, receipt["provenance"]["aab"])
            dependencies.append({"uri": f"urn:connectbot:release-support:{profile}:{name}", "digest": {"sha256": digest(data)}})
        infos.append({k: v for k, v in info.items() if k != "profile"})
        versions[profile] = info["version_code"]
        prefix = f"ConnectBot-{info['tag']}-{profile}"
        for kind in ("apk", "aab"):
            add_asset(root, assets, f"{prefix}.{kind}", (directory / f"app-signed.{kind}").read_bytes())
        add_asset(root, assets, f"{prefix}.native-debug-symbols.zip", support["native-debug-symbols.zip"])
        add_asset(root, assets, f"{prefix}.mapping.txt.zst", r.run("zstd", "-q", "-c", "--no-progress", directory / "mapping.txt"))
        add_asset(root, assets, f"provenance-{profile}.json", (directory / "unsigned-aab.sigstore.json").read_bytes())
        for name in ("signing-receipt.dsse.json", "signing-receipt.json", "code_transparency_signed.jwt", "transparency-certificate.der",
                     "apk-lineage.bin", "apk-hybrid-rsa-lineage.bin", "apk-hybrid-pqc-lineage.bin", "apk-effective-lineage.bin"):
            if (directory / name).exists():
                add_asset(root, assets, f"{profile}-{name}", (directory / name).read_bytes())
        dependencies.append({"uri": f"https://github.com/{policy['repository']}/actions/artifacts/{artifact['id']}",
                             "digest": {"sha256": artifact["digest"].removeprefix("sha256:")}})
    require(infos[0] == infos[1], "profiles disagree on release metadata")
    info = infos[0]
    stable = info["source"]["ref"] == f"refs/tags/{info['tag']}" and re.fullmatch(STABLE, info["tag"]) is not None
    release = {"tag_name": info["tag"], "name": info["title"], "target_commitish": source["head_sha"], "prerelease": not stable}
    add_asset(root, assets, "version_code.txt", f"{info['version_code']}\n".encode())
    if stable:
        add_asset(root, assets, "version-info.txt", f"VERSION_NAME={info['tag'][1:]}\nVERSION_CODE={info['version_code']}\n".encode())
    predicate = load((out / "predicate.json").read_bytes())
    predicate["buildDefinition"]["resolvedDependencies"].extend(dependencies)
    (out / "predicate.json").write_bytes(json_bytes(predicate))
    for name, data in (("predicate.json", json_bytes(predicate)), ("verification.json", json_bytes(verification)),
                       ("signer-policy.json", policy_path.read_bytes())):
        add_asset(root, assets, name, data)
    manifest = {"version": 1, "repository": policy["repository"], "repository_id": policy["repository_id"],
        "source": info["source"], "policy_hash": policy["policy_hash"], "release": release, "version_codes": versions,
        "finalizer": source_identity(), "assets": assets}
    (root / "release-manifest.json").write_bytes(json_bytes(manifest))
    return manifest


def verify_handoff(root, expected_hash, policy_path):
    """Authenticate the manifest first, then verify every byte it authorizes publishing."""
    require(r.valid_hash(expected_hash), "expected manifest hash required")
    path = root / "release-manifest.json"
    require(not path.is_symlink() and path.stat().st_size <= 4 * 1024 * 1024 and digest(path.read_bytes()) == expected_hash, "handoff manifest differs")
    policy = load(policy_path.read_bytes())
    r.validate_policy(policy)
    meta = r.api(f"repos/{policy['repository']}")
    r.validate_finalizer_context(meta)
    require(meta["id"] == policy["repository_id"] and meta["visibility"] == policy["visibility"], "publisher repository identity differs")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ["GITHUB_REPOSITORY"] == policy["repository"], "publisher context differs")
    verified = load(r.run("gh", "attestation", "verify", path, "--bundle", root / "final.sigstore.json", "--repo", policy["repository"],
        "--signer-workflow", f"{policy['repository']}/.github/workflows/release-attest.yml", "--source-digest", os.environ["GITHUB_SHA"],
        "--signer-digest", os.environ["GITHUB_SHA"], "--source-ref", os.environ["GITHUB_REF"], "--deny-self-hosted-runners", "--format", "json"))
    require(len(verified) == 1, "ambiguous final provenance")
    result = verified[0]["verificationResult"]
    manifest = load(path.read_bytes())
    require(set(manifest) == {"version", "repository", "repository_id", "source", "policy_hash", "release", "version_codes", "finalizer", "assets"}
            and manifest["version"] == 1, "unsupported release manifest")
    producer = manifest["finalizer"]
    current = source_identity()
    require(manifest["repository"] == policy["repository"] and manifest["repository_id"] == policy["repository_id"]
            and manifest["policy_hash"] == policy["policy_hash"] and set(producer) == set(current)
            and all(producer[k] == current[k] for k in current if k != "attempt")
            and type(producer["attempt"]) is int and 0 < producer["attempt"] <= current["attempt"], "handoff identity differs")
    statement = result["statement"]
    predicate = statement["predicate"]
    invocation = f"https://github.com/{policy['repository']}/actions/runs/{producer['run_id']}/attempts/{producer['attempt']}"
    require(statement["predicateType"] == r.SLSA and predicate["buildDefinition"]["buildType"] == r.BUILD_TYPE
            and result["signature"]["certificate"]["runInvocationURI"] == invocation
            and result["signature"]["certificate"]["sourceRepositoryIdentifier"] == str(policy["repository_id"]), "final provenance invocation differs")
    source = manifest["source"]
    inputs = {"source_run": str(source["run_id"]), "source_attempt": str(source["attempt"])}
    event = load(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    require(event.get("inputs") == inputs, "publisher dispatch inputs differ")
    require(predicate["buildDefinition"]["externalParameters"] == {"workflow": {
        "repository": f"https://github.com/{policy['repository']}", "ref": os.environ["GITHUB_REF"], "path": ".github/workflows/signed-release.yml"},
        "inputs": inputs}, "final provenance parameters differ")
    require(source["repository"] == policy["repository"] and r.valid_hash(source["commit"], 40) and r.allowed_ref(policy["refs"], source["ref"]), "release source differs")
    assets = manifest["assets"]
    require(0 < len(assets) <= 128 and {p.name for p in root.iterdir()} == set(assets) | {"release-manifest.json", "final.sigstore.json"}, "unexpected handoff files")
    subjects = statement["subject"]
    for name, expected in assets.items():
        require(re.fullmatch(r"[A-Za-z0-9_.+\-]{1,220}", name) and name not in (".", ".."), "unsafe manifest path")
        file = root / name
        require(not file.is_symlink() and file.is_file() and 0 < file.stat().st_size <= r.MAX_BYTES
                and file.stat().st_size == expected["bytes"] and digest(file.read_bytes()) == expected["sha256"], "handoff asset differs")
        require(any(s.get("name", "").rsplit("/", 1)[-1] == name and s.get("digest", {}).get("sha256") == expected["sha256"] for s in subjects), "release asset absent from final attestation")
    require(load((root / "predicate.json").read_bytes()) == predicate and (root / "signer-policy.json").read_bytes() == policy_path.read_bytes(), "final predicate/policy differs")
    rel = manifest["release"]
    require(set(rel) == {"tag_name", "name", "target_commitish", "prerelease"} and re.fullmatch(TAG, rel["tag_name"])
            and rel["target_commitish"] == source["commit"], "invalid release metadata")
    stable = source["ref"] == f"refs/tags/{rel['tag_name']}" and re.fullmatch(STABLE, rel["tag_name"]) is not None
    require(rel["prerelease"] is (not stable), "release classification differs")
    require((source["ref"] == "refs/heads/main" and rel["tag_name"].startswith("git-"))
            or source["ref"] == f"refs/tags/{rel['tag_name']}", "release tag/source mismatch")
    require(set(manifest["version_codes"]) == {"oss", "google"} and len(set(manifest["version_codes"].values())) == 1
            and all(type(v) is int and 0 < v <= 2100000000 for v in manifest["version_codes"].values()), "invalid release versions")
    required = {"predicate.json", "verification.json", "signer-policy.json", "version_code.txt"}
    for profile in ("oss", "google"):
        prefix = f"ConnectBot-{rel['tag_name']}-{profile}"
        required.update({f"{prefix}.apk", f"{prefix}.aab", f"{prefix}.mapping.txt.zst", f"{prefix}.native-debug-symbols.zip",
            f"provenance-{profile}.json", f"{profile}-signing-receipt.dsse.json", f"{profile}-signing-receipt.json",
            f"{profile}-code_transparency_signed.jwt", f"{profile}-transparency-certificate.der", f"{profile}-apk-lineage.bin"})
        if policy["profiles"][profile]["keys"].get("hybrid"):
            required.update(f"{profile}-{name}" for name in ("apk-hybrid-rsa-lineage.bin", "apk-hybrid-pqc-lineage.bin", "apk-effective-lineage.bin"))
    if stable:
        required.add("version-info.txt")
    require(set(assets) == required, "release asset set differs from policy")
    require((root / "version_code.txt").read_text() == f"{manifest['version_codes']['google']}\n", "version metadata differs")
    if stable:
        require((root / "version-info.txt").read_text() == f"VERSION_NAME={rel['tag_name'][1:]}\nVERSION_CODE={manifest['version_codes']['google']}\n", "F-Droid metadata differs")
    return manifest


def gh_json(method, path, body):
    return load(subprocess.run(["gh", "api", "--hostname", "github.com", "--method", method, path, "--input", "-"],
        input=json_bytes(body), check=True, capture_output=True, timeout=300).stdout)


def verify_existing_publication(root, manifest, existing):
    """A complete rerun may produce fresh provenance; retain the original published evidence."""
    by_name = {a["name"]: a for a in existing}
    require(len(by_name) == len(existing) and set(by_name) == set(manifest["assets"]) | {"release-manifest.json", "final.sigstore.json"}, "published release is incomplete")
    if all(a.get("state") == "uploaded" and a.get("digest") == f"sha256:{digest((root / name).read_bytes())}"
           and a["size"] == (root / name).stat().st_size for name, a in by_name.items()):
        return
    old_bytes = r.download_asset(manifest["repository"], by_name["release-manifest.json"])
    require(len(old_bytes) <= 4 * 1024 * 1024, "published manifest too large")
    old = load(old_bytes)
    require(set(old) == set(manifest) and all(old[k] == manifest[k] for k in manifest if k not in ("assets", "finalizer"))
            and set(old["assets"]) == set(manifest["assets"]), "published release bytes differ")
    require(old["finalizer"]["commit"] == manifest["finalizer"]["commit"] and old["finalizer"]["ref"] == manifest["finalizer"]["ref"]
            and old["finalizer"]["repository"] == manifest["repository"], "published finalizer differs")
    for name, expected in old["assets"].items():
        require(name == "predicate.json" or expected == manifest["assets"][name], "published release bytes differ")
        asset = by_name[name]
        require(asset.get("state") == "uploaded" and asset.get("digest") == "sha256:" + expected["sha256"]
                and asset["size"] == expected["bytes"], "published release bytes differ")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        (path / "release-manifest.json").write_bytes(old_bytes)
        (path / "final.sigstore.json").write_bytes(r.download_asset(manifest["repository"], by_name["final.sigstore.json"]))
        verified = load(r.run("gh", "attestation", "verify", path / "release-manifest.json", "--bundle", path / "final.sigstore.json", "--repo", manifest["repository"],
            "--signer-workflow", f"{manifest['repository']}/.github/workflows/release-attest.yml", "--source-digest", old["finalizer"]["commit"],
            "--signer-digest", old["finalizer"]["commit"], "--source-ref", old["finalizer"]["ref"], "--deny-self-hosted-runners", "--format", "json"))
    require(len(verified) == 1, "ambiguous published attestation")
    result = verified[0]["verificationResult"]
    require(result["signature"]["certificate"]["runInvocationURI"] == f"https://github.com/{manifest['repository']}/actions/runs/{old['finalizer']['run_id']}/attempts/{old['finalizer']['attempt']}"
            and result["signature"]["certificate"]["sourceRepositoryIdentifier"] == str(manifest["repository_id"]), "published invocation differs")
    require(digest(json_bytes(result["statement"]["predicate"])) == old["assets"]["predicate.json"]["sha256"], "published predicate differs")
    for name, expected in old["assets"].items():
        require(any(s.get("name", "").rsplit("/", 1)[-1] == name and s.get("digest", {}).get("sha256") == expected["sha256"]
                    for s in result["statement"]["subject"]), "published asset absent from attestation")


def ensure_release_tag(repo, tag, commit):
    # Create tags explicitly at the verified source, never the default-branch tip.
    tag_path = urllib.parse.quote(tag, safe="")
    try:
        ref = r.api(f"repos/{repo}/git/ref/tags/{tag_path}")
    except subprocess.CalledProcessError:
        # Establish absence through a successful matching-refs response before mutation.
        refs = r.rows(f"repos/{repo}/git/matching-refs/tags/{tag_path}")
        require(not refs, "could not establish release tag identity")
        ref = gh_json("POST", f"repos/{repo}/git/refs", {"ref": f"refs/tags/{tag}", "sha": commit})
    obj = ref["object"]
    for _ in range(8):
        if obj["type"] != "tag":
            break
        obj = r.api(f"repos/{repo}/git/tags/{obj['sha']}")["object"]
    require(obj["type"] == "commit" and obj["sha"] == commit, "release tag points to another commit")


def github_release(root, manifest):
    repo, release = manifest["repository"], manifest["release"]
    source = manifest["source"]
    marker = f"Verified Android signing; source run {source['run_id']}/{source['attempt']}; commit {source['commit']}; policy {manifest['policy_hash']}"
    matches = [a for a in r.rows(f"repos/{repo}/releases") if a["tag_name"] == release["tag_name"]]
    require(len(matches) <= 1, "ambiguous publication release")
    if matches:
        target = matches[0]
        require(target["target_commitish"] == source["commit"] and target["body"].split("\n", 1)[0] == marker
                and target["prerelease"] == release["prerelease"] and target["name"] == release["name"], "unmanaged/conflicting publication release")
    ensure_release_tag(repo, release["tag_name"], source["commit"])
    if not matches:
        notes = gh_json("POST", f"repos/{repo}/releases/generate-notes", {"tag_name": release["tag_name"], "target_commitish": source["commit"]})
        target = gh_json("POST", f"repos/{repo}/releases", {**release, "draft": True, "body": marker + "\n\n" + notes["body"]})
    names = set(manifest["assets"]) | {"release-manifest.json", "final.sigstore.json"}
    existing = r.rows(f"repos/{repo}/releases/{target['id']}/assets")
    require(len({a['name'] for a in existing}) == len(existing) and {a['name'] for a in existing} <= names, "unexpected publication assets")
    if not target["draft"]:
        verify_existing_publication(root, manifest, existing)
    else:
        for name in sorted(names):
            r.upload(repo, target["id"], name, (root / name).read_bytes())
        complete = r.rows(f"repos/{repo}/releases/{target['id']}/assets")
        require(len(complete) == len(names) and {a['name'] for a in complete} == names, "publication assets incomplete")
        for asset in complete:
            data = (root / asset["name"]).read_bytes()
            require(asset.get("state") == "uploaded" and asset.get("digest") == f"sha256:{digest(data)}" and asset["size"] == len(data), "publication asset digest differs")
        target = gh_json("PATCH", f"repos/{repo}/releases/{target['id']}", {"draft": False, "make_latest": "legacy" if not release["prerelease"] else "false"})
    return {"destination": "github", "release_id": target["id"], "tag": release["tag_name"], "url": target["html_url"], "status": "published"}


class PlayError(RuntimeError):
    def __init__(self, status):
        super().__init__(f"Google Play request failed (HTTP {status}); edit was not silently committed or resubmitted")
        self.status = status


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Play:
    def __init__(self, token):
        require(token and "\n" not in token and "\r" not in token, "Google access token required")
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, method, path, body=None, media=None):
        require(path.startswith(f"applications/{PACKAGE}/edits") and ".." not in path and "://" not in path, "invalid Play API path")
        base = "https://androidpublisher.googleapis.com/" + ("upload/" if media is not None else "") + "androidpublisher/v3/"
        data = media if media is not None else (json_bytes(body) if body is not None else None)
        request = urllib.request.Request(base + path, data=data, method=method, headers={"Authorization": "Bearer " + self.token,
            "Content-Type": "application/octet-stream" if media is not None else "application/json"})
        try:
            with self.opener.open(request, timeout=180) as response:
                content = response.read(4 * 1024 * 1024 + 1)
                require(len(content) <= 4 * 1024 * 1024, "Play response too large")
                return load(content) if content else {}
        except urllib.error.HTTPError as error:
            raise PlayError(error.code) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            raise PlayError(0) from None


def retryable(error):
    return isinstance(error, PlayError) and error.status in (0, 429, 500, 502, 503, 504)


def retry_call(call):
    for attempt in range(3):
        try:
            return call()
        except PlayError as error:
            if not retryable(error) or attempt == 2:
                raise
            time.sleep(2 ** attempt)


def bundle_match(bundle, code, sha):
    require(int(bundle["versionCode"]) == code and bundle["sha256"].lower() == sha, "Play version code or bundle hash conflicts")


def play_release(client, root, manifest):
    require(manifest["repository"] == "connectbot/connectbot" and manifest["repository_id"] == 123235, "Play publishing is restricted to production ConnectBot")
    require(load((root / "signer-policy.json").read_bytes())["profiles"]["google"]["package"] == PACKAGE, "Play application differs")
    code = manifest["version_codes"]["google"]
    prefix = f"ConnectBot-{manifest['release']['tag_name']}-google"
    aab = (root / f"{prefix}.aab").read_bytes()
    sha = digest(aab)
    base = f"applications/{PACKAGE}/edits"
    edit = client.request("POST", base, {})["id"]
    path = f"{base}/{edit}"
    committed = False
    try:
        bundles = retry_call(lambda: client.request("GET", path + "/bundles")).get("bundles", [])
        existing = [b for b in bundles if int(b["versionCode"]) == code]
        require(len(existing) <= 1, "ambiguous Play bundle")
        if existing:
            bundle_match(existing[0], code, sha)
        track = retry_call(lambda: client.request("GET", path + "/tracks/alpha"))
        current = [int(v) for release in track.get("releases", []) for v in release.get("versionCodes", [])]
        outcome = {"destination": "play", "package": PACKAGE, "track": "alpha", "version_code": code, "sha256": sha}
        if current and max(current) > code:
            return {**outcome, "status": "superseded"}
        if existing and any(str(code) in release.get("versionCodes", []) and release.get("status") == "completed" for release in track.get("releases", [])):
            return {**outcome, "status": "already-published"}
        if not existing:
            for attempt in range(3):
                try:
                    bundle = client.request("POST", path + "/bundles?uploadType=media", media=aab)
                    bundle_match(bundle, code, sha)
                    break
                except PlayError as error:
                    if not retryable(error):
                        raise
                    # A lost response may still have accepted the upload.
                    matches = [b for b in retry_call(lambda: client.request("GET", path + "/bundles")).get("bundles", []) if int(b["versionCode"]) == code]
                    require(len(matches) <= 1, "ambiguous recovered Play bundle")
                    if matches:
                        bundle_match(matches[0], code, sha)
                        break
                    if attempt == 2:
                        raise
                    time.sleep(2 ** attempt)
        mapping = r.run("zstd", "-q", "-d", "-c", root / f"{prefix}.mapping.txt.zst")
        require(0 < len(mapping) <= r.MAX_BYTES, "expanded mapping outside bounds")
        for kind, data in (("proguard", mapping), ("nativeCode", (root / f"{prefix}.native-debug-symbols.zip").read_bytes())):
            retry_call(lambda kind=kind, data=data: client.request("POST", path + f"/apks/{code}/deobfuscationFiles/{kind}?uploadType=media", media=data))
        update = {"track": "alpha", "releases": [{"name": "Version " + manifest["release"]["tag_name"], "versionCodes": [str(code)], "status": "completed"}]}
        retry_call(lambda: client.request("PUT", path + "/tracks/alpha", update))
        try:
            client.request("POST", path + ":commit?changesInReviewBehavior=ERROR_IF_IN_REVIEW")
            committed = True
        except PlayError as error:
            if not retryable(error):
                raise
            # Never retry a commit blindly: observe the committed state in a fresh edit.
            check = client.request("POST", base, {})["id"]
            check_path = f"{base}/{check}"
            try:
                committed_bundles = client.request("GET", check_path + "/bundles").get("bundles", [])
                committed_track = client.request("GET", check_path + "/tracks/alpha")
                matched = [b for b in committed_bundles if int(b["versionCode"]) == code]
                require(len(matched) == 1, "uncertain Play commit; bundle not confirmed")
                bundle_match(matched[0], code, sha)
                require(any(str(code) in a.get("versionCodes", []) and a.get("status") == "completed" for a in committed_track.get("releases", [])), "uncertain Play commit; alpha not confirmed")
                committed = True
            finally:
                try:
                    client.request("DELETE", check_path)
                except PlayError:
                    pass
        return {**outcome, "status": "published", "edit_id": edit}
    finally:
        if not committed:
            try:
                client.request("DELETE", path)
            except PlayError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build-info", "prepare", "seal", "verify", "github", "play"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=Path(".github/signer-policy.json"))
    parser.add_argument("--source-run", type=int)
    parser.add_argument("--source-attempt", type=int)
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--profile")
    parser.add_argument("--version-code-file", type=Path)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = None
    if args.command == "build-info":
        require(args.profile and args.version_code_file, "profile/version code file required")
        build_info(args.out, args.profile, args.version_code_file)
    elif args.command == "prepare":
        require(args.source_run and args.source_attempt and args.tools, "source run/attempt/tools required")
        r.prepare(args.policy, args.source_run, args.source_attempt, args.out, args.tools.resolve())
        package_release(args.out, args.policy)
    elif args.command == "seal":
        require(args.bundle, "final attestation bundle required")
        shutil.copyfile(args.bundle, args.out / "publish/final.sigstore.json")
        sha = digest((args.out / "publish/release-manifest.json").read_bytes())
        verify_handoff(args.out / "publish", sha, args.policy)
        with open(os.environ["GITHUB_OUTPUT"], "a") as outputs:
            outputs.write(f"manifest_sha256={sha}\n")
        shutil.copyfile(args.bundle, args.out / "final.sigstore.json")
        r.publish_draft(args.out)
    else:
        manifest = verify_handoff(args.out, args.manifest_sha256, args.policy)
        if args.command == "github":
            result = github_release(args.out, manifest)
        elif args.command == "play":
            result = play_release(Play(os.environ.get("GOOGLE_PLAY_ACCESS_TOKEN")), args.out, manifest)
    if result is not None:
        require(args.report, "publication report path required")
        args.report.write_bytes(json_bytes(result) + b"\n")
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
