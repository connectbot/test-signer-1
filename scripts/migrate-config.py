#!/usr/bin/env python3
"""Explicitly migrate a legacy policy. New trust pins must be provisioned before boot."""
import argparse
import json
from pathlib import Path


def migrate(config, profile):
    if config.get("version", 1) != 1:
        raise ValueError("expected legacy version 1")
    config["version"] = 2
    for repo in config["repositories"]:
        path = repo.pop("workflow")
        repo["callers"] = {path: ["REPLACE_WITH_WORKFLOW_CONTENT_SHA256"]}
        repo["builder"] = {"repository": repo["name"], "repository_id": repo["id"],
                           "workflow": path, "refs": repo["refs"],
                           "sha256": ["REPLACE_WITH_WORKFLOW_CONTENT_SHA256"], "helpers": {}}
        repo["receipt_key"] = "receipt"
        repo["profiles"] = {profile: {key: (repo.pop(key, None) if key == "archive_resource" else repo.pop(key)) for key in
            ("package", "apk_artifact", "aab_artifact", "apk_file", "aab_file", "signing", "archive_resource")}}
        repo["migrate_legacy_profile"] = profile
        repo["revision"] += 1
    config["keys"]["receipt"] = {"private_key": "/root/receipt.pk8", "certificate": "/root/receipt.pem",
                                "fingerprint": "REPLACE_WITH_CERTIFICATE_DER_SHA256"}
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    if not args.profile or len(args.profile) > 32 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.profile):
        parser.error("invalid profile ID")
    result = migrate(json.loads(args.input.read_text()), args.profile)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
