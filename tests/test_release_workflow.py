#!/usr/bin/env python3
"""Adversarial finalizer tests; no network or deployment credentials."""
import base64
import copy
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release", ROOT / "integration/connectbot/.github/scripts/signer-release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def test_source_pin_ignores_mtime_but_binds_paths_and_contents(self):
        def archive(name="src/Main.java", content=b"class Main {}", mtime=1, symlink=False):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as tar:
                member = tarfile.TarInfo(name)
                member.mtime = mtime
                member.size = len(content)
                if symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/tmp/outside"
                tar.addfile(member, io.BytesIO(content))
            return stream.getvalue()
        original = release.source_tree_digest(archive())
        self.assertEqual(original, release.source_tree_digest(archive(mtime=9000)))
        self.assertNotEqual(original, release.source_tree_digest(archive(content=b"class Changed {}")))
        self.assertNotEqual(original, release.source_tree_digest(archive(name="src/Other.java")))
        for data in (archive(name="../Main.java"), archive(symlink=True)):
            with self.assertRaises(ValueError):
                release.source_tree_digest(data)

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.key, cert = root / "key.pem", root / "cert.pem"
        subprocess.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(cls.key), "-out", str(cert), "-days", "2", "-subj", "/CN=Receipt-test"], check=True, capture_output=True)
        cls.der = release.run("openssl", "x509", "-in", cert, "-outform", "DER")
        cls.fingerprint = release.digest(cls.der)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def policy(self):
        return {"version": 2, "visibility": "public", "repository": "example/app", "repository_id": 42,
            "policy_hash": "a" * 64, "signer_revision": "b" * 40, "revision": 3,
            "receipt_keys": {self.fingerprint: base64.b64encode(self.der).decode()},
            "profiles": {"oss": {"package": "org.example", "keys": {"original": "c" * 64, "classical": "d" * 64, "upload": "e" * 64, "transparency": "f" * 64, "hybrid": None}, "lineage_sha256": "1" * 64, "rotation_min_sdk": 33, "hybrid_min_sdk": None}}}

    def receipt(self):
        policy = self.policy()
        return {"version": 2, "repository": "example/app", "package": "org.example", "job": {
            "version": 2, "profile": "oss", "id": "v2-42-10-2-oss-" + "a" * 64,
            "repository_id": 42, "run_id": 10, "attempt": 2, "commit": "2" * 40,
            "policy_hash": "a" * 64, "revision": 3}, "keys": policy["profiles"]["oss"]["keys"],
            "lineage": {"sha256": "1" * 64}, "rotation_min_sdk": 33, "hybrid_min_sdk": None,
            "signer": {"revision": "b" * 40}, "outputs": [{"name": "app-signed.apk", "sha256": "3" * 64, "bytes": 100}]}

    def envelope(self):
        receipt = self.receipt()
        statement = {"_type": "https://in-toto.io/Statement/v1", "predicateType": "urn:android-signer:receipt:v2", "predicate": receipt, "subject": [{"name": o["name"], "digest": {"sha256": o["sha256"]}} for o in receipt["outputs"]]}
        payload = release.json_bytes(statement)
        kind = release.PAYLOAD_TYPE
        pae = f"DSSEv1 {len(kind)} {kind} {len(payload)} ".encode() + payload
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(self.key)], input=pae, stdout=subprocess.PIPE, check=True).stdout
        return {"payloadType": kind, "payload": base64.b64encode(payload).decode(), "signatures": [{"keyid": self.fingerprint, "sig": base64.b64encode(sig).decode()}]}

    def test_receipt_signature_and_tampering(self):
        envelope = self.envelope()
        self.assertEqual(release.verify_receipt(release.json_bytes(envelope), self.policy()), self.receipt())
        bad = copy.deepcopy(envelope)
        bad["payload"] = base64.b64encode(b"{}").decode()
        with self.assertRaises(subprocess.CalledProcessError):
            release.verify_receipt(release.json_bytes(bad), self.policy())
        for field, value in [("payloadType", "application/json"), ("signatures", envelope["signatures"] * 2)]:
            bad = copy.deepcopy(envelope)
            bad[field] = value
            with self.assertRaises(ValueError):
                release.verify_receipt(release.json_bytes(bad), self.policy())

    def test_transaction_substitution(self):
        receipt, policy = self.receipt(), self.policy()
        source = {"id": 10, "run_attempt": 2, "head_sha": "2" * 40}
        release.validate_transaction(receipt, policy, source, "oss")
        for section, key, value in [("job", "attempt", 1), ("job", "profile", "google"), ("job", "policy_hash", "0" * 64), ("job", "commit", "0" * 40), ("keys", "upload", "0" * 64), ("lineage", "sha256", "0" * 64), ("signer", "revision", "0" * 40)]:
            bad = copy.deepcopy(receipt)
            bad[section][key] = value
            with self.assertRaises(ValueError, msg=f"accepted {section}.{key}"):
                release.validate_transaction(bad, policy, source, "oss")

    def test_policy_and_duplicate_json(self):
        release.validate_policy(self.policy())
        bad = self.policy()
        bad["policy_hash"] = "REPLACE"
        with self.assertRaises(ValueError):
            release.validate_policy(bad)
        bad = self.policy()
        bad["receipt_keys"] = {"0" * 64: base64.b64encode(self.der).decode()}
        with self.assertRaises(ValueError):
            release.validate_policy(bad)
        with self.assertRaises(ValueError):
            release.load('{"job":1,"job":2}')
        self.assertTrue(release.allowed_ref(["refs/tags/v*"], "refs/tags/v1.2.3"))
        self.assertFalse(release.allowed_ref(["refs/heads/main"], "refs/heads/main-attacker"))

    def test_archive_traversal_duplicates_and_nested_paths(self):
        for names in [["../app.apk"], ["app.apk", "app.apk"], ["a/app.apk"]]:
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for name in names:
                    archive.writestr(name, b"artifact")
            with self.assertRaises(ValueError):
                release.unpack(stream.getvalue())


if __name__ == "__main__":
    unittest.main()
