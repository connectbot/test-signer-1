#!/usr/bin/env python3
"""Independently verify a disposable-repository release and exercise rejection cases."""
import argparse
import base64
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('release', ROOT / 'integration/connectbot/.github/scripts/signer-release.py')
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True, help='Independently exported public test-deployment policy')
    parser.add_argument('--source-run', type=int, required=True)
    parser.add_argument('--source-attempt', type=int, required=True)
    parser.add_argument('--finalizer-commit', required=True, help='Independently approved full default-branch commit')
    parser.add_argument('--tools', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    policy = r.load(args.policy.read_bytes())
    r.validate_policy(policy)
    r.require(r.valid_hash(args.finalizer_commit, 40), 'full finalizer commit required')
    repo = policy['repository']
    source = r.api(f'repos/{repo}/actions/runs/{args.source_run}/attempts/{args.source_attempt}')
    r.require(source['status'] == 'completed' and source['conclusion'] == 'success' and source['event'] == 'push', 'source build is not successful/eligible')
    r.require(source['head_repository']['id'] == policy['repository_id'], 'source is a fork')
    tag = f"verified/{args.source_run}-{args.source_attempt}-{policy['policy_hash'][:16]}"
    releases = [v for v in r.rows(f'repos/{repo}/releases') if v['tag_name'] == tag]
    r.require(len(releases) == 1 and releases[0]['draft'] and releases[0]['target_commitish'] == source['head_sha'], 'verified draft missing/ambiguous/published')
    assets = r.rows(f"repos/{repo}/releases/{releases[0]['id']}/assets")
    r.require(len({v['name'] for v in assets}) == len(assets), 'duplicate final asset')
    files = {v['name']: r.download_asset(repo, v) for v in assets}
    r.prepare_tools(args.tools.resolve())
    checks = []
    with tempfile.TemporaryDirectory(prefix='signer-live-verification-') as tmp:
        root = Path(tmp)
        bundle = root / 'final.sigstore.json'
        bundle.write_bytes(files['final.sigstore.json'])
        final_predicate = r.load(files['predicate.json'])
        r.require(final_predicate['buildDefinition']['buildType'] == r.BUILD_TYPE, 'wrong final build type')
        expected_inputs = {'sourceRun': f'https://github.com/{repo}/actions/runs/{args.source_run}/attempts/{args.source_attempt}', 'profiles': sorted(policy['profiles'])}
        r.require(final_predicate['buildDefinition']['externalParameters'] == expected_inputs, 'final external parameters differ')
        for profile in sorted(policy['profiles']):
            local = root / profile
            local.mkdir()
            selected = {name[len(profile) + 1:]: data for name, data in files.items() if name.startswith(profile + '-')}
            envelope = selected['signing-receipt.dsse.json']
            receipt = r.verify_receipt(envelope, policy)
            r.validate_transaction(receipt, policy, source, profile)
            r.require(r.load(selected['signing-receipt.json']) == receipt, 'plain receipt differs')
            for output in receipt['outputs']:
                data = selected[output['name']]
                r.require(len(data) == output['bytes'] and r.digest(data) == output['sha256'], 'receipt output differs')
            inputs = r.unsigned_files(policy, source, receipt)
            for kind, data in inputs.items():
                original = local / f'original.{kind}'
                original.write_bytes(data)
                unsigned_bundle = local / f'unsigned-{kind}.sigstore.json'
                unsigned_bundle.write_bytes(selected[unsigned_bundle.name])
                r.verify_provenance(original, unsigned_bundle, policy, source, receipt['provenance'][kind])
            r.preserve_payload(inputs['apk'], selected['app-signed.apk'], {'META-INF/code_transparency_signed.jwt'})
            r.preserve_payload(inputs['aab'], selected['app-signed.aab'], {'META-INF/MANIFEST.MF', 'META-INF/SIGNER.SF', 'META-INF/SIGNER.RSA', 'BUNDLE-METADATA/com.android.tools.build.bundletool/code_transparency_signed.jwt'})
            r.android_verify(local, selected, receipt, args.tools.resolve())
            dependencies = final_predicate['buildDefinition']['resolvedDependencies']
            for uri, sha in [(f'urn:android-signer:receipt:{profile}', r.digest(envelope)), *[(f'urn:android-signer:unsigned:{profile}:{kind}', r.digest(data)) for kind, data in inputs.items()]]:
                r.require(any(d['uri'] == uri and d['digest'].get('sha256') == sha for d in dependencies), 'missing final dependency')
            for kind in ('apk', 'aab'):
                signed = local / f'app-signed.{kind}'
                verification = r.load(r.run('gh', 'attestation', 'verify', signed, '--bundle', bundle, '--repo', repo,
                    '--signer-workflow', f'{repo}/.github/workflows/release-attest.yml', '--source-digest', args.finalizer_commit,
                    '--signer-digest', args.finalizer_commit, '--source-ref', 'refs/heads/main', '--deny-self-hosted-runners', '--format', 'json'))
                r.require(len(verification) == 1 and verification[0]['verificationResult']['statement']['predicate'] == final_predicate, 'final predicate not authenticated')
                tampered = local / f'tampered.{kind}'
                tampered.write_bytes(signed.read_bytes() + b'tampered')
                try:
                    r.run('gh', 'attestation', 'verify', tampered, '--bundle', bundle, '--repo', repo, '--signer-workflow', f'{repo}/.github/workflows/release-attest.yml')
                except subprocess.CalledProcessError:
                    checks.append(f'{profile}/{kind}: modified output rejected')
                else:
                    raise ValueError('modified output accepted')
                checks.append(f'{profile}/{kind}: complete provenance/signature/transparency chain verified')
            altered = r.load(envelope)
            altered['payload'] = base64.b64encode(b'{}').decode()
            try:
                r.verify_receipt(r.json_bytes(altered), policy)
            except subprocess.CalledProcessError:
                checks.append(f'{profile}: modified receipt rejected')
            else:
                raise ValueError('modified receipt accepted')
            wrong = copy.deepcopy(receipt)
            wrong['job']['attempt'] += 1
            try:
                r.validate_transaction(wrong, policy, source, profile)
            except ValueError:
                checks.append(f'{profile}: wrong run attempt rejected')
            else:
                raise ValueError('wrong attempt accepted')
    report = {'version': 1, 'test_repository': repo, 'source_run': args.source_run, 'source_attempt': args.source_attempt,
              'source_commit': source['head_sha'], 'approved_finalizer_commit': args.finalizer_commit, 'checks': checks,
              'status': 'passed', 'limitations': ['Requires separate evidence of VM image integrity, collector durability, runner isolation and repository protection rules.']}
    with args.report.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(f'PASS: {len(checks)} live checks; evidence: {args.report}')


if __name__ == '__main__':
    main()
