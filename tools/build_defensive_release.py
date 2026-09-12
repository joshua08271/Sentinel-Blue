"""Build a reproducible defender distribution without native campaign commands."""
from __future__ import annotations
import argparse
import hashlib
import json
import tomllib
import zipfile
from pathlib import Path

from tools.build_release import ROOT, VERSION, _entries, _write_zip, digest
from tools.check_release_consistency import _python_version, _safe_archive

EXCLUDED = {'adversarial_lab.py', 'native_range_lab.py', 'windows_native_range_lab.py',
            'range_lab.py', 'restoration_lab.py', 'policy_lab.py', 'selftest.py'}
ENTRY = b"from sentinel_blue.__main__ import main\nmain(include_labs=False)\n"
DEFENSIVE_TOOLS = [
    'build_defensive_release.py', 'build_release.py', 'check_release_consistency.py',
    'azure_defensive_rehearsal.py', 'azure_lab_setup_rehearsal.py',
    'azure_lab_isolated_boot.py', 'azure_lab_preflight.py', 'azure_private_transfer.py',
    'azure_setup_guest.py', 'setup_native_inputs.py', 'competition_native_inputs.py',
    'measure_setup_acceptance.py', 'native_defender_startup.py', 'smoke_release.py',
    'windows_query_contract.py', 'measure_collection_pressure.py',
    'agent_transport_rehearsal.py', 'probe_timing_rehearsal.py',
    'service_repair_native.py', 'defensive_practice_native.py',
]
DEFENSIVE_TESTS = [
    'test_defensive_distribution.py', 'test_defensive_azure_payload.py',
    'test_posix_integrity_budget.py', 'test_azure_setup_guest.py',
    'test_integrity_coverage.py', 'test_windows_integrity_budget.py', 'test_process_coverage.py',
    'test_service_coverage.py',
    'test_windows_inventory_host.py', 'test_windows_query_batch.py',
    'test_service_repair.py', 'test_service_recovery_regressions.py',
    'test_autonomous_service_recovery.py', 'test_service_manifest_policy.py',
    'test_store_controller.py', 'test_baseline_promotion.py',
    'test_recovery_ops.py', 'test_competition_opening.py', 'test_setup.py', 'test_setup_acceptance.py',
    'test_controller_continuity.py', 'test_agent_continuity.py',
]
DEFENSIVE_DOCS = [
    'AUTONOMOUS_REPAIR.md', 'AUTONOMOUS_SERVICE_RECOVERY.md',
    'COMPETITION_OPENING.md', 'COMPETITION_STARTUP_COVERAGE.md',
    'CONTROLLER_CONTINUITY.md', 'INITIAL_SETUP.md', 'WINDOWS_COLLECTION.md',
    'DEFENSIVE_VALIDATION_2026-09-11.md', 'AZURE_DEFENSIVE_ACCEPTANCE_1.9.41.md',
    'DEFENSIVE_VALIDATION_1.9.42.md',
    'DEFENSIVE_VALIDATION_1.9.43.md',
    'DEFENSIVE_VALIDATION_1.9.44.md',
    'DEFENSIVE_VALIDATION_1.9.45.md',
    'validation-1.9.43/ci.json', 'validation-1.9.43/local-tests.json',
    'validation-1.9.43/azure-summary.json',
    'validation-1.9.44/ci.json', 'validation-1.9.44/local-tests.json',
    'validation-1.9.44/azure-summary.json',
    'validation-1.9.45/ci.json', 'validation-1.9.45/local-tests.json',
    'validation-1.9.45/azure-summary.json',
    'validation-1.9.42/lifecycle.json', 'validation-1.9.42/transport.json',
    'validation-1.9.42/probe-timing.json', 'validation-1.9.42/local-tests.json',
]


def check_source():
    """Check the identities of this distribution without requiring a browser extension."""
    project = tomllib.loads((ROOT/'pyproject.toml').read_text())
    inventory = json.loads((ROOT/'examples/inventory.example.json').read_text())
    versions = {project['project']['version'],
                _python_version((ROOT/'src/sentinel_blue/__init__.py').read_text(), 'package'),
                inventory['event_profile']['release']['version']}
    if versions != {VERSION} or not (ROOT/'README.md').read_text().startswith('# Sentinel Blue '+VERSION+'\n'):
        raise ValueError('Defender distribution identities disagree')


def build(output: Path):
    if output.resolve().is_relative_to((ROOT/'src').resolve()):
        raise ValueError('Build output must be outside runtime source directories')
    check_source()
    output.mkdir(parents=True, exist_ok=True)
    source = [(name, data) for name, data in _entries([ROOT/'src'])
              if Path(name).name not in EXCLUDED]
    runtime = output/f'sentinel-blue-{VERSION}.pyz'
    _write_zip(runtime, [(name.removeprefix('src/'), data) for name, data in source]+[('__main__.py',ENTRY)],
               prefix=b'#!/usr/bin/env python3\n', compressed=True)
    runtime.chmod(0o755)
    return runtime


def build_bundle(output: Path):
    """Deliver the tested runtime, matching defensive source, instructions and evidence."""
    runtime = build(output)
    paths = [ROOT/'README.md', ROOT/'pyproject.toml', ROOT/'src', ROOT/'examples']
    paths.append(ROOT/'.github/workflows/defender-validation.yml')
    paths += [ROOT/'tools'/name for name in DEFENSIVE_TOOLS]
    paths += [ROOT/'tests'/name for name in DEFENSIVE_TESTS]
    paths += [ROOT/'docs'/name for name in DEFENSIVE_DOCS]
    for optional in ('LICENSE', 'SECURITY.md'):
        if (ROOT/optional).is_file():
            paths.append(ROOT/optional)
    entries = [(name, data) for name, data in _entries(paths) if Path(name).name not in EXCLUDED]
    entries += [('tools/__init__.py', b''), ('tests/__init__.py', b'')]
    source = output/f'sentinel-blue-defender-source-{VERSION}.zip'
    _write_zip(source, entries, compressed=True)
    # Check exact source/runtime equality, path safety and archive integrity.
    with zipfile.ZipFile(runtime) as packaged, zipfile.ZipFile(source) as supplied:
        runtime_names = _safe_archive(packaged, runtime.name)
        _safe_archive(supplied, source.name)
        expected = {name.removeprefix('src/'): data for name, data in entries if name.startswith('src/')}
        expected['__main__.py'] = ENTRY
        if set(runtime_names) != set(expected) or any(packaged.read(name) != data for name, data in expected.items()):
            raise ValueError('Runtime does not exactly match the supplied defender source')
    files = [(runtime.name, runtime.read_bytes()), (source.name, source.read_bytes()),
             ('README.md', (ROOT/'README.md').read_bytes()),
             ('VALIDATION.md', (ROOT/f'docs/DEFENSIVE_VALIDATION_{VERSION}.md').read_bytes()),
             ('AZURE_ACCEPTANCE_1.9.41.md', (ROOT/'docs/AZURE_DEFENSIVE_ACCEPTANCE_1.9.41.md').read_bytes())]
    checksums = ''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name, data in files).encode()
    bundle = output/f'sentinel-blue-defender-{VERSION}.zip'
    _write_zip(bundle, files+[('SHA256SUMS', checksums)], compressed=True)
    return bundle


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--bundle', action='store_true')
    args = parser.parse_args()
    result = build_bundle(args.output) if args.bundle else build(args.output)
    print(digest(result)+'  '+str(result))
