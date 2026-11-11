"""Read Atomic metadata and validate detection queries with recorded OTRF data.

No executor, prerequisite or cleanup command from Atomic is ever executed.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import yaml

ROOT = Path(__file__).resolve().parent
ATOMIC_COMMIT = 'a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6'
ATOMIC_REPO = 'https://github.com/redcanaryco/atomic-red-team'
ATOMIC_HASHES = {
    'T1053.005': 'bbb559eaf81042357413d5680cc90e6acc593c54',
    'T1543.003': 'd1be781e3f56a14503dcd6bf4b6c22bae631a0b1',
    'T1569.002': '8f6c148d84ea6f5e2f80dfa604de7882df68bc57',
}
TASK_GUID = 'e895677d-4f06-49ab-91b6-ae3742d0a2ba'
SERVICE_GUID = '2382dee2-a75f-49aa-9378-f52df6ed3fb1'
SELECTED = [
    {'technique': 'T1053.005', 'guid': TASK_GUID,
     'name': 'Scheduled Task Executing Base64 Encoded Commands From Registry',
     'query_file': 'det-schtasks-persistence.esql',
     'dataset': 'empire_schtasks_creation_execution_elevated_user',
     'expected_rows': 1, 'evidence': 'Security 4698: task registration',
     'limitation': 'Registration does not prove the task ran.'},
    {'technique': 'T1053.005', 'guid': TASK_GUID,
     'name': 'Scheduled Task Executing Base64 Encoded Commands From Registry',
     'query_file': 'det-schtasks-process.esql',
     'dataset': 'empire_schtasks_creation_execution_elevated_user',
     'expected_rows': 2, 'evidence': 'Sysmon 1 and Security 4688: the same schtasks.exe process',
     'limitation': 'Two log records do not mean two distinct processes or two Atomic executions.'},
    {'technique': 'T1569.002', 'guid': SERVICE_GUID,
     'name': 'Execute a Command as a Service',
     'query_file': 'det-service-lateral.esql',
     'dataset': 'empire_psexec_dcerpc_tcp_svcctl',
     'expected_rows': 1, 'evidence': 'System / Service Control Manager 7045: service installation',
     'related_techniques': ['T1543.003'],
     'limitation': '7045 proves installation, not successful execution or lateral movement.'},
]
LIMITATIONS = [
    'No live Atomic tests have been executed. OTRF recordings are technique-level equivalents, not logs of these exact Atomic GUIDs.',
    'Static compatibility of default metadata with query predicates is not a measured live detection result.',
    'The selected task uses a daily schedule, whereas the OTRF example uses logon. Their names, payloads and registry paths also differ.',
    'The selected service is local. The OTRF scenario is remote service activity. Service installation alone does not prove remote execution.',
    'Zero hits in seven background samples is not a production false-positive rate or complete ATT&CK technique coverage.',
    'The original queries match EventID without a provider/channel predicate; they are intended for these validated Windows datasets, not arbitrary mixed-event indices.',
    'Scheduled task Local and T1543.003 Service Installation CMD/PowerShell defaults are not covered by the current suspicious-action filters.',
]


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def metadata_path(technique: str) -> str:
    return f'atomics/{technique}/{technique}.yaml'


def sync_metadata(atomic_root: Path) -> None:
    for technique, expected in ATOMIC_HASHES.items():
        rel = metadata_path(technique)
        target = atomic_root / rel
        url = f'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{ATOMIC_COMMIT}/{rel}'
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(2_000_001)
        if len(data) > 2_000_000 or blob_sha(data) != expected:
            raise ValueError(f'Upstream metadata hash/size mismatch: {technique}')
        if target.exists() and target.read_bytes() != data:
            raise ValueError(f'Refusing to overwrite changed metadata: {target}')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        print(f'VERIFIED {rel}', flush=True)


def load_catalog(atomic_root: Path) -> dict:
    catalog = {}
    for technique, expected in ATOMIC_HASHES.items():
        path = atomic_root / metadata_path(technique)
        data = path.read_bytes()
        if blob_sha(data) != expected:
            raise ValueError(f'Metadata differs from pinned Atomic revision: {path}')
        doc = yaml.safe_load(data)
        if not isinstance(doc, dict) or doc.get('attack_technique') != technique:
            raise ValueError(f'Invalid technique metadata: {technique}')
        for test in doc.get('atomic_tests', []):
            guid = test.get('auto_generated_guid')
            if not isinstance(guid, str) or guid in catalog:
                raise ValueError(f'Missing or duplicate Atomic GUID: {guid}')
            catalog[guid] = {'technique': technique, 'test': test,
                'source_path': metadata_path(technique),
                'source_url': f'{ATOMIC_REPO}/blob/{ATOMIC_COMMIT}/{metadata_path(technique)}',
                'source_sha256': hashlib.sha256(data).hexdigest(), 'source_git_blob_sha1': expected}
    return catalog


def default_text(test: dict) -> str:
    """Literal placeholder substitution only; never eval, execute or expand shell variables."""
    defaults = {name: str(value['default']) for name, value in test.get('input_arguments', {}).items() if 'default' in value}
    command = test.get('executor', {}).get('command', '')
    def replace(match):
        name = match.group(1)
        if name not in defaults:
            raise ValueError(f'Missing default input: {name}')
        return defaults[name]
    return re.sub(r'#\{([^}]+)\}', replace, command)


def suspicious_task_text(value: str) -> bool:
    return any(token in value.lower() for token in ('powershell', '-enc', 'iex', 'frombase64string'))


def suspicious_service_text(value: str) -> bool:
    return any(token in value.lower() for token in ('powershell', 'cmd', '-enc', '%comspec%'))


def selected_plan(catalog: dict) -> list:
    plan = []
    for mapping in SELECTED:
        item = catalog.get(mapping['guid'])
        if item is None:
            raise ValueError(f'Missing selected GUID: {mapping["guid"]}')
        test = item['test']
        if item['technique'] != mapping['technique'] or test['name'] != mapping['name'] or 'windows' not in test.get('supported_platforms', []):
            raise ValueError(f'Selected Atomic metadata changed: {mapping["guid"]}')
        if mapping['guid'] == TASK_GUID:
            commands = default_text(test)
            # Only inspect the schtasks create line, not other setup commands.
            create = next((line for line in commands.splitlines() if 'schtasks' in line.lower() and '/create' in line.lower()), '')
            action = re.split(r'\s/tr\s', create, maxsplit=1, flags=re.IGNORECASE)
            compatible = len(action) == 2 and suspicious_task_text(action[1])
        else:
            service_binary = str(test['input_arguments']['executable_command']['default'])
            compatible = suspicious_service_text(service_binary)
        if not compatible:
            raise ValueError(f'Default Atomic action does not match predicate: {mapping["guid"]}')
        plan.append({**mapping, 'supported_platforms': test['supported_platforms'],
            'executor_type': test.get('executor', {}).get('name'),
            'source_url': item['source_url'], 'source_path': item['source_path'],
            'source_sha256': item['source_sha256'], 'static_default_predicate_compatible': True,
            'execution_mode': 'recorded-equivalent', 'atomic_execution_verified': False})
    return plan


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def verify(atomic_root: Path) -> list:
    catalog = load_catalog(atomic_root)
    plan = selected_plan(catalog)
    safe_catalog = [{'guid': guid, 'technique': item['technique'], 'name': item['test']['name'],
        'supported_platforms': item['test'].get('supported_platforms', []),
        'source_url': item['source_url']} for guid, item in catalog.items()]
    write_json(ROOT / 'output/atomic-catalog.json', {'repository': ATOMIC_REPO, 'commit': ATOMIC_COMMIT, 'tests': safe_catalog})
    write_json(ROOT / 'output/atomic-plan.json', {'repository': ATOMIC_REPO, 'commit': ATOMIC_COMMIT,
        'execution_mode': 'recorded-equivalent', 'atomic_execution_verified': False,
        'plan': plan, 'limitations': LIMITATIONS})
    print(f'PASS metadata: {len(catalog)} catalogued tests, 2 selected GUIDs, 3 query mappings; no Atomic command executed', flush=True)
    return plan


def coverage(plan: list, results: dict) -> dict:
    by_query = {item['query_file']: item for item in results['results']}
    rows = []
    for item in plan:
        result = by_query[item['query_file']]
        columns = [col['name'] for col in result['columns']]
        observed_datasets = sorted({row[columns.index('dataset')] for row in result['values']})
        passed = len(result['values']) == item['expected_rows'] and observed_datasets == [item['dataset']]
        rows.append({**item, 'observed_rows': len(result['values']), 'observed_datasets': observed_datasets,
                     'recorded_query_validation': 'passed' if passed else 'failed'})
    return {'verified_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'repository': ATOMIC_REPO, 'commit': ATOMIC_COMMIT, 'execution_mode': 'recorded-equivalent',
        'atomic_execution_verified': False, 'elasticsearch_version': results['elasticsearch_version'],
        'recorded_events': results['events'], 'recorded_datasets': len(results['dataset_counts']),
        'mappings': rows, 'limitations': LIMITATIONS}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['sync', 'verify', 'catalog', 'run'])
    parser.add_argument('--atomic-root', type=Path, default=ROOT / 'atomic-red-team', help='Root of a local official Atomic checkout or pinned metadata snapshot')
    args = parser.parse_args(argv)
    if args.command == 'sync':
        sync_metadata(args.atomic_root)
    plan = verify(args.atomic_root)
    if args.command == 'catalog':
        for item in {item['guid']: item for item in plan}.values():
            print(f'{item["technique"]} | {item["guid"]} | {item["name"]}')
    if args.command == 'run':
        # This is our local JSON-only importer, not an upstream Atomic executor.
        subprocess.run([sys.executable, str(ROOT / 'run_week9.py')], check=True)
        results = json.loads((ROOT / 'output/results.json').read_text())
        report = coverage(plan, results)
        dataset_manifest = json.loads((ROOT / 'output/data-manifest.json').read_text())
        report['recorded_dataset_sources'] = dataset_manifest
        for mapping in report['mappings']:
            query_bytes = (ROOT / 'source/week9/queries' / mapping['query_file']).read_bytes()
            mapping['query_sha256'] = hashlib.sha256(query_bytes).hexdigest()
        write_json(ROOT / 'output/atomic-coverage.json', report)
        lines = [f'Atomic metadata: {ATOMIC_REPO} @ {ATOMIC_COMMIT}',
                 'Mode: recorded-equivalent. Live Atomic execution: NOT performed.',
                 f'Recorded telemetry: {report["recorded_events"]} events in {report["recorded_datasets"]} OTRF datasets.']
        for item in report['mappings']:
            lines.extend(['', f'{item["technique"]} | {item["guid"]} | {item["name"]}',
                f'Query: {item["query_file"]}; observed={item["observed_rows"]}; recorded validation={item["recorded_query_validation"]}',
                f'Evidence: {item["evidence"]}', f'Limit: {item["limitation"]}'])
        lines.extend(['', 'LIMITATIONS:'] + ['- ' + value for value in LIMITATIONS])
        (ROOT / 'output/atomic-coverage.txt').write_text('\n'.join(lines) + '\n')
        print('\n'.join(lines), flush=True)
        if any(item['recorded_query_validation'] != 'passed' for item in report['mappings']):
            return 1
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, FileNotFoundError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        raise SystemExit(1)
