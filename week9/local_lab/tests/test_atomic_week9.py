import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import atomic_week9 as app

class AtomicMetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = app.load_catalog(app.ROOT / 'atomic-red-team')

    def test_catalog_has_28_pinned_tests(self):
        self.assertEqual(len(self.catalog), 28)

    def test_selects_two_guids_and_three_queries(self):
        plan = app.selected_plan(self.catalog)
        self.assertEqual(len(plan), 3)
        self.assertEqual({row['guid'] for row in plan}, {app.TASK_GUID, app.SERVICE_GUID})
        self.assertTrue(all(not row['atomic_execution_verified'] for row in plan))

    def test_absent_guid_rejected(self):
        catalog = dict(self.catalog)
        del catalog[app.TASK_GUID]
        with self.assertRaisesRegex(ValueError, 'Missing selected GUID'):
            app.selected_plan(catalog)

    def test_wrong_platform_rejected(self):
        catalog = copy.deepcopy(self.catalog)
        catalog[app.TASK_GUID]['test']['supported_platforms'] = ['linux']
        with self.assertRaisesRegex(ValueError, 'metadata changed'):
            app.selected_plan(catalog)

    def test_changed_name_rejected(self):
        catalog = copy.deepcopy(self.catalog)
        catalog[app.TASK_GUID]['test']['name'] = 'Different test'
        with self.assertRaisesRegex(ValueError, 'metadata changed'):
            app.selected_plan(catalog)

    def test_tampered_snapshot_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            shutil.copytree(app.ROOT / 'atomic-red-team/atomics', target / 'atomics')
            file = target / app.metadata_path('T1053.005')
            file.write_bytes(file.read_bytes() + b'\n# modified\n')
            with self.assertRaisesRegex(ValueError, 'differs from pinned'):
                app.load_catalog(target)

    def test_default_substitution_is_literal(self):
        test = {'input_arguments': {'value': {'default': '$(echo should-not-run)'}},
                'executor': {'command': 'show #{value}'}}
        self.assertEqual(app.default_text(test), 'show $(echo should-not-run)')

    def test_missing_default_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Missing default'):
            app.default_text({'executor': {'command': '#{missing}'}})

    def test_task_default_and_negative_control(self):
        chosen = app.default_text(self.catalog[app.TASK_GUID]['test'])
        self.assertTrue(app.suspicious_task_text(chosen))
        self.assertFalse(app.suspicious_task_text(r'C:\Windows\System32\cmd.exe'))

    def test_service_default_and_negative_control(self):
        chosen = self.catalog[app.SERVICE_GUID]['test']['input_arguments']['executable_command']['default']
        self.assertTrue(app.suspicious_service_text(chosen.upper()))
        self.assertFalse(app.suspicious_service_text(r'C:\Windows\Temp\AtomicService.exe'))

    def test_coverage_preserves_provenance_and_no_execution_claim(self):
        plan = app.selected_plan(self.catalog)
        results = {'elasticsearch_version': '9.5.5', 'events': 78868, 'dataset_counts': {'a':1},
            'results': [{'query_file': row['query_file'], 'columns':[{'name':'dataset'}],
                         'values':[[row['dataset']]] * row['expected_rows']} for row in plan]}
        report = app.coverage(plan, results)
        self.assertFalse(report['atomic_execution_verified'])
        self.assertTrue(all(row['recorded_query_validation']=='passed' for row in report['mappings']))
        results['results'][0]['values'][0][0]='unrelated_dataset'
        self.assertEqual(app.coverage(plan, results)['mappings'][0]['recorded_query_validation'], 'failed')

if __name__=='__main__': unittest.main()
