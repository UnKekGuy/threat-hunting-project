"""Evaluate original predicates on literal default-action strings; no events are ingested."""
import json
import os
from pathlib import Path
import re
import sys
import unittest
import urllib.request
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import atomic_week9 as app

@unittest.skipUnless(os.environ.get('WEEK9_TEST_ES') == '1', 'Set WEEK9_TEST_ES=1 for local Elasticsearch expression tests')
class ElasticsearchPredicateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with urllib.request.urlopen('http://127.0.0.1:9201/', timeout=10) as r:
            info=json.load(r)
        if info.get('cluster_name') != 'threat-hunting-week9':
            raise RuntimeError('Unexpected cluster; refusing test')
        catalog=app.load_catalog(app.ROOT/'atomic-red-team')
        commands=app.default_text(catalog[app.TASK_GUID]['test'])
        cls.create=next(line for line in commands.splitlines() if 'schtasks' in line.lower() and '/create' in line.lower())
        cls.action=re.split(r'\s/tr\s',cls.create,maxsplit=1,flags=re.IGNORECASE)[1]
        cls.service=catalog[app.SERVICE_GUID]['test']['input_arguments']['executable_command']['default']

    def matches(self, filename, fields):
        query=(app.ROOT/'source/week9/queries'/filename).read_text()
        predicate=query.split('| WHERE',1)[1].split('| KEEP',1)[0]
        row=', '.join(name+' = '+json.dumps(value) for name,value in fields.items())
        query='ROW '+row+' | WHERE '+predicate+' | STATS matches = COUNT(*)'
        req=urllib.request.Request('http://127.0.0.1:9201/_query?format=json',method='POST',
             data=json.dumps({'query':query}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=30) as r:result=json.load(r)
        return result['values'][0][0]

    def test_task_default_action_matches(self):
        self.assertEqual(self.matches('det-schtasks-persistence.esql',{'EventID':4698,'TaskContent':self.action}),1)

    def test_task_plain_cmd_does_not_match(self):
        self.assertEqual(self.matches('det-schtasks-persistence.esql',{'EventID':4698,'TaskContent':r'C:\Windows\System32\cmd.exe'}),0)

    def test_task_null_does_not_match(self):
        self.assertEqual(self.matches('det-schtasks-persistence.esql',{'EventID':4698,'TaskContent':None}),0)

    def test_process_sysmon_matches(self):
        self.assertEqual(self.matches('det-schtasks-process.esql',{'EventID':1,'Image':r'C:\Windows\System32\schtasks.exe','NewProcessName':None,'CommandLine':self.create}),1)

    def test_process_security_coalesce_matches(self):
        self.assertEqual(self.matches('det-schtasks-process.esql',{'EventID':4688,'Image':None,'NewProcessName':r'C:\Windows\System32\schtasks.exe','CommandLine':self.create}),1)

    def test_process_casing_matches(self):
        self.assertEqual(self.matches('det-schtasks-process.esql',{'EventID':1,'Image':r'C:\WINDOWS\SYSTEM32\SCHTASKS.EXE','NewProcessName':None,'CommandLine':self.create.upper()}),1)

    def test_service_default_matches(self):
        self.assertEqual(self.matches('det-service-lateral.esql',{'EventID':7045,'ImagePath':self.service}),1)

    def test_service_plain_executable_does_not_match(self):
        self.assertEqual(self.matches('det-service-lateral.esql',{'EventID':7045,'ImagePath':r'C:\Windows\Temp\AtomicService.exe'}),0)

    def test_service_wrong_id_does_not_match(self):
        self.assertEqual(self.matches('det-service-lateral.esql',{'EventID':7040,'ImagePath':self.service}),0)

if __name__=='__main__': unittest.main()
