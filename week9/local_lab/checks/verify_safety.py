"""Regression checks for optimized Python launch guards and data provenance."""
from pathlib import Path
import copy
import json
import os
import subprocess
import sys
import tempfile
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import prepare_data

with tempfile.TemporaryDirectory() as temp:
    directory=Path(temp)
    marker=directory/'started'
    container={'HostConfig':{'Memory':3221225472,'PortBindings':{'9200/tcp':[{'HostIp':'0.0.0.0','HostPort':'9201'}]}},
      'ImageDigest':'sha256:13b4a40bb095774f5fda635e45fd5677cc6a26565e42b24997b0c72b88e75984',
      'Config':{'Env':['xpack.security.enabled=false']}}
    fake=directory/'podman'
    fake.write_text('#!/usr/bin/env python3\nimport sys,pathlib\nif sys.argv[1:3]==["container","exists"]: sys.exit(0)\nif sys.argv[1]=="inspect": print('+repr(json.dumps([container]))+'); sys.exit(0)\npathlib.Path('+repr(str(marker))+').write_text("unexpected start")\nsys.exit(1)\n')
    fake.chmod(0o700)
    env=dict(os.environ,PATH=str(directory)+os.pathsep+os.environ['PATH'],PYTHONOPTIMIZE='1')
    result=subprocess.run(['bash',str(ROOT/'start-lab.sh')],env=env,text=True,capture_output=True)
    if result.returncode==0 or marker.exists() or 'Unexpected port binding' not in result.stderr:
        raise RuntimeError('Optimized launch guard failed: '+repr(result))
    print('PASS: PYTHONOPTIMIZE=1 still rejects non-loopback containers before start')

manifest=json.loads((ROOT/'output/data-manifest.json').read_text())
modified=copy.deepcopy(manifest)
modified[0]['records'][0]['events']+=1
try:
    prepare_data.verify_manifest(modified)
except ValueError as error:
    if 'does not match' not in str(error): raise
else:
    raise RuntimeError('Modified manifest accepted')
print('PASS: modified local manifest rejected against pinned archives')

with tempfile.TemporaryDirectory() as temp:
    root=Path(temp);(root/'data').mkdir()
    item=prepare_data.DATASETS[0]
    (root/'data'/Path(item[0]).name).write_bytes(b'modified archive')
    with patch.object(prepare_data,'ROOT',root):
        try:
            prepare_data.prepare(item,allow_download=False)
        except ValueError as error:
            if 'hash mismatch' not in str(error):raise
        else:
            raise RuntimeError('Modified archive accepted')
print('PASS: modified source archive rejected against published Git blob SHA')
