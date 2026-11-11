"""Download and validate recorded JSON lab data. Never execute content from logs."""
from pathlib import Path
import concurrent.futures, hashlib, json, urllib.request, zipfile, time
ROOT=Path(__file__).resolve().parent
COMMIT='d9d40ef123d2c87d5d3df28c96bcab4f0faccc87'
DATASETS=[
('persistence/host/empire_schtasks_creation_execution_elevated_user.zip','efb17cef30affdd953cdd1f27ab739c98410eea2'),
('lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip','3e3de27a68b450a6167b36d10d2e8768afef8b28'),
('credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip','62238d3cf2a67ca6dac5cd11746a20ef21eb50dc'),
('credential_access/host/empire_mimikatz_logonpasswords.zip','908597522a7dd9471c00fefac8a0721a81cd24c4'),
('credential_access/host/psh_lsass_memory_dump_comsvcs.zip','fd8eec1c22f0cbc3c2667e9b88509df12a84a134'),
('credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip','fc2a7def56eafb8d2dc9088217d4615d864a0fd0'),
('defense_evasion/host/cmd_mshta_vbscript_execute_psh.zip','9c9defd5f3cf563c36291b5a98c49be5a8b13d06'),
('execution/host/empire_launcher_vbs.zip','876430f905878589738d79dd434bd128dda50054'),
('execution/host/psh_powershell_httplistener.zip','ac23774536c98d7b45460fe860c95eb673b9f75d')]
def prepare(item, allow_download=True):
    path,expected=item
    url='https://raw.githubusercontent.com/OTRF/Security-Datasets/'+COMMIT+'/datasets/atomic/windows/'+path
    target=ROOT/'data'/Path(path).name
    if not target.exists():
        if not allow_download:
            raise FileNotFoundError("Missing pinned archive; run prepare_data.py: " + str(target))
        last=None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(url,timeout=60) as r:
                    data=r.read(10000001)
                if len(data)>10000000: raise ValueError('Archive too large')
                break
            except Exception as e:
                last=e
                if attempt==2: raise
                time.sleep(2)
    else: data=target.read_bytes()
    actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if actual!=expected: raise ValueError('Archive hash mismatch: '+target.name)
    if not target.exists(): target.write_bytes(data)
    records=[]
    with zipfile.ZipFile(target) as z:
        for info in z.infolist():
            if '/' in info.filename or '\\' in info.filename or not info.filename.endswith('.json') or info.file_size>150000000:
                raise ValueError('Unsafe archive member: '+info.filename)
            out=ROOT/'data'/info.filename
            content=z.read(info)
            count=0
            for line in content.splitlines():
                if not isinstance(json.loads(line),dict): raise ValueError('Expected JSON event')
                count+=1
            if out.exists() and out.read_bytes()!=content: raise ValueError('Existing JSON differs')
            if not out.exists(): out.write_bytes(content)
            records.append({'file':info.filename,'events':count,'sha256':hashlib.sha256(content).hexdigest()})
    result={'archive':target.name,'source_url':url,'git_blob_sha1':actual,'sha256':hashlib.sha256(data).hexdigest(),'records':records}
    print('VERIFIED',target.name,sum(r['events'] for r in records),'events',flush=True)
    return result

def verify_manifest(manifest):
    """Re-anchor a manifest and extracted JSON to immutable published archive hashes."""
    verified = [prepare(item, allow_download=False) for item in DATASETS]
    if manifest != verified:
        raise ValueError("Local data manifest does not match the verified pinned OTRF archives")
    return verified

if __name__=='__main__':
    (ROOT/'data').mkdir(exist_ok=True)
    (ROOT/'output').mkdir(exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(prepare,DATASETS))
    (ROOT/'output'/'data-manifest.json').write_text(json.dumps(results,indent=2)+'\n')
    print('COMPLETE',sum(r['events'] for d in results for r in d['records']),'events in',len(results),'datasets',flush=True)
