"""Import recorded OTRF JSON and run read-only ES|QL; never execute log contents."""
from pathlib import Path
import hashlib, json, urllib.request, urllib.error, datetime
import prepare_data
ROOT=Path(__file__).resolve().parent
ES='http://127.0.0.1:9201'
INDEX='winlogs'
QUERY_HASHES={'det-schtasks-persistence.esql':'4f38e243d6fae887a8e3d883c6f23c6198c749aa','det-schtasks-process.esql':'a4dca80db340c31fa086f7716150db28727d071b','det-service-lateral.esql':'2faec0a78e61124d051d84074b28610ce1ac74f3'}
def request(method,path,body=None,ctype='application/json'):
    if body is not None and not isinstance(body,bytes): body=json.dumps(body).encode()
    req=urllib.request.Request(ES+path,data=body,method=method,headers={'Content-Type':ctype})
    try:
        with urllib.request.urlopen(req,timeout=120) as response: return json.load(response)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f'Elasticsearch {e.code}: '+e.read().decode()[:4000]) from e

def main():
    info=request('GET','/')
    if info.get('cluster_name')!='threat-hunting-week9': raise RuntimeError('Unexpected cluster: refusing to write')
    manifest=json.loads((ROOT/'output'/'data-manifest.json').read_text())
    prepare_data.verify_manifest(manifest)
    expected=sum(r['events'] for d in manifest for r in d['records'])
    if len(manifest)!=9: raise RuntimeError('Expected all nine datasets')
    try:
        with urllib.request.urlopen(ES+'/'+INDEX,timeout=10) as r: existing=json.load(r)
    except urllib.error.HTTPError as e:
        if e.code!=404: raise
        existing=None
    if existing is None:
        mapping={'settings':{'number_of_replicas':0,'number_of_shards':1},'mappings':{'_meta':{'purpose':'threat-hunting-week9-recorded-data'},'dynamic_templates':[{'strings':{'match_mapping_type':'string','mapping':{'type':'keyword','ignore_above':32766}}}],'properties':{'@timestamp':{'type':'date'},'EventID':{'type':'long'},'Keywords':{'type':'keyword'}}}}
        request('PUT','/'+INDEX,mapping)
    elif existing[INDEX]['mappings'].get('_meta',{}).get('purpose')!='threat-hunting-week9-recorded-data':
        raise RuntimeError('Existing index is not owned by this lab')
    counts={}
    def bulk(lines):
        if not lines: return
        response=request('POST','/'+INDEX+'/_bulk',('\n'.join(lines)+'\n').encode(),'application/x-ndjson')
        if response.get('errors'):
            failures=[v for item in response['items'] for v in item.values() if 'error' in v]
            raise RuntimeError('Bulk import errors: '+json.dumps(failures[:3]))
    for dataset in manifest:
        for record in dataset['records']:
            file=ROOT/'data'/record['file']
            if hashlib.sha256(file.read_bytes()).hexdigest()!=record['sha256']: raise RuntimeError('Dataset changed: '+file.name)
            name=file.name.split('_20')[0]
            batch=[]; count=0
            with file.open(encoding='utf-8') as f:
                for n,line in enumerate(f,1):
                    event=json.loads(line); event['dataset']=name
                    if '@timestamp' not in event and 'TimeCreated' in event:
                        value=event['TimeCreated'].replace(' ','T')
                        event['@timestamp']=value if value.endswith('Z') else value+'Z'
                    docid=hashlib.sha256((file.name+':'+str(n)).encode()).hexdigest()
                    batch.extend((json.dumps({'index':{'_id':docid}}),json.dumps(event)))
                    count+=1
                    if len(batch)>=1000: bulk(batch); batch=[]
            bulk(batch)
            if count!=record['events']: raise RuntimeError('Wrong record count')
            counts[name]=count
            print('IMPORTED',name,count,flush=True)
    request('POST','/'+INDEX+'/_refresh')
    actual=request('GET','/'+INDEX+'/_count')['count']
    if actual!=expected: raise RuntimeError(f'Expected {expected} records, got {actual}')
    results=[]; output=[]
    for name,expectedhash in QUERY_HASHES.items():
        data=(ROOT/'source'/'week9'/'queries'/name).read_bytes()
        actualhash=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if actualhash!=expectedhash: raise RuntimeError('Query differs from verified source')
        result=request('POST','/_query?format=json',{'query':data.decode()})
        cols=[c['name'] for c in result['columns']]
        result['query_file']=name
        results.append(result)
        text=f'== {name}: {len(result["values"])} rows\n'+' | '.join(cols)+'\n'
        text+='\n'.join(' | '.join('' if x is None else str(x) for x in row) for row in result['values'])+'\n'
        output.append(text)
        print('RESULT',name,len(result['values']),'rows',flush=True)
    report={'verified_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elasticsearch_version':info['version']['number'],'events':actual,'dataset_counts':counts,'results':results,'cluster_health':request('GET','/_cluster/health')}
    (ROOT/'output'/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    (ROOT/'output'/'results.txt').write_text('\n'.join(output))
    hits=[len(r['values']) for r in results]
    if hits!=[1,2,1]: raise RuntimeError('Counts differ from repository baseline: '+str(hits))
    allowed={'empire_schtasks_creation_execution_elevated_user','empire_psexec_dcerpc_tcp_svcctl'}
    for result in results:
        columns=[c['name'] for c in result['columns']]
        datasetpos=columns.index('dataset')
        if any(row[datasetpos] not in allowed for row in result['values']): raise RuntimeError('Unexpected background dataset hit')
    print('PASS: all 9 datasets,',actual,'events; hit counts 1, 2, 1; no hits in the 7 background datasets',flush=True)
if __name__=='__main__': main()
