"""Load OTRF Security-Datasets JSON logs into Elasticsearch.

Every event goes to the index "winlogs" as it is (raw Sysmon / Security field names),
plus a "dataset" field with the file name, so hits can be traced back.

Usage: python3 load_to_elastic.py http://127.0.0.1:9201 dataset1.json [dataset2.json ...]
"""
import json
import sys
import urllib.request

INDEX = "winlogs"


def post(url, body, ctype="application/json"):
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype}, method="POST")
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def main():
    es, files = sys.argv[1].rstrip("/"), sys.argv[2:]
    # keyword fields, so CallTrace/TargetImage can be matched with wildcards
    mapping = {"mappings": {"dynamic_templates": [{"strings": {
        "match_mapping_type": "string",
        "mapping": {"type": "keyword", "ignore_above": 32766}}}],
        "properties": {"@timestamp": {"type": "date"}, "EventID": {"type": "long"},
                       # number in some datasets, hex string in others
                       "Keywords": {"type": "keyword"}}}}
    req = urllib.request.Request(f"{es}/{INDEX}", data=json.dumps(mapping).encode(),
                                 headers={"Content-Type": "application/json"}, method="PUT")
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        if e.code != 400:  # 400 = index already exists
            raise
    for path in files:
        name = path.rsplit("/", 1)[-1].split("_20")[0]
        lines = []
        for line in open(path, encoding="utf-8"):
            e = json.loads(line)
            e["dataset"] = name
            # newer datasets only have TimeCreated ("2020-10-18 07:50:06.220"), taken as UTC
            if "@timestamp" not in e and "TimeCreated" in e:
                e["@timestamp"] = e["TimeCreated"].replace(" ", "T") + "Z"
            lines.append('{"index":{}}')
            lines.append(json.dumps(e))
        r = post(f"{es}/{INDEX}/_bulk?refresh=true", ("\n".join(lines) + "\n").encode(),
                 "application/x-ndjson")
        print(f"{name}: {len(lines) // 2} events, errors={r['errors']}")


if __name__ == "__main__":
    main()
