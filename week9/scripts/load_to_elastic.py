"""Load the atomic-test event records into Elasticsearch.

Takes JSON-lines files (each line = one event) and indexes them into the
"winlogs" index, same as weeks 6-7: raw field names plus the "dataset" field
that tells which atomic test produced the event (it is already in each event).

Usage: python3 load_to_elastic.py http://127.0.0.1:9201 events.jsonl
"""
import json
import sys
import urllib.request

INDEX = "winlogs"


def post(url, body):
    if isinstance(body, str):
        body = body.encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def main():
    es, files = sys.argv[1].rstrip("/"), sys.argv[2:]
    # strings as keyword, so wildcards match TaskContent / ImagePath / CommandLine
    mapping = {"mappings": {"dynamic_templates": [{"strings": {
        "match_mapping_type": "string",
        "mapping": {"type": "keyword", "ignore_above": 32766}
    }}]}}
    req = urllib.request.Request(f"{es}/{INDEX}", data=json.dumps(mapping).encode(),
                                 headers={"Content-Type": "application/json"}, method="PUT")
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        if e.code != 400:  # index already exists (it does, from week 6/7)
            raise
    for path in files:
        for line in open(path, encoding="utf-8"):
            e = json.loads(line)
            post(f"{es}/{INDEX}/_doc", json.dumps(e))
    print(f"loaded {sum(1 for p in files for _ in open(p))} event(s) -> winlogs")


if __name__ == "__main__":
    main()
