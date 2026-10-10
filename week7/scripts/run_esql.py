"""Run ES|QL query files against Elasticsearch and print the result as a table.

Usage: python3 run_esql.py http://127.0.0.1:9201 queries/car-2020-05-001.esql [more.esql ...]
"""
import json
import sys
import urllib.request


def esql(es, query):
    req = urllib.request.Request(f"{es}/_query?format=json", method="POST",
                                 data=json.dumps({"query": query}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def main():
    es = sys.argv[1].rstrip("/")
    for path in sys.argv[2:]:
        r = esql(es, open(path, encoding="utf-8").read())
        cols = [c["name"] for c in r["columns"]]
        print(f"== {path}: {len(r['values'])} rows")
        print(" | ".join(cols))
        for row in r["values"]:
            print(" | ".join("" if v is None else str(v) for v in row))
        print()


if __name__ == "__main__":
    main()
