"""Run the week 5 PowerShell hunt logic over OTRF Security-Datasets logs.

The filter is the same as the Splunk/KQL queries in the README:
Sysmon 1, Security 4688 and PowerShell 4104 events where PowerShell runs
with an encoded command, execution policy bypass, IEX or a download cradle.

Second check: PowerShell started by mshta.exe (LockBit ran HTA files via mshta in AA23-325A).

Usage: python3 hunt_powershell.py dataset1.json [dataset2.json ...]
"""
import base64
import json
import re
import sys
from collections import Counter

EVENTS = {
    ("Microsoft-Windows-Sysmon/Operational", 1),
    ("Security", 4688),
    ("Microsoft-Windows-PowerShell/Operational", 4104),
}
PS = re.compile(r"\b(powershell|pwsh)(\.exe)?\b", re.I)
SUSPICIOUS = re.compile(
    r"(\s[-/](enc|encodedcommand|e|ec)\s"
    r"|executionpolicy\s+bypass|\s-ep\s+bypass"
    r"|invoke-expression|\biex\b"
    r"|net\.webclient|downloadstring|downloadfile"
    r"|invoke-webrequest|\biwr\b)",
    re.I,
)
ENC_ARG = re.compile(r"\s[-/](?:enc|encodedcommand|e|ec)\s+([A-Za-z0-9+/=]{20,})", re.I)


def decode(cmd):
    m = ENC_ARG.search(cmd)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16le")
    except Exception:
        return None


def hunt(path):
    hits = []
    for line in open(path, encoding="utf-8"):
        e = json.loads(line)
        if (e.get("Channel"), e.get("EventID")) not in EVENTS:
            continue
        image = e.get("Image") or e.get("NewProcessName") or ""
        cmd = e.get("CommandLine") or e.get("ScriptBlockText") or ""
        # 4104 comes from the PowerShell log itself, process events need a PowerShell image
        if e["EventID"] != 4104 and not (PS.search(image) or PS.search(cmd)):
            continue
        parent = e.get("ParentImage") or e.get("ParentProcessName") or ""
        if SUSPICIOUS.search(" " + cmd):
            e["_reason"] = "suspicious arguments"
        elif parent.lower().endswith("\\mshta.exe"):
            e["_reason"] = "parent is mshta.exe"
        else:
            continue
        hits.append(e)
    return hits


def main():
    for path in sys.argv[1:]:
        hits = hunt(path)
        print(f"== {path.rsplit('/', 1)[-1]}: {len(hits)} hits")
        print("   by event:", dict(Counter(f"{h['Channel'].split('/')[0]}:{h['EventID']}" for h in hits)))
        seen = set()
        for h in hits:
            cmd = (h.get("CommandLine") or h.get("ScriptBlockText") or "").strip()
            key = cmd[:120]
            if key in seen:
                continue
            seen.add(key)
            parent = h.get("ParentImage") or h.get("ParentProcessName") or "-"
            print(f"   [{h.get('@timestamp', h.get('TimeCreated', ''))}] {h['EventID']} host={h.get('Hostname', '-')} parent={parent} ({h['_reason']})")
            print(f"     cmd: {cmd[:160]}")
            decoded = decode(" " + cmd)
            if decoded:
                print(f"     decoded: {decoded[:200]}")
        print()


if __name__ == "__main__":
    main()
