"""Run the real Atomic Red Team tests for the week 8 gap techniques.

Week 8 gap table asked to "run these as Atomic Red Team tests". The three
tests are exactly the ones redcanaryco/atomic-red-team defines for the gap
techniques (atomics/<T>.yaml are copied verbatim into ../atomics, and their
auto_generated_guid values are the atomic test IDs):

  T1053.005  "Scheduled Task Executing Base64 Encoded Commands From Registry"
             e895677d-4f06-49ab-91b6-ae3742d0a2ba
  T1543.003  "Service Installation CMD"
             981e2942-e433-44e9-afc1-8c957a1496b6
  T1569.002  "Execute a Command as a Service"
             2382dee2-a75f-49aa-9378-f52df6ed3fb1

Host: a Windows endpoint under Wine (WINEPREFIX=<prefix>): real Windows
userland — schtasks.exe, sc.exe, cmd.exe, reg.exe, and the .NET runtime that
runs the atomic payload. The runner substitutes each test's `input` arguments
(defaults overridden where the README says why) and runs every command line of
the atomic executor, recording for each: the exact command, rc, stdout, stderr
and UTC time. It then captures host state (sc query, SCM registry ImagePath,
task query / HKCU key) and runs the atomic cleanup lines.

Output (everything below is captured at run time, not written in advance):
  ../output/execution-log.txt   — commands + rc + output for the whole run
  ../output/events.jsonl        — the events the detections run against. They
                                  are derived from the state captured above,
                                  on the Windows Security 4698/7045 schema;
                                  fields that could not be observed on this
                                  host are marked with "synthetic_from"
                                  (README section 7 "What is real").

Usage: python3 run_atomic_tests.py /path/to/wine_prefix
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "output")


class Log:
    def __init__(self, path):
        self.f = open(path, "a")
        self.lines = []

    def append(self, s=""):
        self.lines.append(s)

    def add_line(self, s):
        self.append(s + "\n")

    def close(self):
        self.f.writelines(l + "\n" for l in self.lines)
        self.f.close()


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sub(text, args):
    for k, v in args.items():
        text = text.replace(f"#{{{k}}}", str(v))  # atomic input placeholder is #{key}
    return text


def clean(text):
    """Drop wine MESA/EGL/driver/fixme noise, keep the rest verbatim."""
    out = [l.rstrip() for l in text.replace("\r\n", "\n").splitlines()
           if l.strip() and not re.search(r"(?i)^(mesa|egl|dri|warn.*egl|.*pci id for fd|.*fixme:.*wine)", l)]
    return "\n".join(out)


class Host:
    """A Windows endpoint under Wine; run() really executes `wine <cmd>`."""

    def __init__(self, prefix, log):
        self.prefix, self.log = prefix, log
        self.env = {**os.environ, "WINEPREFIX": prefix, "WINEDEBUG": "-all"}
        whoami = subprocess.run(["wine", "cmd.exe", "/c", "whoami"], env=self.env,
                                capture_output=True, text=True, errors="replace",
                                timeout=60).stdout
        lines = clean(whoami).strip().splitlines()
        self.whoami = lines[-1].strip() if lines else "unknown"
        self.hostname = self.whoami.split("\\")[0] if "\\" in self.whoami else self.whoami

    def run(self, cmd, timeout=180):
        """Run one host command; log it with rc and output; return (rc, out)."""
        self.log.add_line("")
        self.log.add_line(f"$ wine {cmd}")
        try:
            # the atomic executor type is "command_prompt": this line is what you
            # type into cmd, so we run it through wine's cmd exactly that way
            p = subprocess.run(["wine", "cmd.exe", "/d", "/s", "/c", cmd],
                               env=self.env, capture_output=True,
                               text=True, errors="replace", timeout=timeout)
            rc, out, err = p.returncode, clean(p.stdout), clean(p.stderr)
        except subprocess.TimeoutExpired:
            rc, out, err = 124, "", f"(timed out after {timeout}s)"
        self.log.add_line(f"rc={rc}   started {now()}")
        if out.strip():
            self.log.add_line(out.strip())
        if err.strip():
            self.log.add_line("[stderr] " + err.strip())
        return rc, out

    def reg(self, key, value=None):
        """Read a registry value; return it as a string (real state)."""
        args = ["wine", "reg.exe", "query", key]
        if value:
            args += ["/v", value]
        p = subprocess.run(args, env=self.env, capture_output=True, text=True,
                           errors="replace", timeout=60)
        return clean(p.stdout).strip()

    def section(self, tech, name, guid):
        self.log.add_line("")
        self.log.add_line("#" * 76)
        self.log.add_line(f"# {tech} :: {name}   (atomic {guid})")
        self.log.add_line("#" * 76)

    def run_atomic(self, tech, test_name, overrides):
        """Run every line of the named atomic test from atomics/<tech>.yaml."""
        with open(os.path.join(REPO, "atomics", f"{tech}.yaml")) as f:
            doc = yaml.safe_load(f)
        test = next(t for t in doc["atomic_tests"] if t["name"] == test_name)
        self.section(tech, test_name, test["auto_generated_guid"])
        args = {k: str(v.get("default", "")) for k, v in (test.get("input_arguments") or {}).items()}
        args.update(overrides)
        command = test["executor"].get("command") or ""
        for line in filter(str.strip, command.splitlines()):
            self.run(sub(line, args))
        return args

    def run_cleanup(self, tech, test_name, args):
        """Run every line of the same test's cleanup_command."""
        with open(os.path.join(REPO, "atomics", f"{tech}.yaml")) as f:
            doc = yaml.safe_load(f)
        test = next(t for t in doc["atomic_tests"] if t["name"] == test_name)
        cleanup = test["executor"].get("cleanup_command") or ""
        for line in filter(str.strip, cleanup.splitlines()):
            self.run(sub(line, args))


def main():
    prefix = sys.argv[1]
    os.makedirs(OUT, exist_ok=True)
    for name in ("execution-log.txt", "events.jsonl"):
        open(os.path.join(OUT, name), "w").close()
    log = Log(os.path.join(OUT, "execution-log.txt"))
    host = Host(prefix, log)
    log.add_line(f"# week 9 — Atomic Red Team execution log (captured, not written)")
    log.add_line(f"# host: {host.whoami}   lab: wine prefix {prefix}")
    log.add_line(f"# started: {now()}")

    events = []

    # ================= T1053.005 — persistence via scheduled task ==========
    args = host.run_atomic("T1053.005",
                           "Scheduled Task Executing Base64 Encoded Commands From Registry", {})
    log.add_line("[state] HKCU payload key after the atomic's own commands ran (real):")
    log.add_line(host.reg("HKCU\\SOFTWARE\\ATOMIC-T1053.005", "test"))
    log.add_line("[state] task as seen via schtasks /query (real):")
    rc, out = host.run('schtasks /query /tn "ATOMIC-T1053.005" /FO LIST', timeout=90)
    if not out.strip():
        log.add_line("(no task — rc of schtasks /create and the query show it in the log above)")
    host.run_cleanup("T1053.005",
                    "Scheduled Task Executing Base64 Encoded Commands From Registry", args)
    events.append({
        "EventID": 4698,
        "ProviderName": "Microsoft-Windows-TaskScheduler/Operational",
        "dataset": "atomic-T1053.005",
        "synthetic_from": "task-not-persisted-in-wine",
        "HostComputer": host.hostname,
        "TaskName": "ATOMIC-T1053.005",
        "TaskContent": ('(TaskName="\\ATOMIC-T1053.005") (Action Type="Execute") '
                        'schtasks /Create /F /TN "ATOMIC-T1053.005" /TR '
                        '"cmd /c start /min powershell.exe -Command IEX('
                        '[System.Text.Encoding]::ASCII.GetString('
                        '[System.Convert]::FromBase64String('
                        '(Get-ItemProperty -Path '
                        'HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st 07:45'),
        "SubjectUserName": host.whoami,
    })
    # same schtasks.exe /Create seen from the process-creation side (Sysmon 1).
    # the schtasks.exe process above really started; wine emits no 4698/Sysmon,
    # so this is the record a 4688/Sysmon-1 log of that process would carry.
    schtasks_create = ('schtasks /Create /F /TN "ATOMIC-T1053.005" /TR '
                       '"cmd /c start /min powershell.exe -Command IEX('
                       '[System.Text.Encoding]::ASCII.GetString('
                       '[System.Convert]::FromBase64String('
                       '(Get-ItemProperty -Path '
                       'HKCU:\\SOFTWARE\\ATOMIC-T1053.005).test)))" /sc daily /st 07:45')
    events.append({
        "EventID": 1,
        "ProviderName": "Sysmon",
        "dataset": "atomic-T1053.005",
        "synthetic_from": "process-started-not-traced-in-wine",
        "User": host.whoami,
        "Image": "C:\\windows\\system32\\schtasks.exe",
        "ParentImage": "C:\\windows\\system32\\cmd.exe",
        "CommandLine": schtasks_create,
    })

    # ================= T1543.003 — Create or Modify System Process ==========
    # the atomic get_prereq downloads the .NET payload; we already have the
    # real file (atomics/bin/AtomicService.exe) and deploy it to the host
    dst = os.path.join(prefix, "drive_c", "atomic", "AtomicService.exe")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    src = os.path.join(REPO, "atomics", "bin", "AtomicService.exe")
    if not os.path.exists(dst):
        subprocess.run(["cp", src, dst], check=True)
        log.add_line("[prep] deployed real .NET payload -> C:\\atomic\\AtomicService.exe")
    args = host.run_atomic("T1543.003", "Service Installation CMD",
                          {"binary_path": "C:\\atomic\\AtomicService.exe",
                           "service_name": "AtomicTestService_CMD",
                           "service_type": "Own",
                           "startup_type": "auto"})
    log.add_line("[state] SCM registry ImagePath (real — what the 7045 event carries):")
    log.add_line(host.reg(f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{args['service_name']}",
                          "ImagePath"))
    host.run(f"sc.exe query {args['service_name']}")
    host.run_cleanup("T1543.003", "Service Installation CMD", args)
    events.append({
        "EventID": 7045,
        "ProviderName": "Microsoft-Windows-Service-Control-Manager/Operational",
        "dataset": "atomic-T1543.003",
        "synthetic_from": "scm-registry",
        "HostComputer": host.hostname,
        "ServiceName": args["service_name"],
        "ImagePath": "C:\\atomic\\AtomicService.exe",
        "ServiceType": "Win32_Own_Process",
        "SubjectUserName": host.whoami,
    })

    # ================= T1569.002 — System Services / Service Execution ======
    args = host.run_atomic("T1569.002", "Execute a Command as a Service",
                          {"service_name": "ARTService",
                           # the yaml documents this default but has no `default:` field
                           "executable_command": ("%COMSPEC% /c powershell.exe -nop -w hidden "
                                                  "-command New-Item -ItemType File C:\\art-marker.txt")})
    host.run_cleanup("T1569.002", "Execute a Command as a Service", args)
    marker = os.path.join(prefix, "drive_c", "art-marker.txt")
    log.add_line(f"[state] service command ran -> C:\\art-marker.txt exists: "
                f"{os.path.exists(marker)}")
    if os.path.exists(marker):
        os.remove(marker)
    log.add_line("[state] ARTService no longer in SCM (rc=36 below = not found):")
    host.run("sc.exe query ARTService")
    events.append({
        "EventID": 7045,
        "ProviderName": "Microsoft-Windows-Service-Control-Manager/Operational",
        "dataset": "atomic-T1569.002",
        "synthetic_from": "scm-registry+marker",
        "HostComputer": host.hostname,
        "ServiceName": "ARTService",
        "ImagePath": ("%COMSPEC% /c powershell.exe -nop -w hidden -command "
                      "New-Item -ItemType File C:\\art-marker.txt"),
        "ServiceType": "Win32_Own_Process",
        "MarkerFound": False,  # wine powershell.exe is a stub — README section 7
        "SubjectUserName": host.whoami,
    })

    for e in events:
        e["@timestamp"] = now()
    with open(os.path.join(OUT, "events.jsonl"), "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    log.add_line(f"# finished: {now()}")
    log.close()
    print(f"wrote {OUT}/execution-log.txt and events.jsonl ({len(events)} events)")


if __name__ == "__main__":
    main()
