"""Native Suricata check for local signatures: syntax test (-T), then each PCAP from
tests/pcap/cases.json is replayed offline (-r) in a disposable container with no network,
and the resulting alerts are compared with the expectations.
Usage: pcap_test.py [--image jasonish/suricata:8.0] [--keep]
Evidence label for passing results: "pcap-lab (Suricata <version>)" - not proof of production behaviour
on a different version, ruleset or traffic."""
import argparse
import collections
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CASES = ROOT / "tests" / "pcap" / "cases.json"
RULES = ROOT / "suricata" / "rules" / "local.rules"


def docker(image, work, args):
    cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "suricata",
           "-v", f"{RULES}:/input/local.rules:ro", "-v", f"{work}:/work", image, *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def sets(variables):
    out = []
    for k, v in variables.items():
        out += ["--set", f"vars.address-groups.{k}={v}"]
    return out


def evaluate(alerts, case):
    wanted = set(case.get("only_sids") or [])
    got = collections.Counter()
    for a in alerts:
        sid = a["alert"]["signature_id"]
        if not wanted or sid in wanted:
            got[(sid, a.get("src_ip"), a.get("dest_ip"))] += 1
    exp = collections.Counter({(e["sid"], e["src_ip"], e["dest_ip"]): e["count"] for e in case["expect"]})
    problems = []
    for key in sorted(set(got) | set(exp), key=str):
        if got[key] != exp[key]:
            problems.append(f"sid={key[0]} {key[1]}->{key[2]}: expected {exp[key]} got {got[key]}")
    return problems


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--image", default=f"jasonish/suricata:{os.environ.get('SURICATA_VERSION') or '8.0'}")
    p.add_argument("--keep", action="store_true", help="keep the work directory")
    args = p.parse_args()
    if not shutil.which("docker"):
        print("NOT_RUN: docker not found - native Suricata tests were not executed")
        return 2
    spec = json.loads(CASES.read_text())
    work = pathlib.Path(tempfile.mkdtemp(prefix="pcap-test-"))
    os.chmod(work, 0o777)
    variables = sets(spec["suricata_vars"])

    ver = docker(args.image, work, ["-V"]).stdout.strip()
    print(f"engine: {ver or 'unknown'} ({args.image})")
    t = docker(args.image, work, ["-T", "-S", "/input/local.rules", "-l", "/work", *variables])
    if t.returncode != 0:
        print("FAIL syntax (-T):\n" + (t.stderr or t.stdout)[-2000:])
        return 1
    print("syntax: OK")

    failed = 0
    for case in spec["cases"]:
        name = pathlib.Path(case["pcap"]).stem
        out = work / name
        out.mkdir()
        os.chmod(out, 0o777)
        subprocess.run([sys.executable, str(CASES.parent / case["generator"]), str(work / case["pcap"])], check=True)
        r = docker(args.image, work, ["--runmode", "single", "-k", "none", "-S", "/input/local.rules",
                                      "-r", f"/work/{case['pcap']}", "-l", f"/work/{name}", *variables])
        eve = out / "eve.json"
        if r.returncode != 0 or not eve.exists():
            print(f"FAIL {name}: suricata exit {r.returncode}\n{r.stderr[-1500:]}")
            failed += 1
            continue
        alerts = [json.loads(l) for l in eve.read_text().splitlines()
                  if l.strip() and json.loads(l).get("event_type") == "alert"]
        problems = evaluate(alerts, case)
        for pr in problems:
            print(f"FAIL {name}: {pr}")
        print(f"{name}: {len(alerts)} alerts, {len(problems)} problems  # {case.get('notes', '')}")
        failed += bool(problems)
    if args.keep:
        print(f"work dir: {work}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
