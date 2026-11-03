"""Run logtest for each <topic> and compare with tests/logtest/<topic>.expect.
Expect line: '<event_no> <rule_id> <level> <alert yes|no>  # note'  (event_no counts events, 1-based)
Usage: check_logtest.py <topic> [<topic> ...]     exit 1 on any failure or analysisd ERROR/WARNING"""
import json
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests" / "logtest"


def parse_expect(text):
    cases = []
    for raw in text.splitlines():
        body, _, note = raw.partition("#")
        if not body.strip():
            continue
        n, rid, lvl, alert = body.split()
        if alert not in ("yes", "no"):
            raise ValueError(f"alert must be yes/no: {raw!r}")
        cases.append({"n": int(n), "rule": rid, "level": lvl, "alert": alert, "note": note.strip()})
    return cases


def compare(cases, results):
    failures = []
    for c in cases:
        got = results[c["n"] - 1] if c["n"] <= len(results) else {}
        g = (str(got.get("id")), str(got.get("level")), "yes" if got.get("alert") else "no")
        if g != (c["rule"], c["level"], c["alert"]):
            failures.append(f"event {c['n']}: expected {c['rule']} {c['level']} {c['alert']} "
                            f"got {' '.join(g)}  # {c['note']}")
    return failures


def run(topic):
    out = subprocess.run([str(ROOT / "tools" / "logtest.sh"), str(TESTS / f"{topic}.txt")],
                         capture_output=True, text=True)
    lines = out.stdout.splitlines()
    results = [json.loads(l) for l in lines if l.startswith("{")]
    version = next((l for l in lines if l.startswith("engine: ")), "engine: unknown")
    engine = [l for l in lines + out.stderr.splitlines()
              if not l.startswith("{") and ("ERROR" in l or "WARNING" in l)]
    if out.returncode != 0 and not results:
        engine.append(f"logtest.sh exited {out.returncode}: {out.stderr.strip()[-500:]}")
    return results, engine, version


def main(topics):
    if not shutil.which("docker"):
        print("NOT_RUN: docker not found - Wazuh logtest was not executed")
        return 2
    total = 0
    for topic in topics:
        cases = parse_expect((TESTS / f"{topic}.expect").read_text())
        results, engine, version = run(topic)
        if topic == topics[0]:
            print(version)
        failures = compare(cases, results)
        for f in failures:
            print(f"FAIL {topic} {f}")
        for e in engine:
            print(f"ENGINE {topic} {e}")
        print(f"{topic}: {len(results)} events, {len(cases)} cases, {len(failures)} failed")
        total += len(failures) + len(engine)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:] or sorted(p.stem for p in TESTS.glob("*.expect"))))
