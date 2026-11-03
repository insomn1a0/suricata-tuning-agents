"""Regression corpus runner: tests/corpus/<case>/{input.pcap, test.yaml, siem.yaml}.

Engine stage (`--engine`, evidence label pcap-lab): Suricata replays each pcap offline in a disposable
container with no network, with the generated threshold.config (suppress) and disable.conf applied, so
Suricata-side intents are held to the same standard; test.yaml `checks` (suricata-verify syntax: filter / count / match on dotted
EVE fields) must hold.
End-to-end stage (default, adds evidence label logtest): the same alerts go through Wazuh logtest with the
severity ladder and the rules GENERATED from tuning/intents; siem.yaml says what analysts must and must not
see. "No attack lost": every case marked `attack:` must be visible.

Why not the suricata-verify runner itself: run.py expects a Suricata source/build tree; the kit tests the
packaged engine image. The test.yaml subset used here is suricata-verify syntax, so cases can move there.

Exit: 0 pass, 1 an expectation failed, 2 not run (no docker), 3 setup/engine error.
Usage: corpus_test.py [--engine] [--case NAME] [--extra-intent FILE.yaml] [--keep]
  --extra-intent: render the intents plus this one into a temporary rule set (a deliberately bad intent
  must make the run fail - see `make test-e2e-mutant`)."""
import argparse
import collections
import json
import os
import re
import pathlib
import shutil
import subprocess
import sys
import tempfile

import yaml

import kitconfig
import render

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "corpus"
RULES = [ROOT / "suricata" / "rules" / "local.rules", CORPUS / "lab-standins.rules"]


def dotted(event, path):
    node = event
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def matches(event, match):
    return all(dotted(event, k) == v or (isinstance(dotted(event, k), list) and v in dotted(event, k))
               for k, v in match.items())


def run_suricata(image, case_dir, work, variables):
    out = work / case_dir.name
    out.mkdir(mode=0o777)
    os.chmod(out, 0o777)
    rules = work / "all.rules"
    cmd = ["docker", "run", "--rm", "--network", "none", "--entrypoint", "suricata",
           "-v", f"{case_dir}:/case:ro", "-v", f"{work}:/work", image, "--runmode", "single", "-k", "none",
           "-S", f"/work/{rules.name}", "-r", "/case/input.pcap", "-l", f"/work/{case_dir.name}",
           "--set", "threshold-file=/work/threshold.config"]
    for k, v in variables.items():
        cmd += ["--set", f"vars.address-groups.{k}={v}"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    eve = out / "eve.json"
    if r.returncode != 0 or not eve.exists():
        raise RuntimeError(f"suricata exit {r.returncode}: {r.stderr[-1500:]}")
    # An engine error is not a pass: a threshold line with a trailing comment was silently ignored this way.
    errors = [line for line in (r.stdout + r.stderr).splitlines() if re.match(r"^\S*\s*E: ", line) or " E: " in line]
    if errors:
        raise RuntimeError("suricata reported errors:\n" + "\n".join(errors[:5]))
    return [json.loads(line) for line in eve.read_text().splitlines() if line.strip()]


def check_engine(events, spec):
    problems = []
    for n, chk in enumerate(spec.get("checks", []), 1):
        f = chk["filter"]
        got = sum(1 for e in events if matches(e, f.get("match", {})))
        if got != f["count"]:
            problems.append(f"check {n}: expected {f['count']} got {got} for {f.get('match')}")
    return problems


def logtest(alerts, wazuh_dir, work):
    """Run alerts through Wazuh logtest with the given rules dir; returns one result per alert."""
    events = work / "siem-events.txt"
    events.write_text("".join(json.dumps(a) + "\n" for a in alerts))
    env = dict(os.environ, WAZUH_RULES_DIR=str(wazuh_dir))
    r = subprocess.run([str(ROOT / "tools" / "logtest.sh"), str(events)], capture_output=True, text=True, env=env)
    lines = r.stdout.splitlines()
    results = [json.loads(line) for line in lines if line.startswith("{")]
    if len(results) != len(alerts):
        raise RuntimeError(f"logtest returned {len(results)} results for {len(alerts)} alerts: {r.stderr[-800:]}")
    engine = next((line for line in lines if line.startswith("engine: ")), "engine: unknown")
    return results, engine


def check_siem(alerts, results, spec):
    problems, summary = [], collections.Counter()
    for exp in spec.get("expect", []):
        hits = [(a, r) for a, r in zip(alerts, results) if matches(a, exp["match"])]
        kind = "attack" if exp.get("attack") else "noise" if not exp["visible"] else "context"
        summary[f"{kind}_total"] += 1
        if not hits:  # never reached the SIEM (suppressed, disabled, not detected): counts as lost
            problems.append(f"{exp['name']}: no alert matched {exp['match']}")
            continue
        for a, r in hits:
            visible = bool(r.get("alert"))
            if visible != exp["visible"]:
                problems.append(f"{exp['name']}: expected {'visible' if exp['visible'] else 'hidden'}, got rule "
                                f"{r.get('id')} level {r.get('level')} {'visible' if visible else 'hidden'}")
            if "rule" in exp and str(r.get("id")) != str(exp["rule"]):
                problems.append(f"{exp['name']}: expected rule {exp['rule']}, got {r.get('id')}")
        summary[f"{kind}_ok"] += all(bool(r.get("alert")) == exp["visible"] for _, r in hits)
    return problems, summary


def load_intents(extra_intent, work):
    if not extra_intent:
        return render.load_intents()
    intents_dir = work / "intents"
    shutil.copytree(render.INTENTS, intents_dir)
    shutil.copy(extra_intent, intents_dir / pathlib.Path(extra_intent).name)
    return render.load_intents(intents_dir)


def build_suricata(intents, work):
    """Rules minus disabled SIDs, plus the threshold file - both rendered from the intents."""
    generated = render.render_suricata(intents)
    (work / "threshold.config").write_text(generated["threshold.config"])
    disabled = set(re.findall(r"^1:(\d+)", generated["disable.conf"], re.M))
    rules = "".join(r.read_text() for r in RULES).splitlines()
    kept = [line for line in rules if not (re.search(r"\bsid:(\d+);", line) and
                                           re.search(r"\bsid:(\d+);", line).group(1) in disabled)]
    (work / "all.rules").write_text("\n".join(kept) + "\n")


def build_rules(intents, extra_intent, work):
    """Wazuh rules dir: the repo's, or the repo's with an extra intent rendered in."""
    if not extra_intent:
        return ROOT / "wazuh"
    wazuh = work / "wazuh"
    shutil.copytree(ROOT / "wazuh", wazuh)
    (wazuh / "rules" / render.WAZUH_OUT.name).write_text(render.render_wazuh4(intents))
    return wazuh


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--engine", action="store_true", help="Suricata checks only (no Wazuh)")
    p.add_argument("--case", action="append", help="run only these cases")
    p.add_argument("--extra-intent", help="render this intent in addition to tuning/intents")
    p.add_argument("--keep", action="store_true")
    args = p.parse_args(argv)
    if not shutil.which("docker"):
        print("NOT_RUN: docker not found - corpus was not executed")
        return 2
    cfg = kitconfig.load()
    suite = yaml.safe_load((CORPUS / "suite.yaml").read_text())
    image = f"jasonish/suricata:{cfg['SURICATA_VERSION']}"
    work = pathlib.Path(tempfile.mkdtemp(prefix="corpus-"))
    os.chmod(work, 0o777)
    intents = load_intents(args.extra_intent, work)
    build_suricata(intents, work)
    wazuh_dir = None if args.engine else build_rules(intents, args.extra_intent, work)
    cases = sorted(d for d in CORPUS.iterdir() if (d / "test.yaml").exists() and (not args.case or d.name in args.case))
    print(f"engine: {subprocess.run(['docker', 'run', '--rm', '--entrypoint', 'suricata', image, '-V'], capture_output=True, text=True).stdout.strip()} ({image})")
    failed, total, engine = 0, collections.Counter(), "engine: not run"
    for case in cases:
        events = run_suricata(image, case, work, suite["vars"])
        problems = check_engine(events, yaml.safe_load((case / "test.yaml").read_text()))
        alerts = [e for e in events if e.get("event_type") == "alert"]
        if not args.engine and (case / "siem.yaml").exists():
            results, engine = logtest(alerts, wazuh_dir, work)
            more, summary = check_siem(alerts, results, yaml.safe_load((case / "siem.yaml").read_text()))
            problems += more
            total.update(summary)
        for pr in problems:
            print(f"FAIL {case.name}: {pr}")
        print(f"{case.name}: {len(alerts)} alerts, {len(problems)} problems")
        failed += bool(problems)
    if not args.engine:
        print(f"{engine}\nattacks visible {total['attack_ok']}/{total['attack_total']}, "
              f"noise hidden {total['noise_ok']}/{total['noise_total']}, "
              f"context as expected {total['context_ok']}/{total['context_total']}")
    if args.keep:
        print(f"work dir: {work}")
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (render.IntentError, RuntimeError, OSError, yaml.YAMLError) as e:
        # exit 3, not 1: a mutant must be killed by a lost attack, not by a broken run
        print(f"ERROR: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(3)
