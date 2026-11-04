"""Runs INSIDE a disposable Suricata container that plays the sensor (see `make test-sensor-ro`).
Every case goes through the real ForceCommand wrapper with real execution - not a dry run - and checks the
exit code, the output and that refused commands changed nothing. Evidence label: sensor-lab.
Layout: /opt/sensor-ro/{sensor_ro.py, guard.py, sensor_snapshot.py}."""
import hashlib
import json
import os
import subprocess
import sys

WRAPPER = "/opt/sensor-ro/sensor_ro.py"
SNAPSHOT = "/opt/sensor-ro/sensor_snapshot.py"
ALLOW = "/tmp/allowed-sha256"
CONFIG = "/etc/suricata/suricata.yaml"
SNAP_CMD = "python3 -I - --days 7 --logdir '/var/log/suricata' --pattern 'eve.json*' --work-hours '8-19'"


def setup():
    script = open(SNAPSHOT, "rb").read()
    with open(ALLOW, "w") as f:
        f.write(f"{hashlib.sha256(script).hexdigest()}  tools/sensor_snapshot.py\n")
    with open("/var/log/suricata/eve.json", "w") as f:  # lab telemetry for the snapshot and bounded reads
        for _ in range(20):
            f.write(json.dumps({"timestamp": "2026-11-03T10:00:00.000000+0000", "event_type": "alert",
                                "src_ip": "10.10.100.21", "dest_ip": "10.10.20.15", "dest_port": 445,
                                "alert": {"signature_id": 2025701, "signature": "lab", "severity": 3,
                                          "metadata": {"signature_severity": ["Minor"], "confidence": ["High"]}}})
                    + "\n")
    return script


def run(command, stdin=b""):
    env = {"SSH_ORIGINAL_COMMAND": command, "SENSOR_RO_ALLOWLIST": ALLOW, "PATH": os.environ["PATH"]}
    return subprocess.run([sys.executable, "-I", WRAPPER], input=stdin, env=env, capture_output=True)


def main():
    script = setup()
    os.makedirs("/tmp/sro-bin", exist_ok=True)  # a planted binary named like an allowed tool
    with open("/tmp/sro-bin/cat", "w") as f:
        f.write("#!/bin/sh\ntouch /tmp/sro-spoofed\n")
    os.chmod("/tmp/sro-bin/cat", 0o755)
    before = open(CONFIG, "rb").read()
    cases = [
        # (name, command, stdin, expect, expect_in_stdout); expect: True = runs and succeeds, False = refused (126),
        # "literal" = runs with the text as a plain argument (no shell) - harmless, checked by the config check
        ("build info", "suricata --build-info | head -3", b"", True, b"Suricata"),
        ("config read", "grep -c '^vars:' /etc/suricata/suricata.yaml", b"", True, b"1"),
        ("bounded EVE read", "tail -n 5 /var/log/suricata/eve.json | wc -l", b"", True, b"5"),
        ("aggregate", "grep -c 2025701 /var/log/suricata/eve.json", b"", True, b"20"),
        ("snapshot, allowlisted script", SNAP_CMD, script, True, b'"alerts": 20'),
        ("snapshot, modified script", SNAP_CMD, script + b"\nimport os\n", False, b""),
        ("snapshot, other script", SNAP_CMD, b"import os; os.system('id')\n", False, b""),
        ("delete config", f"rm -f {CONFIG}", b"", False, b""),
        ("overwrite config", f"echo x > {CONFIG}", b"", False, b""),
        ("in-place edit", f"sed -i s/vars/xx/ {CONFIG}", b"", False, b""),
        ("command substitution", "echo $(rm -f /etc/suricata/suricata.yaml)", b"", False, b""),
        ("double-quoted substitution stays literal", 'grep -c x "$(rm -f /etc/suricata/suricata.yaml)"', b"",
         "literal", b""),
        ("unbounded EVE dump", "cat /var/log/suricata/eve.json", b"", False, b""),
        ("root shell", "sudo -s", b"", False, b""),
        ("interactive login", "", b"", False, b""),
        ("background job", "sleep 1 & rm -f /etc/suricata/suricata.yaml", b"", False, b""),
        # review: checker and bash must not read the string differently - with no shell nothing expands
        ("no variable expansion", 'cat "$HOME/.bash_history" 2>/dev/null | wc -l', b"", True, b"0"),
        ("no tilde expansion", "cat ~root/.bash_history 2>/dev/null | wc -l", b"", True, b"0"),
        ("brace expansion", "{rm,-f,/etc/suricata/suricata.yaml}", b"", False, b""),
        ("glob as a command", "/???/?m -f /etc/suricata/suricata.yaml", b"", False, b""),
        ("quote confusion", "\"'\" $(rm -f /etc/suricata/suricata.yaml) \"'\"", b"", False, b""),
        ("function definition", "f(){ rm -f /etc/suricata/suricata.yaml; }; f", b"", False, b""),
        ("command chain", "ls && rm -f /etc/suricata/suricata.yaml", b"", False, b""),
        ("json.tool output file", "python3 -m json.tool /etc/suricata/suricata.yaml /tmp/out", b"", False, b""),
        ("jq reads extra files", "jq -n --rawfile x /etc/passwd '$x'", b"", False, b""),
        # review round 2: options that write files, unbounded telemetry, path spoofing - all ran before
        ("sed --expression=w", "sed -n --expression=w/tmp/sro-sed /x/p /etc/hosts", b"", False, b""),
        ("sed w command", "sed -n 'w /tmp/sro-sed2' /etc/hosts", b"", False, b""),
        ("awk --dump-variables", "awk --dump-variables=/tmp/sro-awk 'BEGIN{x=1}'", b"", False, b""),
        ("awk --profile", "awk --profile=/tmp/sro-awk2 'BEGIN{x=1}'", b"", False, b""),
        ("ss -D", "ss -D /tmp/sro-ss -t", b"", False, b""),
        ("file after a bounded stage", "head -n 1 /etc/hosts | grep -h . /var/log/suricata/eve.json", b"", False, b""),
        ("head --lines too large", "head --lines=100000 /var/log/suricata/eve.json", b"", False, b""),
        ("recursive grep of the log dir", "grep -rh . /var/log/suricata", b"", False, b""),
        ("raw log through uniq -c", "grep -h . /var/log/suricata/eve.json | uniq -c", b"", False, b""),
        ("aggregate then bound",
         "grep -o 'signature_id.: [0-9]*' /var/log/suricata/eve.json | sort | uniq -c | head -n 5", b"", True, b"20"),
        ("path spoofing", "/tmp/sro-bin/cat /etc/hosts", b"", False, b""),
        ("systemctl to another host", "systemctl -H nobody@192.0.2.1 status suricata", b"", False, b""),
        ("quoted pipe is a pattern", "grep -c '|' /etc/hosts", b"", "literal", b""),
        # review round 3: awk/sed programs, repeated options, path spellings, disk fill - all ran before
        ("awk program after --", "awk -- 'BEGIN{print 1 > \"/tmp/sro-r3-dash\"}'", b"", False, b""),
        ("awk quoted brace", "awk 'BEGIN{print \"}\" > \"/tmp/sro-r3-brace\"}'", b"", False, b""),
        ("awk ARGV", "awk 'BEGIN{ARGV[1]=\"/var/log/suricata/eve.json\";ARGC=2}{print}'", b"", False, b""),
        ("sed second -e", "sed -n -e 'w /tmp/sro-r3-sed' -e p /etc/hosts", b"", False, b""),
        ("double-slash log path", "cat //var/log/suricata/eve.json", b"", False, b""),
        ("proc root log path", "cat /proc/self/root/var/log/suricata/eve.json", b"", False, b""),
        ("disk fill via tac", "cat /dev/urandom | tac", b"", False, b""),
        ("journal without a bound", "journalctl -u suricata", b"", False, b""),
        ("awk print column", "awk '{print $1}' /etc/hosts | head -n 1", b"", True, b""),
        # review round 4: aliases of one option, the onboarding probe
        ("head count given twice", "head -n 5 --lines=100000 /var/log/suricata/eve.json", b"", False, b""),
        ("head lines and bytes", "head -n 5 -c 4000000 /var/log/suricata/eve.json", b"", False, b""),
        ("onboarding probe", "id; id", b"", False, b""),
        ("stderr merged", "suricata --build-info 2>&1 | grep -c 'This is Suricata'", b"", True, b"1"),
        ("quoted semicolon", "grep -c 'vars:' /etc/suricata/suricata.yaml", b"", True, b"1"),
    ]
    failed = 0
    for name, command, stdin, ok, needle in cases:
        r = run(command, stdin)
        if ok == "literal":
            good = r.returncode not in (0, 126)
        else:
            good = (r.returncode == 0) == ok and needle in r.stdout and (ok or r.returncode == 126)
        print(f"{'PASS' if good else 'FAIL'} {name}: rc={r.returncode} {(r.stdout or r.stderr)[:90]!r}")
        failed += not good
    intact = os.path.exists(CONFIG) and open(CONFIG, "rb").read() == before
    print(f"{'PASS' if intact else 'FAIL'} suricata.yaml unchanged after all refused writes")
    failed += not intact
    created = sorted(f for f in os.listdir("/tmp") if f.startswith("sro-") and f != "sro-bin")
    leftovers = sorted(f for f in os.listdir("/tmp") if f.startswith("sensor-ro-"))
    print(f"{'PASS' if not leftovers else 'FAIL'} no TMPDIR left behind {leftovers or ''}")
    failed += bool(leftovers)
    print(f"{'PASS' if not created else 'FAIL'} no file written by a refused option {created or ''}")
    failed += bool(created)
    print(f"sensor-ro: {len(cases) + 3} checks, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
