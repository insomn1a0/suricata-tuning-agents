"""Sensor-side ForceCommand decisions without a sensor. The real execution test is `make test-sensor-ro`
(a Suricata container plays the sensor). No shell runs the command, so the parse here is what executes."""
import hashlib
import unittest

from .helpers import ROOT, load

if not (ROOT / ".claude/hooks/guard.py").exists():
    raise unittest.SkipTest("guard not in this workspace")
ro = load("tools/sensor_ro.py", "sensor_ro")
SNAP = "sudo -n python3 -I - --days 7 --logdir '/var/log/suricata' --pattern 'eve.json*' --work-hours '8-19'"
SCRIPT = b"print('snapshot')\n"
HASHES = {hashlib.sha256(SCRIPT).hexdigest()}


def allowed(command, script=None):
    return ro.decide(command, script, HASHES)[0]


class SensorRo(unittest.TestCase):
    def test_reads(self):
        for cmd in ("sudo -n cat /etc/suricata/suricata.yaml",
                    "awk '{print $1}' /var/log/suricata/stats.log | sort | uniq -c",
                    "sudo -n suricatasc -c dump-counters",
                    "tail -n 50 /var/log/suricata/suricata.log 2>/dev/null",
                    "suricata --build-info 2>&1 | head -3",
                    "systemctl status suricata --no-pager",
                    "grep -h 'sid:2025701;' /var/lib/suricata/rules/suricata.rules | head -3",
                    "head -n1 /var/log/suricata/eve.json | python3 -m json.tool",
                    "grep -c '|' /etc/hosts", "awk 'NR>1 {print $3}' /var/log/suricata/stats.log",
                    "sed -n '1,5p' /etc/hosts", "tr -d x", "cut -d , -f 1 /etc/hosts | sort | uniq -c | head -n 5",
                    "jq -c .alert.signature_id /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -n 20",
                    "journalctl -u suricata -n 50 --no-pager", "ls -la /var/log/suricata",
                    "true"):
            self.assertTrue(allowed(cmd), cmd)

    def test_refusals(self):
        for cmd in ("", "rm -f /etc/suricata/disable.conf", "echo x > /etc/x", "echo $(id)", "ls; id", "ls && id",
                    "sleep 1 & id", "sudo -s", "sudo cat /etc/x", "cat /var/log/suricata/eve.json", "cat <(id)",
                    "python3 -c 'print(1)'", "ls 'unbalanced", "systemctl restart suricata", "ls\nrm -f /x",
                    "{rm,-f,/x}", "/???/?m -f /x", "f(){ rm -f /x; }; f", "cat /etc/x 2> /tmp/e", "cat /etc/x 1>&2",
                    "python3 -m json.tool in.json out.json", "jq -n --rawfile x /etc/passwd '$x'", "env",
                    "find / -name x", "xargs rm",
                    # review round 2 (each of these ran on the lab sensor before)
                    "sed -n --expression=w/tmp/x /x/p /etc/hosts", "awk --dump-variables=/tmp/x 'BEGIN{x=1}'",
                    "awk -d/tmp/x 'BEGIN{x=1}'", "ss -D /tmp/x -t", "head --lines=100000 /var/log/suricata/eve.json",
                    "head -n 1 /etc/hosts | grep -h . /var/log/suricata/eve.json", "grep -rh . /var/log/suricata",
                    "grep -h . /var/log/suricata/eve.json | uniq -c", "/tmp/x/cat /etc/hosts",
                    "systemctl -H nobody@192.0.2.1 status suricata", "tail -f /var/log/suricata/suricata.log",
                    "journalctl -f", "journalctl -o export -n 5", "cat /var/log/suricata/alerts.json",
                    # review round 3 (each ran on the lab sensor before)
                    "awk -- 'BEGIN{print 1 > \"/tmp/x\"}'", "awk 'BEGIN{print \"}\" > \"/tmp/x\"}'",
                    "awk 'BEGIN{ARGV[1]=\"/var/log/suricata/eve.json\";ARGC=2}{print}'",
                    "sed -n -e 'w /tmp/x' -e p /etc/hosts", "cat //var/log/suricata/fast.log",
                    "cat /proc/self/root/var/log/suricata/fast.log", "cat /dev/urandom | tac", "journalctl -u suricata",
                    "head -n 1000 /var/log/suricata/eve.json /var/log/suricata/eve.json.1", "grep -e a -e b f",
                    "python3 -I - --days 7 --logdir '/etc' --pattern '*'",
                    # review round 4: aliases of one option
                    "head -n 5 --lines=100000 /var/log/suricata/eve.json",
                    "head -5 --bytes=4000000 /var/log/suricata/eve.json",
                    "journalctl -n 5 --lines=100000 -u suricata", "journalctl -u suricata --unit=ssh -n 5",
                    "systemctl status suricata -n 100000", "id; id"):
            self.assertFalse(allowed(cmd), repr(cmd))

    def test_parse_is_what_runs(self):
        self.assertEqual(ro.parse("grep -h 'sid:1;' f | head -3 2>/dev/null"),
                         [(["grep", "-h", "sid:1;", "f"], None), (["head", "-3"], "null")])
        self.assertEqual(ro.parse('cat "$HOME/x"'), [(["cat", "$HOME/x"], None)])  # literal, never expanded

    def test_snapshot_needs_allowlisted_script(self):
        ok, _, plan = ro.decide(SNAP, SCRIPT, HASHES)
        self.assertTrue(ok)
        self.assertEqual(plan[1][:3], ["sudo", "-n", "/usr/bin/python3"])  # argv, absolute interpreter, no shell
        self.assertFalse(allowed(SNAP, SCRIPT + b"import os\n"))
        self.assertFalse(allowed(SNAP, b""))
        self.assertFalse(allowed(SNAP.replace("--days 7", "--days 7 -c x"), SCRIPT))  # not the snapshot form

    def test_refusal_does_not_point_at_the_laptop_change_path(self):
        ok, reason, _ = ro.decide("rm -f /x", None, HASHES)
        self.assertFalse(ok)
        self.assertNotIn("SENSOR_CHANGE", reason)


if __name__ == "__main__":
    unittest.main()
