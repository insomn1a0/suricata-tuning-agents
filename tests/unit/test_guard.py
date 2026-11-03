"""PreToolUse guard: a table of tool calls -> expected decision. Quoting, nesting and wrappers are the
tricky part - a guard that only matches the obvious spelling is a false sense of safety."""
import io
import json
import subprocess
import sys
import unittest

from .helpers import ROOT, load

GUARD = ROOT / ".claude/hooks/guard.py"
if not GUARD.exists():  # plugin workspace: the guard ships with the plugin, tested in the kit repo
    raise unittest.SkipTest("guard not in this workspace")
guard = load(".claude/hooks/guard.py", "guard")
CTX = guard.Context("sensor.lab.local", {"sensor.lab.local", "files01.lab.local", "dc1.lab.local"})
S = "ssh -o BatchMode=yes analyst@sensor.lab.local"

BASH = [
    # read-only sensor access is the normal path
    (f"{S} 'sudo -n cat /etc/suricata/suricata.yaml'", "allow"),
    (f"{S} \"sudo -n grep -h 'sid:2025701;' /var/lib/suricata/rules/suricata.rules | head -5\"", "allow"),
    (f"{S} 'tail -n 50 /var/log/suricata/suricata.log 2>/dev/null'", "allow"),
    (f"{S} 'systemctl status suricata --no-pager'", "allow"),
    (f"{S} 'sudo -n suricatasc -c dump-counters'", "allow"),
    (f"{S} \"sudo -n python3 -I - --days 7\" < tools/sensor_snapshot.py > snapshots/x.json", "allow"),
    ("tools/snapshot.sh 7", "allow"),
    # writes on the sensor
    (f"{S} \"sudo tee /etc/suricata/disable.conf\"", "block"),
    (f"{S} 'echo 2025701 | sudo -n tee -a /etc/suricata/disable.conf'", "block"),
    (f"{S} 'sudo -n sed -i s/a/b/ /etc/suricata/suricata.yaml'", "block"),
    (f"{S} 'echo x > /tmp/f'", "block"),
    (f"{S} 'cat /etc/hosts >> /tmp/f'", "block"),
    (f"{S} 'sudo systemctl restart suricata'", "block"),
    (f"{S} 'sudo -n suricatasc -c reload-rules'", "block"),
    (f"{S} 'sudo apt-get install -y tcpdump'", "block"),
    (f"{S} 'sudo -n pip3 install scapy'", "block"),
    (f"{S} 'sudo tcpreplay -i eth0 x.pcap'", "block"),
    (f"{S} 'sudo -n rm -f /var/log/suricata/eve.json.1'", "block"),
    (f"{S} 'find /var/log/suricata -name \"*.gz\" -delete'", "block"),
    (f"{S} 'sudo kill -HUP 1234'", "block"),
    (f"{S} \"bash -c 'sudo mv /a /b'\"", "block"),
    (f"{S} 'cat x; sudo -n cp /a /b'", "block"),
    (f"{S} 'python3 -c \"open(1)\"'", "block"),
    (f"{S} 'sudo bash -s' < fix.sh", "block"),
    (f"{S}", "block"),
    ("scp disable.conf analyst@sensor.lab.local:/tmp/", "block"),
    ("scp analyst@sensor.lab.local:/var/log/suricata/eve.json .", "ask"),
    ("bash -c \"ssh analyst@sensor.lab.local 'sudo -n rm /x'\"", "block"),
    (f"echo $({S} 'sudo -n rm -rf /x')", "block"),
    # found by probing the first (denylist) version - all of these were allowed
    (f"{S} 'sudo vim /etc/suricata/suricata.yaml'", "block"),
    (f"{S} 'ls /tmp/x | xargs sudo rm'", "block"),
    (f"{S} \"awk 'BEGIN{{system(\\\"rm /x\\\")}}'\"", "block"),
    (f"{S} 'sudo tar -xf /tmp/r.tgz -C /etc/suricata'", "block"),
    (f"{S} 'sudo journalctl --vacuum-time=1s'", "block"),
    (f"{S} 'sudo ip link set eth1 down'", "block"),
    (f"{S} 'sudo -n somebinary --apply'", "ask"),
    # reads that matter for sensor health stay allowed
    (f"{S} 'ip -s link show eth1; ethtool -S eth1 | grep -i drop'", "allow"),
    (f"{S} 'sudo -n journalctl -u suricata --since -1h --no-pager | tail -20'", "allow"),
    (f"{S} \"awk '{{print $1}}' /var/log/suricata/stats.log | sort | uniq -c\"", "allow"),
    (f"{S} 'sudo -n suricata --build-info'", "allow"),
    (f"{S} 'sudo -n suricata -c /etc/suricata/suricata.yaml -i eth1'", "block"),
    # approved sensor-change path goes to the user, never silently through
    (f"SENSOR_CHANGE=2025701 {S} 'sudo -n cp -a /etc/suricata/disable.conf /etc/suricata/disable.conf.bak-20261103'", "ask"),
    # git and outward-facing actions
    ("git commit -m 'x'", "ask"),
    ("git -C /repo push origin main", "ask"),
    ("make lint && git add -A && git commit -qm wip", "ask"),
    ("git status && git diff --stat", "allow"),
    ("gh pr merge 3 --squash", "ask"),
    ("gh pr view 3", "allow"),
    # internal identifiers to the web
    ("curl -s https://api.example.org/lookup?ip=10.10.20.15", "block"),
    ("wget https://search.example.org/?q=files01.lab.local", "block"),
    ("curl -s https://api.github.com/repos/OISF/suricata/releases/latest", "allow"),
    # secrets into files
    ("echo 'API_TOKEN=s3cr3tvalue123456' >> config/environment.env", "block"),
    ("echo 'WAZUH_ALERT_LEVEL=6' >> config/environment.env", "allow"),
    # local work stays unrestricted
    ("rm -rf examples/lab/data && make demo", "allow"),
    ("echo 'unbalanced", "ask"),
]

FILES = [
    ("Write", {"file_path": "config/environment.env", "content": 'SIEM_PASSWORD="Hunter2Hunter2"\n'}, "block"),
    ("Write", {"file_path": "x.md", "content": "token: ghp_" + "a" * 36}, "block"),
    ("Edit", {"file_path": "x.py", "old_string": "a", "new_string": "-----BEGIN OPENSSH PRIVATE KEY-----"}, "block"),
    ("Write", {"file_path": "docs/SAFETY.md", "content": "Never use passwords or tokens.\npassword: $SIEM_PASSWORD\n"}, "allow"),
    ("Write", {"file_path": "config/environment.example.env", "content": 'SENSOR_SSH="analyst@sensor.lab.local"\n'}, "allow"),
    ("MultiEdit", {"file_path": "a", "edits": [{"old_string": "x", "new_string": "api_key = 'abcd1234efgh5678'"}]}, "block"),  # gitleaks:allow
]

WEB = [
    ("WebSearch", {"query": "ET INFO SMB2 NT Create AndX 2025701 false positive"}, "allow"),
    ("WebSearch", {"query": "suricata alert from 10.10.30.40 to dc1.lab.local"}, "block"),
    ("WebFetch", {"url": "https://docs.suricata.io/en/latest/", "prompt": "what is files01.lab.local"}, "block"),
    ("WebFetch", {"url": "https://docs.suricata.io/en/latest/rules/dcerpc-keywords.html", "prompt": "opnum"}, "allow"),
]


class GuardTable(unittest.TestCase):
    def check(self, tool, tool_input, expected):
        decision, reasons = guard.decide(tool, tool_input, CTX)
        self.assertEqual(decision, expected, f"{tool} {tool_input} -> {decision} {reasons}")
        if expected != "allow":
            self.assertTrue(reasons, "a non-allow decision must say why")

    def test_bash(self):
        for cmd, expected in BASH:
            with self.subTest(cmd=cmd):
                self.check("Bash", {"command": cmd}, expected)

    def test_file_tools(self):
        for tool, tool_input, expected in FILES:
            with self.subTest(tool=tool, input=tool_input):
                self.check(tool, tool_input, expected)

    def test_web_tools(self):
        for tool, tool_input, expected in WEB:
            with self.subTest(tool=tool, input=tool_input):
                self.check(tool, tool_input, expected)

    def test_case_count(self):
        self.assertGreaterEqual(len(BASH) + len(FILES) + len(WEB), 25)


class GuardProcess(unittest.TestCase):
    """The hook contract as Claude Code sees it: exit code, stderr, stdout JSON."""

    def run_hook(self, payload):
        return subprocess.run([sys.executable, str(ROOT / ".claude/hooks/guard.py")], input=payload,
                              capture_output=True, text=True, env={"CLAUDE_PROJECT_DIR": str(ROOT)})

    def test_block_exits_2_with_reason(self):
        r = self.run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": f"{S} 'sudo rm /x'"}}))
        self.assertEqual(r.returncode, 2)
        self.assertIn("read-only", r.stderr)

    def test_ask_returns_permission_decision(self):
        r = self.run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "git push"}}))
        self.assertEqual(r.returncode, 0)
        out = json.loads(r.stdout)["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "ask")

    def test_allow_is_silent(self):
        r = self.run_hook(json.dumps({"tool_name": "Read", "tool_input": {"file_path": "README.md"}}))
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, "", ""))

    def test_fail_closed_on_garbage(self):
        r = self.run_hook("not json")
        self.assertEqual(r.returncode, 2)
        self.assertIn("fail closed", r.stderr)


if __name__ == "__main__":
    unittest.main()
