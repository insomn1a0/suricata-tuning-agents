"""The public-repo guard accepts lab data only and is not fooled by prefixes or version strings."""
import contextlib
import io
import tempfile
import unittest

from .helpers import ROOT, load

lab = load("tools/check_lab_data.py", "check_lab_data")


def findings(line):
    return lab.ip_findings(line) + lab.host_findings(line)


class LabDataTest(unittest.TestCase):
    def test_allowed(self):
        for line in ("dest_ip ^10\\.10\\.20\\.15$ but literal 10.10.20.150:445",
                     "HOME_NET [10.10.0.0/16], beacon to 203.0.113.50, doc 198.51.100.7 and 192.0.2.0/24",
                     "files01.lab.local, sensor.lab.local, 127.0.0.1",
                     "Wazuh 4.14.9, Suricata 8.0.8, OID 1.3.6.1.4.1"):
            self.assertEqual(findings(line), [], line)

    def test_rejected(self):
        self.assertEqual(findings("from 10.1.2.3"), ["non-lab address 10.1.2.3"])  # lab-data: allow
        self.assertEqual(findings("net 10.0.0.0/8"), ["non-lab address 10.0.0.0/8"])  # wider than the lab  # lab-data: allow
        self.assertEqual(findings("dns 8.8.8.8"), ["non-lab address 8.8.8.8"])  # lab-data: allow
        self.assertEqual(findings("ssh analyst@sensor01.corp.local"), ["non-lab hostname sensor01.corp.local"])  # lab-data: allow
        self.assertEqual(findings("dc1.example.internal"), ["non-lab hostname dc1.example.internal"])  # lab-data: allow

    def test_allow_marker_skips_line(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt") as f:
            f.write("bad 8.8.4.4  # lab-data: allow\nbad 8.8.4.4\n")  # lab-data: allow
            f.flush()
            self.assertEqual(lab.check_file(f.name, "x"), ["x:2: non-lab address 8.8.4.4"])  # lab-data: allow

    @unittest.skipUnless((ROOT / ".git").exists(), "not a git repository")
    def test_repo_is_clean(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(lab.main([]), 0, out.getvalue())


if __name__ == "__main__":
    unittest.main()
