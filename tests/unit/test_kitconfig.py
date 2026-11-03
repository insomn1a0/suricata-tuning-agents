"""Config precedence and parsing: defaults < config/environment.env < process environment.
Regression: make's `-include` of the env file kept quotes and trailing spaces ('"8.0"   ')."""
import tempfile
import unittest

from .helpers import load

kc = load("tools/kitconfig.py", "kitconfig")


class KitConfigTest(unittest.TestCase):
    def test_parse_quotes_and_comments(self):
        cfg = kc.parse_env('SURICATA_VERSION="8.0.7"   # lab image tag\n'
                           "# WAZUH_VERSION=1\n"
                           'WAZUH_LOCATION="[001] (lab-sensor) any->/var/log/suricata/eve.json"\n')
        self.assertEqual(cfg, {"SURICATA_VERSION": "8.0.7",
                               "WAZUH_LOCATION": "[001] (lab-sensor) any->/var/log/suricata/eve.json"})

    def test_precedence(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env") as f:
            f.write('WAZUH_VERSION="4.14.8"\nSURICATA_VERSION="8.0.7"\n')
            f.flush()
            cfg = kc.load(f.name, environ={"SURICATA_VERSION": "8.0.6", "UNRELATED": "x"})
        self.assertEqual(cfg["WAZUH_VERSION"], "4.14.8")
        self.assertEqual(cfg["SURICATA_VERSION"], "8.0.6")
        self.assertEqual(cfg["RULE_ID_RANGE"], kc.DEFAULTS["RULE_ID_RANGE"])
        self.assertNotIn("UNRELATED", cfg)

    def test_missing_file_gives_defaults(self):
        self.assertEqual(kc.load("/nonexistent/environment.env", environ={}), kc.DEFAULTS)


if __name__ == "__main__":
    unittest.main()
