"""Static checks of the logtest specs (no Wazuh): every expect line has an event, every event
is valid EVE JSON, expected rule IDs exist. The real run is `make test-logtest`."""
import json
import unittest

from .helpers import ROOT, load

check = load("tools/check_logtest.py", "check_logtest")
lint = load("tools/lint_rules.py", "lint_rules")
TESTS = ROOT / "tests" / "logtest"


class SpecTest(unittest.TestCase):
    def test_specs_consistent(self):
        rules, findings = lint.lint(sorted(str(p) for p in (ROOT / "wazuh/rules").glob("*.xml")), (100200, 100299))
        self.assertEqual(findings, [])
        topics = sorted(p.stem for p in TESTS.glob("*.expect"))
        self.assertTrue(topics)
        for topic in topics:
            events = [l for l in (TESTS / f"{topic}.txt").read_text().splitlines() if l and not l.startswith("#")]
            for e in events:
                self.assertEqual(json.loads(e)["event_type"], "alert")
            cases = check.parse_expect((TESTS / f"{topic}.expect").read_text())
            self.assertEqual(sorted(c["n"] for c in cases), list(range(1, len(events) + 1)), topic)
            for c in cases:
                self.assertTrue(c["rule"] in rules or c["rule"] in lint.STOCK_PARENTS, (topic, c))

    def test_compare(self):
        cases = check.parse_expect("1 100220 3 no # a\n2 100206 6 yes # b\n")
        ok = [{"id": "100220", "level": 3, "alert": False}, {"id": "100206", "level": 6, "alert": True}]
        self.assertEqual(check.compare(cases, ok), [])
        bad = [{"id": "100206", "level": 6, "alert": True}]
        fails = check.compare(cases, bad)
        self.assertEqual(len(fails), 2)
        self.assertIn("event 1", fails[0])


class LintTest(unittest.TestCase):
    def test_catches_unanchored_and_literal_ip(self):
        import tempfile, pathlib
        p = pathlib.Path(tempfile.mkdtemp()) / "bad.xml"
        p.write_text('<group name="x,"><rule id="100250" level="3"><if_sid>100206</if_sid>'
                     '<field name="alert.signature_id" type="pcre2">2025701</field>'
                     '<description>from 10.10.2.3</description></rule></group>')
        _, findings = lint.lint([str(p)], (100200, 100299))
        text = "\n".join(findings)
        self.assertIn("not found", text)
        self.assertIn("anchored", text)
        self.assertIn("literal IP", text)


if __name__ == "__main__":
    unittest.main()
