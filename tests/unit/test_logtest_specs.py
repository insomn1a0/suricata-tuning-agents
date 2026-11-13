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
            lines = (TESTS / f"{topic}.txt").read_text().splitlines()
            events = [line for line in lines if line and not line.startswith("#")]
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
        import tempfile
        import pathlib
        p = pathlib.Path(tempfile.mkdtemp()) / "bad.xml"
        p.write_text('<group name="x,"><rule id="100250" level="3"><if_sid>100206</if_sid>'
                     '<field name="alert.signature_id" type="pcre2">2025701</field>'
                     '<description>from 10.10.2.3</description></rule></group>')
        _, findings = lint.lint([str(p)], (100200, 100299))
        text = "\n".join(findings)
        self.assertIn("not found", text)
        self.assertIn("anchored", text)
        self.assertIn("literal IP", text)

    def test_ladder_leaf_is_not_a_lowering(self):
        """Severity + confidence at the stock parent's level splits a hidden bucket; anything wider still hides."""
        import tempfile
        import pathlib
        leaf = ('<rule id="{id}" level="{level}"><if_sid>86601</if_sid>'
                '<field name="alert.metadata.signature_severity">Minor</field>{extra}'
                '<description>x</description><group>suricata,</group></rule>')
        conf = '<field name="alert.metadata.confidence">Medium</field>'
        for rule, flagged in ((dict(id=100250, level=3, extra=conf), False),
                              (dict(id=100251, level=2, extra=conf), True),     # below the stock level
                              (dict(id=100252, level=3, extra=""), True),       # wider than one bucket
                              (dict(id=100253, level=3, extra=conf + '<field name="dest_ip">x</field>'), True),
                              # review: a catch-all value or an extra element turns a leaf into a hiding rule
                              (dict(id=100254, level=3, extra='<field name="alert.metadata.confidence">.</field>'),
                               True),
                              (dict(id=100255, level=3, extra=conf + "<options>no_log</options>"), True),
                              (dict(id=100256, level=3, extra=conf.replace("<field ", '<field type="pcre2" ')), True)):
            p = pathlib.Path(tempfile.mkdtemp()) / "ladder.xml"
            p.write_text(f'<group name="x,">{leaf.format(**rule)}</group>')
            _, findings = lint.lint([str(p)], (100200, 100299))
            with self.subTest(rule=rule):
                self.assertEqual(any("must pin alert.signature_id" in f for f in findings), flagged, findings)

    def test_alternation_must_be_grouped(self):
        self.assertTrue(lint.top_level_alternation(r"^10\.10\.0\.10|10\.10\.0\.11$"))  # also matches 10.10.0.100
        for ok in (r"^(?:10\.10\.0\.10|10\.10\.0\.11)$", r"^a[|]b$", r"^a\|b$", r"^2025701$"):
            self.assertFalse(lint.top_level_alternation(ok), ok)


if __name__ == "__main__":
    unittest.main()
