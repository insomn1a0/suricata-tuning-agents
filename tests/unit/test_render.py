"""Intents -> backends: schema and semantic checks refuse unsafe intents, adapters render deterministically,
generated negatives cover the PLAYBOOK traps, the sibling model matches the engine. Rows marked `review`
come from the adversarial review of stage 3. The engine check is `make test-logtest` on the generated files."""
import copy
import json
import pathlib
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET

from .helpers import ROOT, load

try:
    render = load("tools/render.py", "render")
except ModuleNotFoundError as e:  # PyYAML missing: `make venv`
    raise unittest.SkipTest(f"render needs {e.name}")

SCHEMA = json.loads((ROOT / "tuning/schema.json").read_text())
RULES = render.ladder()
BASE = {
    "id": "lab-lower", "card": "examples/cards/2025701.md", "status": "approved", "action": "lower",
    "sids": [2025701], "signature": "ET INFO test", "metadata": {"signature_severity": "Minor", "confidence": "High"},
    "routes": [{"dst": "10.10.20.15", "dst_port": 445}], "level": 3,
    "description": "test $(dest_ip)", "rationale": "r", "risk": "r", "compensating_control": "c",
    "wazuh": {"parent": 100206, "rule_ids": [100250]},
}
SURICATA_SIDE = {"wazuh": None, "level": None, "description": None, "metadata": None}


def intent(**changes):
    out = copy.deepcopy(BASE)
    for k, v in changes.items():
        if v is None:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def problems(**changes):
    i = intent(**changes)
    return render.validate(i, SCHEMA) or render.check_semantics(i, 6, RULES)


class Checks(unittest.TestCase):
    def test_base_is_valid(self):
        self.assertEqual(problems(), [])

    def test_schema_rejects(self):
        self.assertTrue(problems(action="hide"))
        self.assertTrue(problems(routes=[{"dst": "10.10.20.0/24", "dst_port": 445}]))  # no subnets
        self.assertTrue(problems(routes=[{"dest": "10.10.20.15"}]))                     # typo in a field name
        self.assertTrue(problems(sids=[]))
        self.assertTrue(problems(rationale=None))
        self.assertTrue(problems(status=None))   # review 6: a draft without status must not go live

    def test_semantics_reject(self):
        self.assertTrue(problems(level=6))                                               # lower must hide
        self.assertTrue(problems(routes=[{"dst_port": 445}]))                            # by port alone
        self.assertTrue(problems(routes=[{"dst": "10.10.20.15", "dst_port": 445},
                                         {"dst": "10.10.0.10", "dst_port": 445}]))       # 2 routes, 1 rule id
        self.assertTrue(problems(description="from 10.10.20.15"))
        self.assertTrue(problems(action="enrich", level=3))                              # enrich must stay visible

    def test_review_findings(self):
        self.assertTrue(problems(level=0))                                   # 1: level 0 beats every sibling
        self.assertTrue(problems(wazuh={"parent": 100203, "rule_ids": [100250]}))   # 3: non-leaf parent
        self.assertTrue(problems(wazuh={"parent": 86601, "rule_ids": [100250]}))    # 3: stock parent
        self.assertTrue(problems(metadata={"signature_severity": "Major", "confidence": "High"}))  # 3: lands on 100205
        self.assertTrue(problems(routes=[{"src": "10.10.100.21"}]))          # 4: one client to every server
        self.assertTrue(problems(routes=[{"dst": "10.10.20.15"}]))           # 4: every port
        many = [f"10.10.20.{n}" for n in range(1, 10)]
        self.assertTrue(problems(routes=[{"dst": many, "dst_port": 445}]))   # 4: 9 addresses
        self.assertTrue(problems(action="raise", level=12, rate_limit={"ignore_seconds": 60}))  # 7
        self.assertTrue(problems(action="enrich", level=6, rate_limit={"ignore_seconds": 60},
                                 routes=[{"dst": ["10.10.0.10", "10.10.0.11"], "dst_port": 445}]))  # 7: shared window
        self.assertTrue(problems(routes=[{"dst": "010.010.020.015", "dst_port": 445}]))  # 8
        self.assertTrue(problems(routes=[{"dst": "999.1.1.1", "dst_port": 445}]))        # 8

    def test_suppress_refuses_what_suricata_cannot_pin(self):
        self.assertEqual(problems(action="suppress", routes=[{"dst": "10.10.20.15"}], **SURICATA_SIDE), [])
        self.assertTrue(problems(action="suppress", routes=[{"dst": "10.10.20.15", "dst_port": 445}], **SURICATA_SIDE))
        self.assertTrue(problems(action="suppress", routes=[{"src": "10.10.100.21", "dst": "10.10.20.15"}],
                                 **SURICATA_SIDE))
        self.assertTrue(problems(action="suppress", routes=[{"dst": "10.10.20.15"}], compensating_control="none",
                                 **SURICATA_SIDE))  # 5: data lost even from archives needs a named control

    def test_disable_is_global(self):
        self.assertEqual(problems(action="disable", routes=None, **SURICATA_SIDE), [])
        self.assertTrue(problems(action="disable", **SURICATA_SIDE))


class Registry(unittest.TestCase):
    def load_with(self, *extra):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(render.INTENTS, pathlib.Path(d) / "i")
            for x in extra:
                (pathlib.Path(d) / "i" / f"{x['id']}.yaml").write_text(json.dumps(x))
            return render.load_intents(pathlib.Path(d) / "i", 6, (100200, 100299))

    def test_repo_intents_load(self):
        self.assertEqual(len(self.load_with()), 2)

    def test_ids_and_overlaps(self):
        for bad, why in ((dict(wazuh={"parent": 100206, "rule_ids": [100250]}), "not in the registry"),
                         (dict(wazuh={"parent": 100206, "rule_ids": [100206]}), "ladder or reserved"),
                         (dict(wazuh={"parent": 100206, "rule_ids": [100210]}), "ladder or reserved"),
                         (dict(wazuh={"parent": 100206, "rule_ids": [100220]}), "already used")):
            with self.subTest(why=why), self.assertRaises(render.IntentError) as e:
                self.load_with(intent(id="lab-x", **bad))
            self.assertIn(why, str(e.exception))

    def test_overlapping_routes_are_refused(self):
        # review 1: a raise for a host and the files01 lower can match the same event; the engine picks by level.
        raise_ = intent(id="lab-raise", action="raise", level=12, routes=[{"src": "10.10.100.66", "dst": "10.10.20.15",
                                                                           "dst_port": 445}])
        rows = [(raise_, raise_["routes"][0], 100250)]
        lower = render.load_intents(render.INTENTS, 6, (100200, 100299))[0]
        rows.append((lower, lower["routes"][0], 100220))
        self.assertTrue(render.routes_overlap(rows[0][1], rows[1][1]))
        self.assertTrue(render.check_overlaps([lower, dict(raise_, wazuh={"parent": 100206, "rule_ids": [100250]})]))


class EngineModel(unittest.TestCase):
    def test_sibling_order_is_level_not_file_order(self):
        # Observed on Wazuh 4.14.9: level 0 first, then higher levels, file order only for ties.
        order = sorted([(3, 0), (4, 1), (0, 2), (9, 3), (1, 4)], key=lambda lv: render.engine_key(*lv))
        self.assertEqual([lv for lv, _ in order], [0, 9, 4, 3, 1])
        self.assertLess(render.engine_key(5, 1), render.engine_key(5, 2))

    def test_ladder_select(self):
        self.assertEqual(render.ladder_select(RULES, {"signature_severity": "Minor", "confidence": "High"}), "100206")
        self.assertEqual(render.ladder_select(RULES, {"signature_severity": "Critical", "confidence": "High"}), "100202")
        self.assertEqual(render.ladder_select(RULES, {"signature_severity": "Minor", "confidence": "Medium"}), "86601")


class Rendering(unittest.TestCase):
    def test_union_of_routes_is_one_rule_per_route(self):
        i = intent(routes=[{"src": "10.10.100.21", "dst": "10.10.20.15", "dst_port": 445},
                           {"src": "10.10.100.22", "dst": "10.10.20.16", "dst_port": 445}],
                   wazuh={"parent": 100206, "rule_ids": [100250, 100251]})
        xml = render.render_wazuh4([i])
        self.assertEqual(xml.count("<rule "), 2)
        self.assertNotIn("10\\.10\\.100\\.21|", xml)  # never src=(A|B), dst=(X|Y)
        notes = [n for n, _, _ in render.negatives(i)]
        self.assertIn("crossed: route 1 with dst of route 2", notes)
        self.assertIn("crossed: route 2 with src of route 1", notes)

    def test_text_cannot_inject_rules(self):
        # review 2: rationale closed the comment and added a level-0 rule that lint accepted.
        payload = ('ok --> <rule id="100298" level="0"><if_sid>100202</if_sid><description>x</description></rule> <!--')
        xml = render.render_wazuh4([intent(rationale=payload, description="a & b <c>", card="x -- y")])
        ids = [r.get("id") for r in ET.fromstring(f"<root>{xml}</root>").iter("rule")]
        self.assertEqual(ids, ["100250"])
        self.assertIn("a &amp; b &lt;c&gt;", xml)

    def test_alternation_is_grouped(self):
        self.assertEqual(render.regex(["10.10.0.10", "10.10.0.11"], "dst"), r"^(?:10\.10\.0\.10|10\.10\.0\.11)$")

    def test_tests_use_the_intents_metadata(self):
        # review 3: events used to copy the parent's metadata and reached it by construction.
        files = render.render_tests([BASE], [BASE], 6)
        first = json.loads(files["intent-lab-lower.txt"].splitlines()[1])
        self.assertEqual(first["alert"]["metadata"], {"signature_severity": ["Minor"], "confidence": ["High"]})

    def test_negatives_include_lookalike_sids_and_never_match_their_own_route(self):
        for i in render.load_intents(render.INTENTS, 6, (100200, 100299)):
            if i["action"] in render.SIEM_ACTIONS:
                cases = render.negatives(i)
                self.assertTrue(any(s == int(f"{i['sids'][0]}0") for _, s, _ in cases))
                for note, sid, ctx in cases:
                    hit = sid in i["sids"] and any(render.route_matches(r, ctx) for r in i["routes"])
                    self.assertFalse(hit, (i["id"], note))

    def test_suricata_threshold(self):
        sup = intent(action="suppress", routes=[{"src": ["10.10.0.53", "10.10.0.54"]}], **SURICATA_SIDE)
        out = render.render_suricata([sup, intent(id="lab-off", action="disable", sids=[2200074], **SURICATA_SIDE)])
        self.assertIn("suppress gen_id 1, sig_id 2025701, track by_src, ip 10.10.0.53,10.10.0.54", out["threshold.config"])
        self.assertIn("1:2200074", out["disable.conf"])

    def test_wazuh5_is_an_explicit_stub(self):
        with self.assertRaises(NotImplementedError):
            render.render_wazuh5([BASE])

    def test_generated_files_are_current(self):
        self.assertEqual(render.main(["--check"]), 0, "run `make render`")


if __name__ == "__main__":
    unittest.main()
