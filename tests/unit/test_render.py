"""Intents -> backends: schema and semantic checks refuse unsafe intents, adapters render deterministically,
generated negatives cover the PLAYBOOK traps. The engine check is `make test-logtest` on the generated files."""
import copy
import json
import unittest

from .helpers import ROOT, load

try:
    render = load("tools/render.py", "render")
except ModuleNotFoundError as e:  # PyYAML missing: `make venv`
    raise unittest.SkipTest(f"render needs {e.name}")

SCHEMA = json.loads((ROOT / "tuning/schema.json").read_text())
BASE = {
    "id": "lab-lower", "card": "examples/cards/2025701.md", "action": "lower", "sids": [2025701],
    "signature": "ET INFO test", "routes": [{"dst": "10.10.20.15", "dst_port": 445}], "level": 3,
    "description": "test $(dest_ip)", "rationale": "r", "risk": "r", "compensating_control": "c",
    "wazuh": {"parent": 100206, "rule_ids": [100250]},
}


def problems(**changes):
    intent = copy.deepcopy(BASE)
    for k, v in changes.items():
        if v is None:
            intent.pop(k)
        else:
            intent[k] = v
    return render.validate(intent, SCHEMA) or render.check_semantics(intent, 6)


class Checks(unittest.TestCase):
    def test_base_is_valid(self):
        self.assertEqual(problems(), [])

    def test_schema_rejects(self):
        self.assertTrue(problems(action="hide"))
        self.assertTrue(problems(routes=[{"dst": "10.10.20.0/24"}]))      # no subnets: an address is exact
        self.assertTrue(problems(routes=[{"dest": "10.10.20.15"}]))       # typo in a field name
        self.assertTrue(problems(sids=[]))
        self.assertTrue(problems(rationale=None))

    def test_semantics_reject(self):
        self.assertTrue(problems(level=6))                                   # lower must hide
        self.assertTrue(problems(routes=[{"dst_port": 445}]))                # lower by port alone
        self.assertTrue(problems(routes=[{"dst": "10.10.20.15"}, {"dst": "10.10.0.10"}]))  # 2 routes, 1 rule id
        self.assertTrue(problems(description="from 10.10.20.15"))
        self.assertTrue(problems(action="enrich", level=3))                  # enrich must stay visible

    def test_suppress_refuses_what_suricata_cannot_pin(self):
        sup = dict(action="suppress", wazuh=None, level=None, description=None)
        self.assertEqual(problems(routes=[{"dst": "10.10.20.15"}], **sup), [])
        self.assertTrue(problems(routes=[{"dst": "10.10.20.15", "dst_port": 445}], **sup))
        self.assertTrue(problems(routes=[{"src": "10.10.100.21", "dst": "10.10.20.15"}], **sup))

    def test_disable_is_global(self):
        dis = dict(action="disable", wazuh=None, level=None, description=None)
        self.assertEqual(problems(routes=None, **dis), [])
        self.assertTrue(problems(**dis))


class Rendering(unittest.TestCase):
    def test_union_of_routes_is_one_rule_per_route(self):
        intent = dict(BASE, routes=[{"src": "10.10.100.21", "dst": "10.10.20.15"},
                                    {"src": "10.10.100.22", "dst": "10.10.20.16"}],
                      wazuh={"parent": 100206, "rule_ids": [100250, 100251]})
        xml = render.render_wazuh4([intent])
        self.assertEqual(xml.count("<rule "), 2)
        self.assertNotIn("10\\.10\\.100\\.21|", xml)  # never src=(A|B), dst=(X|Y)
        notes = [n for n, _, _ in render.negatives(intent)]
        self.assertIn("crossed: route 1 with dst of route 2", notes)
        self.assertIn("crossed: route 2 with src of route 1", notes)

    def test_alternation_is_grouped(self):
        self.assertEqual(render.regex(["10.10.0.10", "10.10.0.11"], "dst"), r"^(?:10\.10\.0\.10|10\.10\.0\.11)$")

    def test_negatives_never_match_their_own_route(self):
        for intent in render.load_intents():
            if intent["action"] in render.SIEM_ACTIONS:
                for note, sid, ctx in render.negatives(intent):
                    hit = sid in intent["sids"] and any(render.route_matches(r, ctx) for r in intent["routes"])
                    self.assertFalse(hit, (intent["id"], note))

    def test_suricata_threshold(self):
        intent = dict(BASE, action="suppress", routes=[{"src": ["10.10.0.53", "10.10.0.54"]}])
        out = render.render_suricata([intent, dict(BASE, id="lab-off", action="disable", sids=[2200074])])
        self.assertIn("suppress gen_id 1, sig_id 2025701, track by_src, ip 10.10.0.53,10.10.0.54", out["threshold.config"])
        self.assertIn("1:2200074", out["disable.conf"])

    def test_wazuh5_is_an_explicit_stub(self):
        with self.assertRaises(NotImplementedError):
            render.render_wazuh5([BASE])

    def test_generated_files_are_current(self):
        self.assertEqual(render.main(["--check"]), 0, "run `make render`")


if __name__ == "__main__":
    unittest.main()
