"""README metrics come from the rule model, not from hand-typed numbers; ignore windows follow event time."""
import contextlib
import io
import unittest

from .helpers import load

try:
    metrics = load("tools/metrics.py", "metrics")
except ModuleNotFoundError as e:  # PyYAML missing: `make venv`
    raise unittest.SkipTest(f"metrics needs {e.name}") from e
render = metrics.render
META = {"signature_severity": ["Minor"], "confidence": ["High"]}


def ev(t, dst, src="10.10.100.21", sid=2025701, port=445):
    return {"timestamp": f"2026-01-05T{t}:00.000000+0100", "src_ip": src, "dest_ip": dst, "src_port": 50000,
            "dest_port": port, "proto": "TCP", "alert": {"signature_id": sid, "signature": "x", "metadata": META}}


class Model(unittest.TestCase):
    def setUp(self):
        self.intents = render.load_intents(render.INTENTS, 6, (100200, 100299))

    def test_lower_enrich_window_and_attack(self):
        events = [ev("08:00", "10.10.20.15"),                       # distribution share: lowered
                  ev("08:00", "10.10.0.10"), ev("08:30", "10.10.0.10"),  # DC: first visible, repeat in window hidden
                  ev("10:30", "10.10.0.10"),                        # window over: visible again
                  ev("08:31", "10.10.0.11"),                        # the other DC has its own window
                  ev("14:00", "10.10.30.40", src="10.10.100.77")]   # admin share: stays visible
        got = [(e["timestamp"][11:16], e["dest_ip"], before, after, rule)
               for e, before, after, rule in metrics.classify(events, self.intents, 6)]
        self.assertEqual(got, [("08:00", "10.10.20.15", True, False, "100220"),
                               ("08:00", "10.10.0.10", True, True, "100221"),
                               ("08:30", "10.10.0.10", True, False, "100221"),
                               ("08:31", "10.10.0.11", True, True, "100222"),
                               ("10:30", "10.10.0.10", True, True, "100221"),
                               ("14:00", "10.10.30.40", True, True, "100206")])

    def test_readme_block_is_current(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(metrics.main(["--check"]), 0, "run `make metrics`")


if __name__ == "__main__":
    unittest.main()
