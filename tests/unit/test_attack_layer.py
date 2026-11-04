"""The ATT&CK layer is generated from the repo and scores only what the repo backs."""
import contextlib
import io
import unittest

from .helpers import load

try:
    layer = load("tools/attack_layer.py", "attack_layer")
except ModuleNotFoundError as e:  # PyYAML missing: `make venv`
    raise unittest.SkipTest(f"attack layer needs {e.name}") from e


class AttackLayer(unittest.TestCase):
    def test_scores(self):
        scores = {t["techniqueID"]: t["score"] for t in layer.layer()["techniques"]}
        self.assertEqual(scores["T1003.006"], 3)  # local DCSync signature + corpus proof
        self.assertEqual(scores["T1570"], 2)      # corpus proof through the ET stand-in only
        self.assertTrue(all(s in (1, 2, 3) for s in scores.values()))

    def test_committed_layer_is_current(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(layer.main(["--check"]), 0, "run `make attack-layer`")


if __name__ == "__main__":
    unittest.main()
