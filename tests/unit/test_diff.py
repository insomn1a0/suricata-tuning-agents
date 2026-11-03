import datetime
import pathlib
import tempfile
import unittest

from .helpers import load

snap = load("tools/sensor_snapshot.py", "sensor_snapshot")
diff = load("tools/diff_snapshots.py", "diff_snapshots")
gen = load("examples/lab/make_sample_eve.py", "make_sample_eve")
TZ = datetime.timezone(datetime.timedelta(hours=1))


class DiffTest(unittest.TestCase):
    def test_demo_weeks(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        gen.main(str(tmp))
        w1 = snap.build([str(tmp / "week1/eve.json")], 7, datetime.datetime(2026, 1, 12, tzinfo=TZ), (8, 19), TZ)
        w2 = snap.build([str(tmp / "week2/eve.json")], 7, datetime.datetime(2026, 1, 19, tzinfo=TZ), (8, 19), TZ)
        r = diff.compare(w1, w2)
        self.assertEqual([s["sid"] for s in r["appeared"]], [9100001])
        self.assertEqual([s["sid"] for s in r["gone"]], [9900003])
        self.assertEqual([c["sid"] for c in r["changed"]], [9900002])
        self.assertIn("NEW SIDs (1)", diff.render(w1, w2, r))


if __name__ == "__main__":
    unittest.main()
