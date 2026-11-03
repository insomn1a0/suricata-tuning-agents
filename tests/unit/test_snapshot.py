import datetime
import gzip
import json
import pathlib
import tempfile
import unittest

from .helpers import load

snap = load("tools/sensor_snapshot.py", "sensor_snapshot")
gen = load("examples/lab/make_sample_eve.py", "make_sample_eve")
TZ = datetime.timezone(datetime.timedelta(hours=1))


def alert(ts, sid=2025701, sev="Minor", conf="High", src="10.10.100.21", dst="10.10.20.15", port=445):
    meta = {}
    if sev:
        meta["signature_severity"] = [sev]
    if conf:
        meta["confidence"] = [conf]
    return {"timestamp": ts, "flow_id": 1, "event_type": "alert", "src_ip": src, "dest_ip": dst,
            "dest_port": port, "app_proto": "smb",
            "alert": {"signature_id": sid, "signature": "x", "metadata": meta}}


class LadderTest(unittest.TestCase):
    def test_mirrors_xml_ladder(self):
        cases = {("Critical", "High"): ("100202", 13), ("Critical", "Medium"): ("100201", 11),
                 ("Critical", "-"): ("100200", 10), ("Major", "High"): ("100205", 9),
                 ("Major", "Medium"): ("100204", 8), ("Major", "Low"): ("100203", 7),
                 ("Minor", "High"): ("100206", 6), ("Minor", "Medium"): ("86601", 3),
                 ("-", "-"): ("86601", 3)}
        for (sev, conf), want in cases.items():
            self.assertEqual(snap.predicted(sev, conf), want, (sev, conf))


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())

    def write(self, name, events, garbage=False, gz=False):
        lines = [json.dumps(e) for e in events] + (["not json", '{"event_type":"alert"}'] if garbage else [])
        data = ("\n".join(lines) + "\n").encode()
        p = self.tmp / name
        if gz:
            with gzip.open(p, "wb") as f:
                f.write(data)
        else:
            p.write_bytes(data)
        return str(p)

    def test_window_garbage_gzip_and_worktime(self):
        now = datetime.datetime(2026, 1, 12, tzinfo=TZ)
        f1 = self.write("eve.json", [
            alert("2026-01-05T10:00:00.000000+0100"),                  # Monday work hours
            alert("2026-01-10T10:00:00.000000+0100"),                  # Saturday
            alert("2025-12-01T10:00:00.000000+0100"),                  # outside 7 days
            alert("2026-01-06T03:00:00.000000+0100", sid=9, conf=None),  # hidden, night
        ], garbage=True)
        f2 = self.write("eve.json.1.gz", [alert("2026-01-07T09:30:00.000000+0100", dst="10.10.0.10")], gz=True)
        doc = snap.build([f1, f2], 7, now, (8, 19), tz=TZ)
        self.assertEqual(doc["alerts"], 4)
        self.assertEqual(doc["skipped_lines"], 2)
        self.assertEqual(doc["visible"], 3)
        s = {x["sid"]: x for x in doc["sids"]}
        self.assertEqual(s[2025701]["count"], 3)
        self.assertEqual(s[2025701]["dst_distinct"], 2)
        self.assertEqual(s[2025701]["worktime_share"], round(2 / 3, 2))
        self.assertEqual(s[9]["predicted_level"], 3)
        self.assertEqual(s[2025701]["top_pairs"][0], ("10.10.100.21->10.10.20.15:445", 2))

    def test_demo_week1_totals(self):
        gen.main(str(self.tmp / "demo"))
        now = datetime.datetime(2026, 1, 12, tzinfo=TZ)
        doc = snap.build([str(self.tmp / "demo/week1/eve.json")], 7, now, (8, 19), tz=TZ)
        s = {x["sid"]: x for x in doc["sids"]}
        self.assertEqual(set(s), {2025701, 2025709, 9900001, 9900002, 9900003})
        self.assertEqual(s[9900001]["count"], 840)
        self.assertEqual(s[2025701]["top_dst"][0][0], "10.10.20.15")
        self.assertNotIn(9100001, s)


if __name__ == "__main__":
    unittest.main()
