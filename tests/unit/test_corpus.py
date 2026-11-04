"""Regression corpus without engines: pcaps are current and well-formed, case files are consistent, the
evaluator logic holds, and every mutant passes all static checks (which is why the corpus exists).
The engine runs are `make test-pcap`, `make test-e2e` and `make test-e2e-mutant`."""
import pathlib
import struct
import unittest

from .helpers import ROOT, load

try:
    import yaml
    runner = load("tools/corpus_test.py", "corpus_test")
except ModuleNotFoundError as e:  # PyYAML missing: `make venv`
    raise unittest.SkipTest(f"corpus runner needs {e.name}") from e

gen = load("tests/corpus/generate.py", "corpus_generate")
lib = load("tests/corpus/pcaplib.py", "pcaplib")
CORPUS = ROOT / "tests" / "corpus"
CASES = sorted(d for d in CORPUS.iterdir() if (d / "test.yaml").exists())


def packets(data):
    off = 24
    while off < len(data):
        _, _, incl, orig = struct.unpack("<IIII", data[off:off + 16])
        yield data[off + 16:off + 16 + incl], incl, orig
        off += 16 + incl


class Pcaps(unittest.TestCase):
    def test_committed_pcaps_are_current(self):
        self.assertEqual(gen.main(["--check"]), 0, "run tests/corpus/generate.py")

    def test_well_formed(self):
        for case in CASES:
            data = (case / "input.pcap").read_bytes()
            self.assertEqual(struct.unpack("<IHHiIII", data[:24])[0::6], (0xA1B2C3D4, 1), case.name)
            for pkt, incl, orig in packets(data):
                self.assertEqual(incl, orig)
                ip = pkt[14:34]
                self.assertEqual(lib.csum(ip), 0, f"{case.name}: IPv4 header checksum")
                total, proto = struct.unpack("!H", ip[2:4])[0], ip[9]
                seg = pkt[34:14 + total]
                pseudo = ip[12:20] + struct.pack("!BBH", 0, proto, len(seg))
                self.assertEqual(lib.csum(pseudo + seg), 0, f"{case.name}: L4 checksum")

    def test_dcsync_opnums(self):
        opnums = []
        for pkt, _, _ in packets((CORPUS / "dcsync" / "input.pcap").read_bytes()):
            payload = pkt[54:]
            if len(payload) >= 24 and payload[0] == 5 and payload[2] == 0:  # DCE/RPC request
                opnums.append(struct.unpack("<H", payload[22:24])[0])
        self.assertEqual(opnums, [3, 12, 3])

    def test_only_lab_addresses_are_generated(self):
        for case in CASES:
            for pkt, _, _ in packets((case / "input.pcap").read_bytes()):
                for raw in (pkt[26:30], pkt[30:34]):
                    ip = ".".join(str(b) for b in raw)
                    self.assertTrue(ip.startswith("10.10.") or ip.startswith("203.0.113."), (case.name, ip))


class CaseFiles(unittest.TestCase):
    def test_every_case_has_checks_and_siem_expectations(self):
        self.assertGreaterEqual(len(CASES), 4)
        for case in CASES:
            spec = yaml.safe_load((case / "test.yaml").read_text())
            self.assertTrue(spec["checks"], case.name)
            siem = yaml.safe_load((case / "siem.yaml").read_text())
            for exp in siem["expect"]:
                self.assertIn("visible", exp)
                if "attack" in exp:
                    self.assertTrue(exp["visible"], f"{case.name}: an attack must be expected visible")
                    self.assertRegex(exp["attack"], r"^T\d{4}(\.\d{3})?$")


class Evaluator(unittest.TestCase):
    EVENTS = [{"event_type": "alert", "src_ip": "10.10.100.21", "src_port": 50001,
               "alert": {"signature_id": 9100001, "metadata": {"confidence": ["High"]}}},
              {"event_type": "alert", "src_ip": "10.10.100.21", "src_port": 50002,
               "alert": {"signature_id": 9100001, "metadata": {"confidence": ["High"]}}}]

    def test_dotted_and_list_matching(self):
        self.assertTrue(runner.matches(self.EVENTS[0], {"alert.signature_id": 9100001, "src_port": 50001}))
        self.assertTrue(runner.matches(self.EVENTS[0], {"alert.metadata.confidence": "High"}))
        self.assertFalse(runner.matches(self.EVENTS[0], {"alert.metadata.missing": 1}))

    def test_engine_checks_separate_sessions_on_same_ip_pair(self):
        # Regression from stage 1: keyed by IPs only, an alert on the wrong session passed.
        spec = {"checks": [{"filter": {"count": 1, "match": {"alert.signature_id": 9100001, "src_port": 50001}}},
                           {"filter": {"count": 0, "match": {"alert.signature_id": 9100001, "src_port": 50002}}}]}
        self.assertEqual(runner.check_engine(self.EVENTS[:1], spec), [])
        self.assertEqual(len(runner.check_engine(self.EVENTS[1:], spec)), 2)

    def test_siem_visibility(self):
        spec = {"expect": [{"name": "attack", "match": {"src_port": 50001}, "visible": True, "attack": "T1003.006"}]}
        visible = [{"id": "100202", "level": 13, "alert": True}]
        hidden = [{"id": "100229", "level": 3, "alert": False}]
        self.assertEqual(runner.check_siem(self.EVENTS[:1], visible, spec)[0], [])
        problems, summary = runner.check_siem(self.EVENTS[:1], hidden, spec)
        self.assertEqual(len(problems), 1)
        self.assertEqual((summary["attack_ok"], summary["attack_total"]), (0, 1))
        # an attack suppressed before the SIEM is lost too, not missing from the total
        problems, summary = runner.check_siem([], [], spec)
        self.assertEqual((len(problems), summary["attack_ok"], summary["attack_total"]), (1, 0, 1))


class EngineMetadata(unittest.TestCase):
    def test_declared_metadata_must_match_eve(self):
        intents = [{"sids": [2025701], "metadata": {"signature_severity": "Minor", "confidence": "High"}}]
        good = {"alert": {"signature_id": 2025701,
                          "metadata": {"signature_severity": ["Minor"], "confidence": ["High"]}}}
        bad = {"alert": {"signature_id": 2025701, "metadata": {"signature_severity": ["Minor"]}}}
        other = {"alert": {"signature_id": 1, "metadata": {}}}
        self.assertEqual(runner.metadata_problems([good, other], intents), [])
        self.assertEqual(len(runner.metadata_problems([bad, bad], intents)), 1)


class Mutants(unittest.TestCase):
    def test_mutants_pass_every_static_check(self):
        """If a static check caught them, they would not prove anything about the corpus."""
        import shutil
        import tempfile
        render = runner.render
        mutants = sorted((CORPUS / "mutants").glob("*.yaml"))
        self.assertGreaterEqual(len(mutants), 2)
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(render.INTENTS, pathlib.Path(d) / "i")
            for m in mutants:
                shutil.copy(m, pathlib.Path(d) / "i")
            ids = {i["id"] for i in render.load_intents(pathlib.Path(d) / "i")}
        self.assertTrue({m.stem for m in mutants} <= ids)


if __name__ == "__main__":
    unittest.main()
