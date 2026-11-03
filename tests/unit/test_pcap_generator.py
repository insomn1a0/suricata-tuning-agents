"""The synthetic pcap is well-formed: valid pcap header, IPv4/TCP checksums, expected DCE/RPC opnums;
cases.json points at sessions that exist, and the evaluator tells sessions apart.
The native Suricata run is `make test-pcap`."""
import json
import struct
import unittest

from .helpers import ROOT, load

gen = load("tests/pcap/make_dcerpc_pcap.py", "make_dcerpc_pcap")
runner = load("tools/pcap_test.py", "pcap_test")


def csum_ok(data):
    return gen.csum(data) == 0


class PcapTest(unittest.TestCase):
    def test_structure(self):
        data = gen.build()
        magic, major, minor, _, _, snap, link = struct.unpack("<IHHiIII", data[:24])
        self.assertEqual((magic, major, minor, link), (0xA1B2C3D4, 2, 4, 1))
        off, opnums, n = 24, [], 0
        while off < len(data):
            _, _, incl, orig = struct.unpack("<IIII", data[off:off + 16])
            pkt = data[off + 16:off + 16 + incl]
            off += 16 + incl
            n += 1
            self.assertEqual(incl, orig)
            ip = pkt[14:34]
            self.assertTrue(csum_ok(ip), "IPv4 header checksum")
            total = struct.unpack("!H", ip[2:4])[0]
            tcp = pkt[34:14 + total]
            pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
            self.assertTrue(csum_ok(pseudo + tcp), "TCP checksum")
            payload = tcp[20:]
            if len(payload) >= 24 and payload[0] == 5 and payload[2] == 0:  # DCE/RPC request
                opnums.append(struct.unpack("<H", payload[22:24])[0])
        self.assertEqual(opnums, [3, 12, 3])
        self.assertEqual(n, len(gen.SESSIONS) * 12)

    def test_cases_point_at_sessions(self):
        sessions = {(src, sport, dst) for src, dst, sport, _ in gen.SESSIONS}
        for case in json.loads((ROOT / "tests/pcap/cases.json").read_text())["cases"]:
            for e in case["expect"]:
                self.assertIn((e["src_ip"], e["src_port"], e["dest_ip"]), sessions, e)

    def test_evaluate_separates_sessions_on_same_ip_pair(self):
        # Regression: keyed by IPs only, an alert on the opnum 12 session (port 50002) passed as the opnum 3 one.
        case = {"expect": [{"sid": 1, "src_ip": "10.10.100.21", "src_port": 50001, "dest_ip": "10.10.0.10", "count": 1}]}
        alert = {"alert": {"signature_id": 1}, "src_ip": "10.10.100.21", "dest_ip": "10.10.0.10"}
        self.assertEqual(runner.evaluate([dict(alert, src_port=50001)], case), [])
        self.assertEqual(len(runner.evaluate([dict(alert, src_port=50002)], case)), 2)


if __name__ == "__main__":
    unittest.main()
