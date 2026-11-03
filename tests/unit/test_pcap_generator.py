"""The synthetic pcap is well-formed: valid pcap header, IPv4/TCP checksums, expected DCE/RPC opnums.
The native Suricata run is `make test-pcap`."""
import struct
import unittest

from .helpers import load

gen = load("tests/pcap/make_dcerpc_pcap.py", "make_dcerpc_pcap")


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


if __name__ == "__main__":
    unittest.main()
