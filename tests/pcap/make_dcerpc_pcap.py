"""Synthetic DCE/RPC (DRSUAPI over TCP) pcap for the DCSync signature. Stdlib only.
Usage: make_dcerpc_pcap.py out.pcap
Sessions (one TCP session each, lab addresses):
  1. workstation 10.10.100.21 -> DC 10.10.0.10, opnum 3 (DRSGetNCChanges)  -> must alert
  2. workstation 10.10.100.21 -> DC 10.10.0.10, opnum 12 (DRSCrackNames)   -> must NOT alert
  3. DC 10.10.0.11 -> DC 10.10.0.10, opnum 3 (normal replication)          -> must NOT alert"""
import struct
import sys
import uuid

NDR = ("8a885d04-1ceb-11c9-9fe8-08002b104860", 2)
DRSUAPI = ("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4)
RPC_PORT = 49678
SESSIONS = [("10.10.100.21", "10.10.0.10", 50001, 3),
            ("10.10.100.21", "10.10.0.10", 50002, 12),
            ("10.10.0.11", "10.10.0.10", 50003, 3)]


def ip2b(ip):
    return bytes(int(x) for x in ip.split("."))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, ip2b(src), ip2b(dst))
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + iph + tcp


def hdr(ptype, body, call_id=1):
    # version 5.0, flags first+last frag, little-endian data representation
    return struct.pack("<BBBB4sHHI", 5, 0, ptype, 0x03, b"\x10\0\0\0", 16 + len(body), 0, call_id) + body


def syntax(s):
    return uuid.UUID(s[0]).bytes_le + struct.pack("<HH", s[1], 0)


def bind():
    return hdr(11, struct.pack("<HHIB3x", 4280, 4280, 0, 1) + struct.pack("<HBx", 0, 1) + syntax(DRSUAPI) + syntax(NDR))


def bind_ack():
    sec = b"49678\0"
    body = struct.pack("<HHIH", 4280, 4280, 0x1234, len(sec)) + sec
    body += b"\0" * ((4 - (len(body) % 4)) % 4)
    body += struct.pack("<B3xHH", 1, 0, 0) + syntax(NDR)
    return hdr(12, body)


def request(opnum):
    stub = b"\0" * 32
    return hdr(0, struct.pack("<IHH", len(stub), 0, opnum) + stub, call_id=2)


def session(src, dst, sport, opnum):
    c, s = 1000, 5000
    out = [packet(src, dst, sport, RPC_PORT, c, 0, 0x02),
           packet(dst, src, RPC_PORT, sport, s, c + 1, 0x12),
           packet(src, dst, sport, RPC_PORT, c + 1, s + 1, 0x10)]
    c += 1
    s += 1
    for frm, data in (("c", bind()), ("s", bind_ack()), ("c", request(opnum))):
        if frm == "c":
            out.append(packet(src, dst, sport, RPC_PORT, c, s, 0x18, data))
            c += len(data)
            out.append(packet(dst, src, RPC_PORT, sport, s, c, 0x10))
        else:
            out.append(packet(dst, src, RPC_PORT, sport, s, c, 0x18, data))
            s += len(data)
            out.append(packet(src, dst, sport, RPC_PORT, c, s, 0x10))
    out += [packet(src, dst, sport, RPC_PORT, c, s, 0x11),
            packet(dst, src, RPC_PORT, sport, s, c + 1, 0x11),
            packet(src, dst, sport, RPC_PORT, c + 1, s + 1, 0x10)]
    return out


def build():
    pkts = [p for args in SESSIONS for p in session(*args)]
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, p in enumerate(pkts):
        data += struct.pack("<IIII", 1767600000 + i, 0, len(p), len(p)) + p
    return data


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as f:
        f.write(build())
