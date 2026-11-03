"""Minimal stdlib pcap builder for synthetic lab traffic: Ethernet/IPv4 with TCP sessions (handshake, data
both ways, FIN) and UDP datagrams. Deterministic: same input, same bytes. No third-party captures."""
import struct

ETH = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"


def ip2b(ip):
    return bytes(int(x) for x in ip.split("."))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4(src, dst, proto, payload):
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0x4000, 64, proto, 0, ip2b(src), ip2b(dst))
    return ETH + iph[:10] + struct.pack("!H", csum(iph)) + iph[12:] + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, 6, len(seg))
    seg = seg[:16] + struct.pack("!H", csum(pseudo + seg)) + seg[18:]
    return ipv4(src, dst, 6, seg)


def udp(src, dst, sport, dport, payload):
    dgram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, 17, len(dgram))
    dgram = dgram[:6] + struct.pack("!H", csum(pseudo + dgram) or 0xFFFF) + dgram[8:]
    return ipv4(src, dst, 17, dgram)


def tcp_session(src, dst, sport, dport, exchanges):
    """exchanges: [('c'|'s', bytes)] in order. Returns the packets of one complete TCP session."""
    c, s = 1000, 5000
    out = [tcp(src, dst, sport, dport, c, 0, 0x02), tcp(dst, src, dport, sport, s, c + 1, 0x12),
           tcp(src, dst, sport, dport, c + 1, s + 1, 0x10)]
    c, s = c + 1, s + 1
    for side, data in exchanges:
        if side == "c":
            out += [tcp(src, dst, sport, dport, c, s, 0x18, data), tcp(dst, src, dport, sport, s, c + len(data), 0x10)]
            c += len(data)
        else:
            out += [tcp(dst, src, dport, sport, s, c, 0x18, data), tcp(src, dst, sport, dport, c, s + len(data), 0x10)]
            s += len(data)
    return out + [tcp(src, dst, sport, dport, c, s, 0x11), tcp(dst, src, dport, sport, s, c + 1, 0x11),
                  tcp(src, dst, sport, dport, c + 1, s + 1, 0x10)]


def pcap(packets, start=1767600000, step=1):
    """packets: [bytes] or [(seconds_offset, bytes)]. Classic pcap, microsecond timestamps, Ethernet."""
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, p in enumerate(packets):
        off, p = p if isinstance(p, tuple) else (i * step, p)
        data += struct.pack("<IIII", start + int(off), int((off % 1) * 1e6), len(p), len(p)) + p
    return data
