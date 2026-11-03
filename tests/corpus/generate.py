"""Generate the synthetic regression corpus: tests/corpus/<case>/input.pcap. Stdlib only, deterministic,
lab addresses only. Each case directory also holds test.yaml (Suricata-level checks, suricata-verify syntax)
and siem.yaml (what must be visible to analysts after all tuning intents).
Usage: generate.py [--check]      --check: fail if a committed pcap differs from what this script builds"""
import pathlib
import struct
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from pcaplib import pcap, tcp_session, udp  # noqa: E402

CORPUS = pathlib.Path(__file__).resolve().parent


# ---------- DCE/RPC (DRSUAPI) for DCSync ----------

NDR = ("8a885d04-1ceb-11c9-9fe8-08002b104860", 2)
DRSUAPI = ("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4)


def _rpc(ptype, body, call_id=1):
    return struct.pack("<BBBB4sHHI", 5, 0, ptype, 0x03, b"\x10\0\0\0", 16 + len(body), 0, call_id) + body


def _syntax(s):
    return uuid.UUID(s[0]).bytes_le + struct.pack("<HH", s[1], 0)


def drsuapi_session(src, dst, sport, opnum):
    bind = _rpc(11, struct.pack("<HHIB3x", 4280, 4280, 0, 1) + struct.pack("<HBx", 0, 1) + _syntax(DRSUAPI)
                + _syntax(NDR))
    sec = b"49678\0"
    body = struct.pack("<HHIH", 4280, 4280, 0x1234, len(sec)) + sec
    body += b"\0" * ((4 - (len(body) % 4)) % 4) + struct.pack("<B3xHH", 1, 0, 0) + _syntax(NDR)
    ack = _rpc(12, body)
    stub = b"\0" * 32
    req = _rpc(0, struct.pack("<IHH", len(stub), 0, opnum) + stub, call_id=2)
    return tcp_session(src, dst, sport, 49678, [("c", bind), ("s", ack), ("c", req)])


def dcsync():
    """1. workstation -> DC opnum 3 (GetNCChanges): attack. 2. same pair opnum 12 (CrackNames): benign.
    3. DC -> DC opnum 3: normal replication."""
    return (drsuapi_session("10.10.100.21", "10.10.0.10", 50001, 3)
            + drsuapi_session("10.10.100.21", "10.10.0.10", 50002, 12)
            + drsuapi_session("10.10.0.11", "10.10.0.10", 50003, 3))


# ---------- SMB2 CREATE ----------

def smb2_create(name, message_id=1):
    fname = name.encode("utf-16-le")
    # MS-SMB2 "SMB2 Packet Header - SYNC": 64 bytes, Command (offset 12) = 5 CREATE
    hdr = b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ16s", 64, 1, 0, 5, 1, 0, 0, message_id, 0, 1, 0x10, b"\0" * 16)
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x00120089, 0x80, 0x07, 1, 0x40, 64 + 56, len(fname), 0, 0)
    msg = hdr + body + fname
    return struct.pack(">I", len(msg)) + msg


def smb_exe():
    """1. workstation -> other workstation's C$: exe copied for remote execution (T1570) - attack.
    2. workstation -> distribution share files01: installer read - noise, lowered.
    3. workstation -> DC SYSVOL: logon script exe - enriched, visible once per hour."""
    return (tcp_session("10.10.100.77", "10.10.30.40", 51001, 445, [("c", smb2_create(r"Windows\Temp\svcupd.exe"))])
            + tcp_session("10.10.100.21", "10.10.20.15", 51002, 445, [("c", smb2_create(r"Deploy\installer.exe"))])
            + tcp_session("10.10.100.22", "10.10.0.10", 51003, 445,
                          [("c", smb2_create(r"lab.local\scripts\logon.exe"))]))


# ---------- HTTP beacon ----------

def beacon():
    """Six identical check-ins from one workstation to 203.0.113.50 every 60 s, plus one ordinary request
    from another workstation to the same host (must not alert)."""
    req = (b"GET /cdn/check HTTP/1.1\r\nHost: update-check.example\r\nUser-Agent: Mozilla/5.0\r\n"
           b"Accept: */*\r\n\r\n")
    resp = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    pkts = []
    for n in range(6):
        pkts += [(n * 60 + k * 0.01, p) for k, p in enumerate(
            tcp_session("10.10.100.23", "203.0.113.50", 52000 + n, 80, [("c", req), ("s", resp)]))]
    pkts += [(400 + k * 0.01, p) for k, p in enumerate(
        tcp_session("10.10.100.25", "203.0.113.50", 52100, 80, [("c", req), ("s", resp)]))]
    return pkts


# ---------- DNS tunnelling-like queries ----------

def dns_query(qid, name):
    q = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 16, 1)


def dns_tunnel():
    """Five TXT queries with 52-character encoded labels from one workstation via the internal resolver,
    plus one normal query (must not alert)."""
    chunks = ["mzxw6ytboi2dmnzrgq3tgojshezdcnbqge2tmnbsgm4dsmjvha4d", "nbswy3dpeb3w64tmmqqgg2dvnzvsa2lomfwgk2le",
              "orsxg5bamjxw63lfnzxgsidvobsgczlfmfzgk2le", "mfzwizdgmfzwizdgmfzwizdgmfzwizdgmfzwizdgmfzwi",
              "nfxgg3tgmfzwizdgnrzxa3dfnzsgk43uojxw4z3e"]
    pkts = [udp("10.10.100.24", "10.10.0.53", 53000 + i, 53, dns_query(0x1000 + i, f"{c}.t.exfil-lab.example"))
            for i, c in enumerate(chunks)]
    return pkts + [udp("10.10.100.25", "10.10.0.53", 53100, 53, dns_query(0x2000, "www.example.com"))]


CASES = {"dcsync": dcsync, "smb-exe": smb_exe, "http-beacon": beacon, "dns-tunnel": dns_tunnel}


def main(argv):
    stale = []
    for name, build in CASES.items():
        data = pcap(build())
        path = CORPUS / name / "input.pcap"
        if "--check" in argv:
            if not path.exists() or path.read_bytes() != data:
                stale.append(name)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    if "--check" in argv:
        print(f"corpus --check: {len(CASES)} cases, {len(stale)} stale {stale or ''}")
        return 1 if stale else 0
    print(f"corpus: {len(CASES)} pcaps written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
