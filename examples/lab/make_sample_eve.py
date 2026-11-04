"""Generate two weeks of synthetic Suricata EVE alerts for the demo (deterministic, lab addresses).
Usage: make_sample_eve.py <out-dir>   -> <out-dir>/week1/eve.json, <out-dir>/week2/eve.json
SIDs 99000xx are fictional examples; 2025701/2025709 mimic well-known ET INFO SMB signatures;
9100001 is the local DCSync signature from suricata/rules/local.rules."""
import datetime
import json
import pathlib
import random
import sys

TZ = datetime.timezone(datetime.timedelta(hours=1))
CLIENTS = [f"10.10.100.{i}" for i in range(20, 80)]
SIGS = {
    2025701: ("ET INFO SMB2 NT Create AndX Request For an Executable File", "Potentially Bad Traffic",
              "Minor", "High", "smb"),
    2025709: ("ET INFO SMB2 NT Create AndX Request For a DLL File", "Potentially Bad Traffic", "Minor", "High", "smb"),
    9900001: ("EXAMPLE DNS Query to Advertising/Tracking Domain", "Misc activity", "Minor", "High", "dns"),
    9900002: ("EXAMPLE TLS SNI of Remote Administration Tool Relay", "Potentially Bad Traffic",
              "Major", "Medium", "tls"),
    9900003: ("EXAMPLE HTTP Basic Authorization over Cleartext", "Potential Corporate Privacy Violation",
              "Minor", "Medium", "http"),
    9100001: ("LOCAL Possible DCSync - DRSUAPI DRSGetNCChanges from non-DC", "Credential Theft",
              "Critical", "High", "dcerpc"),
}


def event(t, flow, src, dst, dport, sid):
    sig, cat, sev, conf, proto = SIGS[sid]
    meta = {"signature_severity": [sev], "confidence": [conf]}
    if sid == 9100001:
        meta["mitre_technique_id"] = ["T1003.006"]
    return {"timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%f") + t.strftime("%z"), "flow_id": flow,
            "in_iface": "eth1", "event_type": "alert", "src_ip": src, "src_port": 49152 + flow % 16000,
            "dest_ip": dst, "dest_port": dport, "proto": "UDP" if proto == "dns" else "TCP", "app_proto": proto,
            "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1, "signature": sig,
                      "category": cat, "severity": 1 if sev == "Critical" else 2 if sev == "Major" else 3,
                      "metadata": meta}}


def week(rng, start, second):
    out, flow = [], 1
    for d in range(7):
        day = start + datetime.timedelta(days=d)
        workday = day.weekday() < 5

        def at(h0, h1, day=day):
            return day + datetime.timedelta(seconds=rng.randrange(h0 * 3600, h1 * 3600))

        plan = [
            # (count, sid, src chooser, dst, port, hours)
            (260 if workday else 20, 2025701, lambda: rng.choice(CLIENTS), "10.10.20.15", 445, (8, 18)),
            (30 if workday else 2, 2025701, lambda: rng.choice(CLIENTS),
             lambda: rng.choice(["10.10.0.10", "10.10.0.11"]), 445, (8, 10)),
            (40 if workday else 0, 2025709, lambda: rng.choice(CLIENTS), "10.10.20.30", 445, (8, 18)),
            (120, 9900001, lambda: rng.choice(CLIENTS), "10.10.0.53", 53, (0, 24)),
            (40 if second else 5, 9900002, lambda: "10.10.100.40", "203.0.113.50", 443, (0, 24)),
            (0 if second else 50, 9900003, lambda: rng.choice(CLIENTS[:10]), "10.10.20.40", 80, (8, 18)),
        ]
        if d == 2:  # admin share copy on a workstation, a handful of events
            plan.append((3, 2025701, lambda: "10.10.100.77", "10.10.30.40", 445, (14, 15)))
        if second and d == 3:
            plan.append((1, 9100001, lambda: "10.10.100.66", "10.10.0.10", 49678, (2, 3)))
        for count, sid, src, dst, port, (h0, h1) in plan:
            for _ in range(count):
                out.append(event(at(h0, h1), flow, src(), dst() if callable(dst) else dst, port, sid))
                flow += 1
    out.sort(key=lambda e: e["timestamp"])
    return out


def main(dest):
    rng = random.Random(42)
    start = datetime.datetime(2026, 1, 5, tzinfo=TZ)  # Monday
    for i, name in enumerate(("week1", "week2")):
        d = pathlib.Path(dest) / name
        d.mkdir(parents=True, exist_ok=True)
        events = week(rng, start + datetime.timedelta(days=7 * i), second=bool(i))
        with open(d / "eve.json", "w") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        print(f"{d / 'eve.json'}: {len(events)} alerts")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "examples/lab/data")
