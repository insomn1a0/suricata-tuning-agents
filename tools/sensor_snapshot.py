"""Aggregate Suricata EVE alerts per SID and print one JSON document.

Runs either ON the sensor (piped over ssh, stdlib only):
    ssh analyst@sensor "sudo -n python3 -I - --days 7" < tools/sensor_snapshot.py
or locally against a file (lab / demo):
    python3 tools/sensor_snapshot.py --eve-glob 'examples/lab/week1/*.json' --now 2026-01-12T00:00:00+00:00

Only aggregates leave the sensor: counts, distinct counts and top-5 lists. Raw events never do.
`predicted_rule`/`predicted_level` mirror the severity x confidence ladder in
wazuh/rules/100200-suricata_rules.xml (100200-100206). Tuning children (100220+, generated) are not
modelled - confirm final rule IDs with a SIEM query.
"""
import argparse
import collections
import datetime
import glob
import gzip
import json
import os
import shutil
import subprocess
import sys


def predicted(sev, conf):
    """Severity x confidence -> (Wazuh rule id, level). Keep in sync with the XML ladder."""
    if sev == "Critical":
        return {"Medium": ("100201", 11), "High": ("100202", 13)}.get(conf, ("100200", 10))
    if sev == "Major":
        return {"Medium": ("100204", 8), "High": ("100205", 9)}.get(conf, ("100203", 7))
    if sev == "Minor" and conf == "High":
        return ("100206", 6)
    return ("86601", 3)  # stock Wazuh Suricata alert rule


def parse_ts(ts):
    # Suricata: 2026-01-05T10:00:00.123456+0200
    return datetime.datetime.strptime(ts[:19] + ts[-5:], "%Y-%m-%dT%H:%M:%S%z")


def parse_hours(spec):
    start, end = (int(x) for x in spec.split("-"))
    if not (0 <= start < end <= 24):
        raise ValueError(f"bad --work-hours {spec!r}, expected e.g. 8-19")
    return start, end


def open_any(path):
    return gzip.open(path, "rb") if path.endswith(".gz") else open(path, "rb")


def build(paths, days, now, work_hours, tz=None):
    since = now - datetime.timedelta(days=days)
    start_h, end_h = work_hours
    sids, total, skipped = {}, 0, 0
    for path in paths:
        with open_any(path) as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                    if e.get("event_type", "alert") != "alert":
                        continue
                    t = parse_ts(e["timestamp"])
                    a = e["alert"]
                    sid = a["signature_id"]
                except (ValueError, KeyError, TypeError):
                    skipped += 1
                    continue
                if t < since or t > now:
                    continue
                total += 1
                s = sids.get(sid)
                if s is None:
                    m = a.get("metadata") or {}
                    sev = ",".join(m.get("signature_severity", [])) or "-"
                    conf = ",".join(m.get("confidence", [])) or "-"
                    rid, lvl = predicted(sev, conf)
                    s = sids[sid] = {
                        "sid": sid, "rev": a.get("rev"), "signature": a.get("signature", ""),
                        "category": a.get("category"), "severity": sev, "confidence": conf,
                        "mitre": m.get("mitre_technique_id", []),
                        "predicted_rule": rid, "predicted_level": lvl, "count": 0,
                        "first": e["timestamp"], "last": e["timestamp"],
                        "_src": collections.Counter(), "_dst": collections.Counter(),
                        "_pair": collections.Counter(), "_port": collections.Counter(),
                        "_proto": collections.Counter(), "_days": set(), "_work": 0, "_flows": set(),
                    }
                s["count"] += 1
                s["first"] = min(s["first"], e["timestamp"])
                s["last"] = max(s["last"], e["timestamp"])
                src, dst, dport = e.get("src_ip"), e.get("dest_ip"), e.get("dest_port")
                s["_src"][src] += 1
                s["_dst"][dst] += 1
                s["_pair"][f"{src}->{dst}:{dport}"] += 1
                s["_port"][dport] += 1
                s["_proto"][e.get("app_proto", "-")] += 1
                local = t.astimezone(tz)
                s["_days"].add(local.date().isoformat())
                if start_h <= local.hour < end_h and local.weekday() < 5:
                    s["_work"] += 1
                if len(s["_flows"]) < 100000:
                    s["_flows"].add(e.get("flow_id"))

    out = []
    for s in sids.values():
        out.append({
            **{k: v for k, v in s.items() if not k.startswith("_")},
            "per_day": round(s["count"] / days, 1),
            "days_seen": len(s["_days"]),
            "flows": len(s["_flows"]),
            "src_distinct": len(s["_src"]), "dst_distinct": len(s["_dst"]),
            "pair_distinct": len(s["_pair"]),
            "top_src": s["_src"].most_common(5), "top_dst": s["_dst"].most_common(5),
            "top_pairs": s["_pair"].most_common(5), "ports": s["_port"].most_common(5),
            "app_proto": s["_proto"].most_common(3),
            "worktime_share": round(s["_work"] / s["count"], 2),
        })
    out.sort(key=lambda x: (-x["count"], x["sid"]))
    return {
        "generated_utc": now.astimezone(datetime.timezone.utc).isoformat(timespec="seconds"),
        "days": days, "files": paths, "alerts": total, "skipped_lines": skipped,
        "visible": sum(x["count"] for x in out if x["predicted_level"] >= 6),
        "sids": out,
    }


def suricata_version():
    if not shutil.which("suricata"):
        return None
    return subprocess.run(["suricata", "-V"], capture_output=True, text=True).stdout.strip() or None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--logdir", default="/var/log/suricata")
    p.add_argument("--pattern", default="eve.json*", help="file glob inside --logdir")
    p.add_argument("--eve-glob", help="explicit glob, overrides --logdir/--pattern")
    p.add_argument("--work-hours", default="8-19", help="local working hours, Mon-Fri, e.g. 8-19")
    p.add_argument("--now", help="ISO time for reproducible runs (default: current time)")
    args = p.parse_args(argv)

    now = (datetime.datetime.fromisoformat(args.now) if args.now
           else datetime.datetime.now(datetime.timezone.utc))
    since = now - datetime.timedelta(days=args.days)
    pattern = args.eve_glob or os.path.join(args.logdir, args.pattern)
    paths = sorted(p for p in glob.glob(pattern)
                   if args.eve_glob or datetime.datetime.fromtimestamp(
                       os.path.getmtime(p), datetime.timezone.utc) >= since)
    if not paths:
        sys.exit(f"no files match {pattern}")
    doc = build(paths, args.days, now, parse_hours(args.work_hours),
                tz=now.tzinfo if args.now else None)
    doc["suricata"] = suricata_version()
    json.dump(doc, sys.stdout, ensure_ascii=False)
    print()


if __name__ == "__main__":
    main()
