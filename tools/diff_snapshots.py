"""Compare two snapshots: new SIDs, disappeared SIDs (possible breakage), x5 spikes/drops,
and the change in analyst-visible volume.
Usage: diff_snapshots.py [old.json new.json]   (default: two latest snapshots/*-7d.json)"""
import glob
import json
import pathlib
import sys

SPIKE_RATIO = 5
MIN_PER_DAY = 5


def compare(old, new, ratio=SPIKE_RATIO, min_per_day=MIN_PER_DAY):
    o = {s["sid"]: s for s in old["sids"]}
    n = {s["sid"]: s for s in new["sids"]}
    appeared = sorted((n[k] for k in n.keys() - o.keys()), key=lambda s: -s["count"])
    gone = sorted((o[k] for k in o.keys() - n.keys()), key=lambda s: -s["count"])
    changed = []
    for k in o.keys() & n.keys():
        a, b = o[k]["per_day"], n[k]["per_day"]
        if max(a, b) >= min_per_day and (b >= ratio * max(a, 0.1) or a >= ratio * max(b, 0.1)):
            changed.append({"sid": k, "was": a, "now": b, "signature": n[k]["signature"],
                            "level": n[k]["predicted_level"]})
    changed.sort(key=lambda c: -max(c["now"] / max(c["was"], 0.1), c["was"] / max(c["now"], 0.1)))
    return {
        "alerts": (old["alerts"], new["alerts"]),
        "visible": (old["visible"], new["visible"]),
        "sids": (len(o), len(n)),
        "appeared": appeared, "gone": gone, "changed": changed,
    }


def row(s, extra=""):
    return f"  {s['sid']:>10} L{s['predicted_level']:<2} {s['per_day']:>8}/d {extra}{s['signature'][:70]}"


def render(old, new, r):
    lines = [f"{old['generated_utc']} -> {new['generated_utc']}",
             f"alerts {r['alerts'][0]} -> {r['alerts'][1]}, visible {r['visible'][0]} -> {r['visible'][1]}, "
             f"sids {r['sids'][0]} -> {r['sids'][1]}",
             f"\nNEW SIDs ({len(r['appeared'])}):"]
    lines += [row(s) for s in r["appeared"][:15]]
    lines.append(f"\nDISAPPEARED SIDs ({len(r['gone'])}) - if they were steady, check for breakage:")
    lines += [row(s, f"days_seen_before={s['days_seen']} ") for s in r["gone"][:15]]
    lines.append(f"\nSPIKES / DROPS x{SPIKE_RATIO} ({len(r['changed'])}):")
    lines += [f"  {c['sid']:>10} L{c['level']:<2} {c['was']:>8}/d -> {c['now']}/d {c['signature'][:60]}"
              for c in r["changed"][:15]]
    return "\n".join(lines)


def main(argv):
    if len(argv) == 2:
        old_p, new_p = argv
    else:
        snaps = pathlib.Path(__file__).resolve().parent.parent / "snapshots"
        files = sorted(glob.glob(str(snaps / "*-7d.json")))
        if len(files) < 2:
            sys.exit("need two snapshots (or pass old.json new.json)")
        old_p, new_p = files[-2:]
    old, new = (json.load(open(p)) for p in (old_p, new_p))
    print(render(old, new, compare(old, new)))


if __name__ == "__main__":
    main(sys.argv[1:])
