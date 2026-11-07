"""Fetch selected rules from the ET Open ruleset at test time - never vendored into the repo.

The corpus normally fires on lab stand-ins (tests/corpus/lab-standins.rules). With the real ruleset the claim
gets stronger: the generated tuning keeps the attack visible when the *actual* ET signature fires, and the
intents' declared metadata is checked against the actual rule text.

- Downloads https://rules.emergingthreats.net/open/suricata-<SURICATA_VERSION>/emerging.rules.tar.gz.
- Reads the archive in memory (nothing extracted to disk, so no path traversal from a foreign tarball).
- Checks the bundled LICENSE: the requested SIDs must sit in the range it declares BSD-licensed.
- Keeps only the SIDs listed in tests/corpus/suite.yaml (`et_open.sids`) and reports `rev` drift against
  `et_open.expected_rev` - an upstream change to a tuned signature is worth a look.
Output (git-ignored): rules-cache/et-open/selected.rules and manifest.json.

Usage: fetch_et_rules.py [--archive FILE] [--strict]     --strict: exit 1 on rev drift"""
import argparse
import datetime
import hashlib
import io
import json
import pathlib
import re
import sys
import tarfile
import urllib.request

import yaml

import kitconfig

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "rules-cache" / "et-open"
URL = "https://rules.emergingthreats.net/open/suricata-{version}/emerging.rules.tar.gz"
BSD_RANGE = re.compile(r"sids\s+(\d+)\s+through\s+(\d+)\s+are from Emerging Threats and are covered under the BSD",
                       re.I)
MAX_ARCHIVE = 64 * 1024 * 1024


def download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "suricata-tuning-agents (lab tests)"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https URL
        data = r.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise SystemExit(f"archive larger than {MAX_ARCHIVE} bytes - refusing")
    return data


def members(data):
    """{name: text} for rules/LICENSE and rules/*.rules, read in memory."""
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile() and re.fullmatch(r"rules/(LICENSE|[\w.-]+\.rules)", m.name):
                out[m.name] = tar.extractfile(m).read().decode("utf-8", errors="replace")
    return out


def select(rule_texts, sids):
    """{sid: rule line} for active rules with these SIDs."""
    found = {}
    for text in rule_texts:
        for line in text.splitlines():
            m = re.search(r"\bsid:\s*(\d+)\s*;", line)
            if m and int(m.group(1)) in sids and not line.lstrip().startswith("#"):
                found[int(m.group(1))] = line.strip()
    return found


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--archive", help="use a local emerging.rules.tar.gz instead of downloading")
    p.add_argument("--strict", action="store_true", help="exit 1 if a rule's rev differs from expected_rev")
    args = p.parse_args(argv)
    spec = yaml.safe_load((ROOT / "tests" / "corpus" / "suite.yaml").read_text())["et_open"]
    sids, expected_rev = set(spec["sids"]), {int(k): v for k, v in spec.get("expected_rev", {}).items()}
    url = URL.format(version=kitconfig.load()["SURICATA_VERSION"])
    data = pathlib.Path(args.archive).read_bytes() if args.archive else download(url)
    files = members(data)
    license_text = files.get("rules/LICENSE", "")
    rng = BSD_RANGE.search(license_text)
    if not rng:
        raise SystemExit("ET Open LICENSE does not declare a BSD SID range - not using these rules")
    lo, hi = int(rng.group(1)), int(rng.group(2))
    outside = sorted(s for s in sids if not lo <= s <= hi)
    if outside:
        raise SystemExit(f"SIDs {outside} are outside the BSD range {lo}-{hi} declared by ET Open's LICENSE")
    found = select((t for n, t in files.items() if n.endswith(".rules")), sids)
    missing = sorted(sids - set(found))
    if missing:
        raise SystemExit(f"SIDs {missing} not found (or disabled) in ET Open for this Suricata version")
    revs = {sid: int(re.search(r"\brev:\s*(\d+)", line).group(1)) for sid, line in found.items()}
    drift = {sid: (expected_rev[sid], rev) for sid, rev in revs.items()
             if sid in expected_rev and expected_rev[sid] != rev}
    OUT.mkdir(parents=True, exist_ok=True)
    header = (f"# ET Open rules selected for the corpus - fetched {datetime.date.today()} from {url}\n"
              f"# SIDs {lo}-{hi}: BSD License, Copyright (c) 2003-2026 Emerging Threats (see LICENSE in the archive)\n")
    (OUT / "selected.rules").write_text(header + "\n".join(found[s] for s in sorted(found)) + "\n")
    (OUT / "LICENSE").write_text(license_text)
    (OUT / "manifest.json").write_text(json.dumps({
        "url": url, "sha256": hashlib.sha256(data).hexdigest(), "fetched": str(datetime.date.today()),
        "bsd_range": [lo, hi], "revs": revs, "drift": {str(k): v for k, v in drift.items()}}, indent=2) + "\n")
    print(f"et-open: {len(found)} rules -> {(OUT / 'selected.rules').relative_to(ROOT)} (BSD range {lo}-{hi})")
    for sid, (want, got) in drift.items():
        print(f"DRIFT sid {sid}: expected rev {want}, ET Open has rev {got} - re-check the intents for it")
    return 1 if drift and args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
