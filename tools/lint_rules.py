"""Static checks for wazuh/rules/*.xml - fast, no Wazuh needed (evidence label: static).
- XML parses; rule IDs unique and inside the registry range (RULE_ID_RANGE, default 100200-100299)
- every <if_sid> points to a rule in this repo or to an allowed stock parent
- tuning rules (level < 6 or with ignore/frequency) pin alert.signature_id with an anchored pcre2 regex
- every pcre2 field regex is anchored (^...$) unless it is explicitly case-insensitive domain matching
- descriptions contain no literal IPv4 addresses (use $(src_ip)/$(dest_ip))
Usage: lint_rules.py [files...]   exit 1 on findings"""
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

import kitconfig

ROOT = pathlib.Path(__file__).resolve().parent.parent
STOCK_PARENTS = {"86600", "86601"}
IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def load(path):
    text = pathlib.Path(path).read_text()
    return ET.fromstring(f"<root>{text}</root>")


def lint(paths, id_range):
    lo, hi = id_range
    rules, findings = {}, []
    for path in paths:
        try:
            root = load(path)
        except ET.ParseError as e:
            findings.append(f"{path}: XML parse error: {e}")
            continue
        for r in root.iter("rule"):
            rid = r.get("id")
            if rid in rules:
                findings.append(f"{path}: duplicate rule id {rid}")
            rules[rid] = (path, r)
            if not (lo <= int(rid) <= hi):
                findings.append(f"{path}: rule {rid} outside registry range {lo}-{hi}")
    for rid, (path, r) in rules.items():
        for parent in (r.findtext("if_sid") or "").replace(",", " ").split():
            if parent not in rules and parent not in STOCK_PARENTS:
                findings.append(f"{path}: rule {rid} if_sid {parent} not found")
        fields = {f.get("name"): f for f in r.findall("field")}
        level = int(r.get("level", "0"))
        tuning = level < 6 or r.get("ignore") or r.get("frequency")
        if tuning and r.findtext("if_sid") not in STOCK_PARENTS:
            sid = fields.get("alert.signature_id")
            if sid is None or sid.get("type") != "pcre2" or not re.fullmatch(r"\^.+\$", sid.text or ""):
                findings.append(f"{path}: tuning rule {rid} must pin alert.signature_id with anchored pcre2")
        for name, f in fields.items():
            if f.get("type") == "pcre2":
                pat = f.text or ""
                if not (pat.startswith("^") or pat.startswith("(?i)^")) or not pat.endswith("$"):
                    findings.append(f"{path}: rule {rid} field {name} pcre2 not anchored: {pat}")
        desc = r.findtext("description") or ""
        if IPV4.search(desc):
            findings.append(f"{path}: rule {rid} description has a literal IP; use $(src_ip)/$(dest_ip)")
    return rules, findings


def main(argv):
    spec = kitconfig.load()["RULE_ID_RANGE"]
    id_range = tuple(int(x) for x in spec.split("-"))
    paths = argv or sorted(str(p) for p in (ROOT / "wazuh" / "rules").glob("*.xml"))
    rules, findings = lint(paths, id_range)
    for f in findings:
        print(f"LINT {f}")
    print(f"lint: {len(rules)} rules, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
