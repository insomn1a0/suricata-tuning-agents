"""Static checks for wazuh/rules/*.xml - fast, no Wazuh needed (evidence label: static).
- XML parses; rule IDs unique and inside the registry range (RULE_ID_RANGE, default 100200-100299)
- every <if_sid> points to a rule in this repo or to an allowed stock parent
- tuning rules (level < WAZUH_ALERT_LEVEL or with ignore/frequency) pin alert.signature_id, anchored pcre2
- every pcre2 field regex is anchored (^...$) unless it is explicitly case-insensitive domain matching, and an
  alternation is grouped: ^a|b$ means (^a)|(b$) and also matches 'a...' and '...b'
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


def top_level_alternation(pat):
    """True if `|` appears outside any (...) or [...] - the anchors then bind only to the first/last branch."""
    depth, cls, esc = 0, False, False
    for ch in pat:
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif cls:
            cls = ch != "]"
        elif ch == "[":
            cls = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            return True
    return False


def load(path):
    text = pathlib.Path(path).read_text()
    return ET.fromstring(f"<root>{text}</root>")


def lint(paths, id_range, alert_level=None):
    lo, hi = id_range
    alert_level = alert_level if alert_level is not None else int(kitconfig.load()["WAZUH_ALERT_LEVEL"])
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
        tuning = level < alert_level or r.get("ignore") or r.get("frequency")
        if tuning:  # also under a stock parent: an unpinned low-level child of 86601 hides everything
            sid = fields.get("alert.signature_id")
            if sid is None or sid.get("type") != "pcre2" or not re.fullmatch(r"\^.+\$", sid.text or ""):
                findings.append(f"{path}: tuning rule {rid} must pin alert.signature_id with anchored pcre2")
        for name, f in fields.items():
            if f.get("type") == "pcre2":
                pat = f.text or ""
                if not (pat.startswith("^") or pat.startswith("(?i)^")) or not pat.endswith("$"):
                    findings.append(f"{path}: rule {rid} field {name} pcre2 not anchored: {pat}")
                elif top_level_alternation(pat):
                    findings.append(f"{path}: rule {rid} field {name} alternation outside a group: {pat}")
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
