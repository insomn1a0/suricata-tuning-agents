"""Public-repo guard: tracked files may contain only lab data.
- IPv4 addresses/prefixes must be inside 10.10.0.0/16, the documentation ranges (RFC 5737) or loopback.
- Internal-looking hostnames (*.local, *.lan, *.corp, *.internal, *.intra) must be *.lab.local.
A line ending in the marker `lab-data: allow` is skipped - only for deliberate negative test fixtures.
Usage: check_lab_data.py [file ...]     (default: tracked + untracked-not-ignored files)   exit 1 on any finding"""
import ipaddress
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ALLOWED_NETS = [ipaddress.ip_network(n) for n in
                ("10.10.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32")]
IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?!\.?\d)")  # not part of 1.2.3.4.5
ALLOW = "lab-data: allow"
HOST = re.compile(r"\b((?:[a-z0-9-]+\.)+(?:local|lan|corp|internal|intra))\b(?!\.[a-z])", re.I)  # not settings.local.json


def ip_findings(line):
    out = []
    for m in IPV4.finditer(line):
        try:
            net = ipaddress.ip_network(m.group(0), strict=False)
        except ValueError:
            continue  # not an address (e.g. 999.1.1.1)
        if not any(net.subnet_of(a) for a in ALLOWED_NETS):
            out.append(f"non-lab address {m.group(0)}")
    return out


def host_findings(line):
    return [f"non-lab hostname {h}" for h in HOST.findall(line)
            if not (h.lower() == "lab.local" or h.lower().endswith(".lab.local"))]


def check_file(path, label):
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8")
    except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
        return []
    return [f"{label}:{n}: {f}" for n, line in enumerate(text.splitlines(), 1)
            if not line.rstrip().endswith(ALLOW) for f in ip_findings(line) + host_findings(line)]


def main(argv):
    if not argv and not (ROOT / ".git").exists():
        print("lab-data: skipped - not a git repository (repo hygiene check for the public kit)")
        return 0
    paths = argv or subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True,
                                   check=True).stdout.splitlines()
    findings = [f for p in paths for f in check_file(p if argv else ROOT / p, p)]
    for f in findings:
        print(f"LABDATA {f}")
    print(f"lab-data: {len(paths)} files, {len(findings)} findings")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
