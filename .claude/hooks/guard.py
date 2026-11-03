#!/usr/bin/env python3
"""PreToolUse guard: turns the kit's safety rules (docs/SAFETY.md) from advice into enforcement.

Principle: recognise the safe path exactly, send everything else to a human, block known writes.
  block - exit 2, reason on stderr (Claude sees it and must change course)
  ask   - the user confirms in Claude Code's permission prompt
  allow - silent exit 0

Sensor (ssh and friends):
  - ssh must be a plain top-level command with allowlisted options; a sensor reference inside loops,
    `bash -c`, xargs, pipes into interpreters, other remote-execution tools (pssh, ansible, ...) is asked
    about, and blocked if a write verb shows up;
  - each remote command is checked against its read-only form (options with arguments are skipped per
    command, then an exact verb set): unknown -> ask; known writes, root shells and text fed into a remote
    shell -> block. A reviewed change prefixed with SENSOR_CHANGE=<card-id> (the sensor-change skill) goes
    to the user instead of being blocked;
  - raw telemetry (EVE, pcap) must come back bounded or aggregated.
Elsewhere: commit/push/merge and outward GitHub actions -> ask; internal identifiers (private ranges in any
notation, inventory names and addresses, the sensor) or local telemetry files sent to web tools -> block;
secrets written into files -> block; edits to the guard, its registration or the approved sensor scripts -> ask.

Fail closed: invalid input or any internal error blocks. The guard reads the command line Claude runs; it is
a seatbelt, not a sandbox. The boundary on the sensor is the read-only account (docs/SAFETY.md)."""
import ipaddress
import json
import os
import pathlib
import re
import shlex
import sys
import urllib.parse

BLOCK, ASK, ALLOW = "block", "ask", "allow"
RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}

# ---------- vocabulary ----------

SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
INTERPRETERS = SHELLS | {"python", "python3", "perl", "ruby", "node", "php", "lua", "tclsh", "expect", "osascript"}
# Local commands that execute their arguments or stdin: a sensor reference inside them is not just data.
EXECUTORS = INTERPRETERS | {"eval", "exec", "source", ".", "xargs", "watch", "timeout", "nohup", "env", "sudo", "doas",
                            "su", "time", "nice", "ionice", "caffeinate", "parallel", "script", "at", "batch",
                            "crontab", "setsid", "stdbuf", "chronic", "unbuffer", "flock", "tmux", "screen", "make",
                            "command", "builtin", "find", "fd", "git", "docker", "podman", "kubectl", "busybox"}
KEYWORDS = {"if", "then", "else", "elif", "fi", "for", "in", "while", "until", "do", "done", "case", "esac",
            "function", "select", "!", "{", "}", "(", ")", "[[", "]]", "coproc"}
PLAIN_SENSOR_TOOLS = {"ssh", "scp", "sftp", "rsync"}
# Other ways to run commands on a remote host; never parsed, always asked about (blocked with write verbs).
REMOTE_EXEC = re.compile(r"^(?:[\w.-]*ssh[\w.-]*|mosh|ansible[\w-]*|salt[\w-]*|pdsh|clush|fab|tsh|teleport|"
                         r"rexec|rsh|telnet|ipmitool|pwsh|winrm)$")
REMOTE_EXEC_SUB = {"gcloud": "ssh", "aws": "ssm", "az": "ssh", "kubectl": "exec", "docker": "exec"}
SAFE_SSH_FLAGS = {"q", "T", "n", "4", "6", "x", "a", "C", "v"}
SAFE_SSH_ARG_FLAGS = {"-i", "-p", "-l"}
SAFE_SSH_OPTIONS = {"batchmode", "connecttimeout", "serveraliveinterval", "serveralivecountmax", "loglevel",
                    "identitiesonly", "stricthostkeychecking", "connectionattempts", "identityfile", "port", "user"}
SSH_ARG_FLAGS = set("BbcDEeFIiJLlmOoPpQRSWw")

REMOTE_WRITE = {"rm", "rmdir", "mv", "cp", "tee", "dd", "truncate", "install", "ln", "mkdir", "touch", "chmod",
                "chown", "chgrp", "kill", "pkill", "killall", "reboot", "shutdown", "halt", "poweroff", "crontab",
                "useradd", "usermod", "userdel", "passwd", "tcpreplay", "suricata-update", "curl", "wget", "scp",
                "rsync", "shred", "unlink", "patch", "logrotate", "vi", "vim", "nano", "ed", "emacs", "sudoedit",
                "tar", "unzip", "gzip", "gunzip", "bzip2", "xz", "zip", "iptables", "nft", "ifconfig", "mount",
                "umount", "modprobe", "insmod", "rmmod", "sysctl", "visudo", "apt", "apt-get", "dnf", "yum",
                "pip", "pip3", "snap", "systemd-run", "at", "nc", "ncat", "socat", "chattr", "setfacl", "mkfifo",
                "telinit", "init", "wall", "write", "sponge", "dpkg-reconfigure", "su", "sudoreplay",
                "update-alternatives", "systemd-tmpfiles", "ssh-copy-id"}
PLAIN_READ = {"cat", "zcat", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "wc", "ls", "stat", "cut", "tr", "jq",
              "column", "nl", "tac", "comm", "readlink", "realpath", "dirname", "basename", "md5sum", "sha1sum",
              "sha256sum", "test", "[", "echo", "printf", "true", "false", "df", "du", "free", "uptime", "id",
              "whoami", "uname", "nproc", "lscpu", "ps", "pgrep", "lsof", "dpkg-query", "pidof", "getent", "groups",
              "who", "printenv"}
# Options that take a value, per command - the value must not be mistaken for a verb or a file.
OPTION_ARGS = {
    "systemctl": {"-p", "--property", "-t", "--type", "-H", "--host", "-M", "--machine", "-s", "--signal",
                  "--state", "-n", "--lines", "-o", "--output", "--what", "--kill-whom", "--root"},
    "ip": {"-n", "-netns", "-f", "-family", "-rc", "-rcvbuf", "-l", "-loops"},
    "date": {"-d", "--date", "-r", "--reference", "-f", "--file", "-I", "--iso-8601", "--rfc-3339"},
    "service": set(),
}
SERVICE_READ = {"status", "is-active", "is-enabled", "is-failed", "show", "cat", "list-units", "list-timers",
                "list-unit-files", "list-dependencies", "list-sockets"}
SURICATASC_READ = {"version", "uptime", "running-mode", "capture-mode", "dump-counters", "iface-list", "iface-stat",
                   "memcap-list", "memcap-show", "ruleset-stats", "ruleset-failed-rules", "help"}
SURICATA_INFO = {"-V", "--build-info", "--list-keywords", "--list-app-layer-protos", "--dump-config", "-h", "--help"}
ETHTOOL_READ = {"-S", "--statistics", "-i", "--driver", "-k", "--show-features", "--show-offload", "-g", "--show-ring",
                "-l", "--show-channels", "-a", "--show-pause", "-c", "--show-coalesce", "-T", "--show-time-stamping",
                "-P", "--show-permaddr", "--phy-statistics"}
IP_OBJECTS = ("link", "address", "addr", "route", "neighbour", "neigh", "rule", "maddress", "tunnel", "netconf")
IP_READ_VERBS = {"show", "list", "lst", "ls", "sh", "get"}
IP_READ_OPTS = {"-s", "-stats", "-statistics", "-d", "-details", "-4", "-6", "-j", "-json", "-p", "-pretty", "-br",
                "-brief", "-c", "-color", "-o", "-oneline", "-h", "-human"}
JOURNAL_WRITE = ("--vacuum", "--rotate", "--flush", "--sync", "--setup-keys", "--update-catalog", "--relinquish",
                 "--smart-relinquish", "--cursor-file")
FIND_ACTIONS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"}
DPKG_WRITE = re.compile(r"^(?:-[A-Za-z]*[iruPaCV]|--(?:install|remove|purge|unpack|configure|triggers|set-selections|"
                        r"clear-selections|update-avail|merge-avail|add-architecture|remove-architecture|force))")
SAFE_SED = re.compile(r"^(?:(?:\d+|\$|/[^/]*/)(?:,(?:\d+|\$|/[^/]*/))?)?p$|^\d+q$|^s/[^/]*/[^/]*/[gpI0-9]*$")
SAFE_REDIRECT = {"/dev/null", "/dev/stderr", "/dev/stdout"}
SAFE_REMOTE_ENV = re.compile(r"^(?:LC_\w+|LANG|LANGUAGE|TZ|COLUMNS|TERM)$")

EGRESS = {"curl", "wget", "http", "https", "httpie", "xh", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "aria2c",
          "dig", "nslookup", "host", "drill", "whois", "openssl"}
EGRESS_TEXT = re.compile(r"https?://|urlopen|requests\.|httpx|fetch\(|socket\.|\b(?:curl|wget|xh|socat|dig|nslookup)\b")
UPLOAD_FLAGS = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--json", "-F", "--form", "-T",
                "--upload-file", "-K", "--config", "--post-file", "--body-file"}
SENSITIVE_PATHS = ("snapshots/", "cards/", "inventory/hosts.md", "config/environment.env", "journal/")
# The guard itself, its registration and the scripts it trusts: changing them changes what is allowed.
PROTECTED = (".claude/hooks/", ".claude/settings.json", ".claude/settings.local.json", "tools/sensor_snapshot.py",
             "tools/snapshot.sh")

GIT_ASK = {"commit", "push", "merge", "rebase", "tag", "commit-tree", "update-ref", "send-pack", "filter-branch",
           "filter-repo", "am", "cherry-pick", "revert", "pull"}
GH_ASK = {("pr", s) for s in ("create", "merge", "comment", "review", "edit", "close", "reopen", "ready")} | \
         {("issue", s) for s in ("create", "comment", "edit", "close", "reopen", "delete", "transfer")} | \
         {("repo", s) for s in ("create", "edit", "delete", "rename", "archive", "fork", "sync")} | \
         {("workflow", "run"), ("alias", "set"), ("label", "create"), ("label", "edit"), ("label", "delete")}
GH_ASK_GROUPS = {"release", "gist", "secret", "variable", "ruleset"}

# Secret patterns. Literal key headers are assembled so this file does not match its own patterns.
_KEY = "PRIVATE" + " KEY"
SECRET_PATTERNS = [
    (re.compile(r"-{5}BEGIN[\s\S]{0,40}" + _KEY), "private key"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"), "GitHub token"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), "GitLab token"),
    (re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}"), "API key"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}"), "JWT"),
    (re.compile(r"(?i)authorization:\s*(?:basic|bearer|token)\s+[A-Za-z0-9+/=._-]{8,}"), "HTTP credentials"),
    (re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:[^/\s@'\"$<{]{3,}@"), "credentials in a URL"),
    (re.compile(r"(?:^|\s)(?:-u|--user)\s+['\"]?[^\s:'\"]+:[^\s'\"$<{]{3,}"), "credentials on a command line"),
]
CRED_KEY = re.compile(  # not after $ or ${: "$PWD:/repo" is a variable, not a credential
    r"(?i)(?<![$\w{])[\"']?\b[\w.-]*(?:passw(?:or)?d|passwd|pass|pwd|pw|secret|token|api[_-]?key|credentials?|creds)\b[\"']?"
    r"\s*[:=]\s*(?:\"([^\"\n]+)\"|'([^'\n]+)'|([^\s\"',;}]+))")
PLACEHOLDER = re.compile(r"(?i)^(?:\$|<|\{\{|%\(|\*+$|x+$|changeme$|example$|placeholder$|redacted$|none$|null$|"
                         r"true$|false$|\.\.\.$|tbd$|todo$|your[_-])")

PRIVATE_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")  # lab-data: allow
PRIVATE_NETS = [ipaddress.ip_network(n) for n in PRIVATE_RANGES]  # RFC 1918, 6598 (CGNAT), 4193 (ULA)
IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.]*\d)")
IPV6_ULA = re.compile(r"(?i)(?<![\w:])f[cd][0-9a-f]{2}:[0-9a-f:]*[0-9a-f](?![\w:])")
IP_INT = re.compile(r"(?<![\w.])(?:0x[0-9a-fA-F]{8}|\d{9,10})(?![\w.])")
HOSTNAME = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]+\b", re.I)
INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".intra", ".home.arpa")
INTERNAL_LABELS = {"corp", "internal", "intranet", "intra", "lan", "local"}
RAW_TELEMETRY = r"eve[\w.*-]*\.json|\.pcap|filestore|{logdir}/[\w.-]*\*|{logdir}/[\w.*-]*\.json"
TRANSFORM = {"jq", "sort", "uniq", "cut", "tr", "column", "grep", "egrep", "zgrep", "awk", "sed", "nl", "cat", "tac"}
BOUNDING = {"wc", "md5sum", "sha256sum", "sha1sum", "stat", "ls", "du", "test", "[", "file", "readlink", "realpath"}


class Context:
    """Environment-specific identifiers: the sensor and the inventory (both git-ignored files)."""

    def __init__(self, sensor_host="", internal_names=(), warning="", log_dir="/var/log/suricata", sensor_aliases=()):
        self.sensor_host = sensor_host.lower()
        self.sensor_aliases = {a.lower() for a in sensor_aliases if a} | ({self.sensor_host} - {""})
        names = {n.lower() for n in internal_names if n and "." in n}
        names |= {n.split(".")[0] for n in names if not IPV4.fullmatch(n) and len(n.split(".")[0]) >= 3}
        self.internal_names = names
        self.warning = warning
        self.log_dir = log_dir.rstrip("/") or "/var/log/suricata"

    @classmethod
    def load(cls, project_dir):
        root = pathlib.Path(project_dir)
        sensor, names, aliases, log_dir, warning = "", set(), set(), "/var/log/suricata", ""
        try:
            env = root / "config" / "environment.env"
            if env.is_file():
                for tok in shlex.split(env.read_text(), comments=True):
                    key, _, value = tok.partition("=")
                    if key == "SENSOR_SSH":
                        sensor = value.rsplit("@", 1)[-1]
                    elif key == "SURICATA_LOG_DIR" and value:
                        log_dir = value
            hosts = root / "inventory" / "hosts.md"
            if hosts.is_file():
                for line in hosts.read_text().splitlines():
                    cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.lstrip().startswith("|") else []
                    if len(cells) < 2 or set(cells[0]) <= set("-: ") or cells[0].lower() in ("address", "ip"):
                        continue
                    addr, name = cells[0], cells[1]
                    row = {a for a in re.split(r"[\s,]+", addr) if IPV4.fullmatch(a)}
                    if name and name != "-":
                        row.add(name)
                    names |= row
                    if sensor and sensor.lower() in {r.lower() for r in row}:
                        aliases |= row  # the sensor's address and name from the inventory
                names |= {h for h in HOSTNAME.findall(hosts.read_text()) if h.lower().endswith(INTERNAL_SUFFIXES)}
        except (OSError, ValueError) as e:  # a broken config must not lock the user out of fixing it
            warning = f"config not readable ({e}); internal-name checks limited"
        return cls(sensor, names | ({sensor} if "." in sensor else set()), warning, log_dir, aliases)

    def internal_identifiers(self, text):
        text = urllib.parse.unquote(text)
        found = [ip for ip in IPV4.findall(text) if _private(_norm_ip(ip))]
        found += [ip for ip in IPV6_ULA.findall(text) if _private(ip)]
        for raw in IP_INT.findall(text):  # 168432655 and 0x0a0a140f are 10.10.20.15 too
            try:
                ip = str(ipaddress.ip_address(int(raw, 16) if raw.lower().startswith("0x") else int(raw)))
            except ValueError:
                continue
            if _private(ip):
                found.append(f"{raw} (= {ip})")
        low = text.lower()
        found += [n for n in self.internal_names if re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", low)]
        found += [h for h in HOSTNAME.findall(low) if h.endswith(INTERNAL_SUFFIXES) or
                  set(h.split(".")[:-1]) & INTERNAL_LABELS]
        return sorted(set(found))

    def mentions_sensor(self, text):
        words = [w for w in re.split(r"[\s'\";|&(){}`<>=,]+", text) if w]
        if any(REMOTE_EXEC.match(os.path.basename(w)) or os.path.basename(w) in PLAIN_SENSOR_TOOLS for w in words):
            return True
        if re.search(r"\$\{?SENSOR_SSH\b", text):
            return True
        low = text.lower()
        return any(re.search(r"(?<![\w.-])" + re.escape(a) + r"(?![\w-])", low) for a in self.sensor_aliases)

    def raw_telemetry(self, text):
        return re.search(RAW_TELEMETRY.format(logdir=re.escape(self.log_dir)), text) is not None


def norm_rel(path):
    """'./x/../tools/a.py' -> 'tools/a.py' (a prefix, not characters: lstrip('./') would eat '.claude')."""
    return os.path.normpath(path).replace(os.sep, "/")


def _norm_ip(ip):
    return ".".join(str(int(o)) for o in ip.split("."))


def _private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in PRIVATE_NETS)


# ---------- shell parsing ----------

def strip_heredocs(command):
    """Drop here-document bodies that only feed a local file writer (`cat > f <<EOF`): they are data, not
    commands. Bodies fed to anything else (bash, ssh, python) stay and are analysed."""
    lines, out, i = command.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
        if m and not line.lstrip().startswith("#"):
            first = os.path.basename((line.split() or [""])[0])
            end = next((k for k in range(i + 1, len(lines)) if lines[k].strip() == m.group(1)), None)
            if end is not None and first in ("cat", "tee"):
                out.append(lines[end])
                i = end
        i += 1
    return "\n".join(out)


def split_commands(command):
    """Command line -> [(tokens, piped_in)], split on ; && || | & and newlines. $(...), `...`, <(...) and >(...)
    are pulled out and analysed as commands of their own. Raises ValueError on unbalanced quotes."""
    subs = re.findall(r"\$\(([^()]*)\)|`([^`]*)`|[<>]\(([^()]*)\)", command)
    lex = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=";&|<>")
    lex.whitespace_split = True
    lex.commenters = ""
    segments, cur, piped = [], [], False
    for tok in lex:
        if tok in (";", "&&", "||", "|", "&", ";;", "|&"):
            if cur:
                segments.append((cur, piped))
            cur, piped = [], tok in ("|", "|&")
        else:
            cur.append(tok)
    if cur:
        segments.append((cur, piped))
    for groups in subs:
        segments += split_commands(next(g for g in groups if g))
    return segments


def pipelines(segments):
    """Group segments into pipelines (a | b | c)."""
    out = []
    for argv, piped in segments:
        if piped and out:
            out[-1].append(argv)
        else:
            out.append([argv])
    return out


def short_flags(tok):
    """'-nu' -> {'n', 'u'}; long options and non-options -> empty set."""
    return set(tok[1:]) if re.match(r"^-[A-Za-z0-9]+$", tok) else set()


def positional(cmd, args):
    """Non-option arguments, skipping the values of options that take one (OPTION_ARGS)."""
    takes, out, i = OPTION_ARGS.get(cmd, set()), [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return out + args[i + 1:]
        if a.startswith("-") and len(a) > 1:
            i += 2 if a in takes else 1
        else:
            out.append(a)
            i += 1
    return out


def strip_keywords(argv):
    """Leading shell keywords and grouping (`do ssh`, `(ssh`, `! ssh`) -> (argv, had_keywords)."""
    had, out = False, list(argv)
    while out and (out[0] in KEYWORDS or out[0].startswith(("(", "{"))):
        had = True
        out = out[1:] if out[0] in KEYWORDS or out[0] in ("(", "{") else [out[0].lstrip("({")] + out[1:]
    while out and out[-1] in (")", "}", "fi", "done", "esac"):
        out = out[:-1]
    return out, had


def strip_assignments(argv):
    assigns, i = {}, 0
    while i < len(argv) and re.match(r"^[A-Za-z_]\w*=", argv[i]):
        k, _, v = argv[i].partition("=")
        assigns[k] = v
        i += 1
    return assigns, argv[i:]


SUDO_ARG_FLAGS = set("ugChpUrtTD")
WRAPPER_ARGS = {"env": {"-u", "--unset", "-C", "--chdir"}, "nice": {"-n", "--adjustment"},
                "ionice": {"-c", "-n", "-p", "-P", "-u"}, "stdbuf": {"-i", "-o", "-e"}, "nohup": set(), "exec": {"-a"},
                "command": set(), "time": {"-f", "--format"}, "setsid": set()}
SUDO_VARS = re.compile(r"^\$\{?SENSOR_SUDO(?::-[^}]*)?\}?$")


def strip_remote_wrappers(argv):
    """sudo / $SENSOR_SUDO / env / nice / timeout ... -> (argv, block reason or None)."""
    i = 0
    while i < len(argv):
        tok, base = argv[i], os.path.basename(argv[i])
        if base in ("sudo", "doas") or SUDO_VARS.match(tok):
            i += 1
            while i < len(argv) and argv[i].startswith("-"):
                flag = argv[i]
                if flag == "--":
                    i += 1
                    break
                if flag in ("--login", "--shell", "--edit") or short_flags(flag) & {"i", "s", "e"}:
                    return [], "root shell or editor via sudo"
                takes_arg = (short_flags(flag) and flag[-1] in SUDO_ARG_FLAGS) or flag in ("--user", "--group")
                i += 2 if takes_arg else 1
        elif base in WRAPPER_ARGS:
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or re.match(r"^[A-Za-z_]\w*=", argv[i])):
                flag = argv[i]
                if base == "env" and (flag in ("-S", "--split-string") or flag.startswith("-S")):
                    return [], "`env -S` runs a command string"
                if base == "time" and (flag in ("-o", "-a", "--append") or flag.startswith("--output")):
                    return [], "`time -o` writes a file"
                i += 2 if flag in WRAPPER_ARGS[base] else 1
        elif base == "timeout":
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or re.match(r"^\d", argv[i])):
                i += 2 if argv[i] in ("-s", "--signal", "-k", "--kill-after") else 1
        else:
            break
    return argv[i:], None


def redirects(argv):
    """[(operator, target)] for output redirects to files (2>&1 and >&2 are not files)."""
    out = []
    for i, tok in enumerate(argv):
        if set(tok) <= set("><&|0123456789") and ">" in tok:
            target = argv[i + 1] if i + 1 < len(argv) else ""
            if tok.endswith("&") or tok.startswith("&"):
                if not re.fullmatch(r"[0-9-]+", target):
                    out.append((tok, target))
            elif not target.startswith("&"):
                out.append((tok, target))
    return out


def stdin_sources(argv):
    out = [argv[i + 1] for i, tok in enumerate(argv) if tok in ("<", "0<") and i + 1 < len(argv)]
    return out + ["heredoc" for tok in argv if tok in ("<<", "<<<", "<<-")]


# ---------- remote (on the sensor) ----------

def remote_read_check(cmd, args):
    """None if this is a known read-only form; otherwise (decision, reason)."""
    nonopt = positional(cmd, args)
    if cmd == "systemctl":
        verb = nonopt[0] if nonopt else "list-units"
        return None if verb in SERVICE_READ else (BLOCK, f"`systemctl {verb}` changes service state")
    if cmd == "service":
        if args == ["--status-all"] or (len(nonopt) == 2 and nonopt[1] == "status" and len(args) == 2):
            return None
        return BLOCK, "`service` other than status"
    if cmd == "journalctl":
        return (BLOCK, "`journalctl` that deletes, rotates or writes files") if any(
            a.startswith(JOURNAL_WRITE) for a in args) else None
    if cmd == "suricatasc":
        cmds = [args[i + 1] for i, a in enumerate(args) if a in ("-c", "--command") and i + 1 < len(args)]
        cmds += [a.split("=", 1)[1] for a in args if a.startswith("--command=")]
        cmds += [a[2:] for a in args if a.startswith("-c") and len(a) > 2 and not a.startswith("--")]
        if not cmds:
            return ASK, "interactive suricatasc"
        bad = [c for c in cmds if (c.split() or [""])[0] not in SURICATASC_READ]
        return (BLOCK, f"suricatasc `{bad[0]}` is not read-only") if bad else None
    if cmd == "suricata":
        if set(args) <= SURICATA_INFO:
            return None
        rest = [a for a in args if a not in ("-T", "-v", "-vv")]
        if "-T" in args and len(rest) % 2 == 0 and set(rest[::2]) <= {"-c", "-S"} and \
                all(v.startswith(("/etc/suricata/", "/var/lib/suricata/")) and ".." not in v for v in rest[1::2]):
            return None
        return BLOCK, "running Suricata beyond -V/--build-info or `-T -c <yaml>`"
    if cmd == "ip":
        opts = [a for a in args if a.startswith("-")]
        obj = nonopt[0] if nonopt else ""
        known = obj and any(o.startswith(obj) for o in IP_OBJECTS) and obj not in ("help",)
        verb = nonopt[1] if len(nonopt) > 1 else "show"
        if known and set(opts) <= IP_READ_OPTS | OPTION_ARGS["ip"] and verb in IP_READ_VERBS:
            return None
        if not known and set(nonopt) & {"exec", "add", "del", "delete", "set", "flush", "attach", "identify"}:
            return BLOCK, "`ip` that changes or enters namespaces"
        if not set(opts) <= IP_READ_OPTS | OPTION_ARGS["ip"] or (known and verb not in IP_READ_VERBS and
                                                                    not re.match(r"^(?:dev|[\w.@-]+\d)$", verb)):
            return BLOCK, "`ip` that changes interfaces, routes or namespaces (iproute2 accepts abbreviations)"
        return ASK, "unusual `ip` form"
    if cmd == "ethtool":
        opts = [a for a in args if a.startswith("-")]
        return None if set(opts) <= ETHTOOL_READ and len(nonopt) <= 1 else (BLOCK, "`ethtool` that changes NIC settings")
    if cmd == "dpkg":
        if any(DPKG_WRITE.match(a) for a in args):
            return BLOCK, "`dpkg` that changes packages"
        return None if args and args[0] in ("-l", "--list", "-s", "--status", "-L", "--listfiles", "-S", "--search",
                                              "-p", "--print-avail") else (ASK, "unusual `dpkg` form")
    if cmd == "rpm":
        ok = all(re.match(r"^-q[ailfcdRs]*$", a) or a in ("--query", "--qf", "--queryformat") or not a.startswith("-")
                 for a in args) and any(a.startswith(("-q", "--query")) for a in args)
        return None if ok else (BLOCK, "`rpm` that changes packages")
    if cmd == "find":
        return (BLOCK, "`find` that deletes, executes or writes") if set(args) & FIND_ACTIONS else None
    if cmd == "sed":
        if any(a.startswith("--in-place") or a == "--file" or re.match(r"^-[A-Za-z]*[if]", a) for a in args):
            return BLOCK, "`sed` in-place edit or script file"
        scripts = [args[i + 1] for i, a in enumerate(args) if a in ("-e", "--expression") and i + 1 < len(args)]
        scripts = scripts or nonopt[:1]
        return None if scripts and all(SAFE_SED.match(s) for s in scripts) else (ASK, "`sed` script beyond p/q/s")
    if cmd in ("awk", "gawk", "mawk"):
        prog = " ".join(args)  # -v c='rm /x' then system(c): the command can hide in any argument
        if any(a in ("-f", "-i", "--include", "-E", "--exec", "--file", "-l", "--load") or
               short_flags(a) & {"i", "l"} for a in args) or re.search(r"@include|@load|inplace|writea", prog):
            return BLOCK, f"`{cmd}` with a program file, extension or in-place edit"
        if re.search(r"printf?[^;}]*>", prog):
            return BLOCK, f"`{cmd}` program writes a file"
        if re.search(r"system|getline|\||fflush|close", prog):
            return complex_verdict(prog, f"`{cmd}` program may run commands or write")
        return None
    if cmd == "sort":
        return (BLOCK, "`sort -o/--compress-program` writes a file or runs a program") if any(
            a.startswith(("--output", "--compress-program")) or "o" in short_flags(a) for a in args) else None
    if cmd == "uniq":
        return None if len(nonopt) <= 1 else (BLOCK, "`uniq IN OUT` writes a file")
    if cmd in ("diff", "cmp"):
        return (BLOCK, "`diff --output` writes a file") if any(a.startswith("--output") for a in args) else None
    if cmd == "date":
        bad = any(a.startswith("--set") or "s" in short_flags(a) for a in args) or \
            any(not a.startswith("+") for a in nonopt)
        return (BLOCK, "`date -s` sets the clock") if bad else None
    if cmd == "hostname":
        return None if set(args) <= {"-f", "-i", "-I", "-s", "-d", "-A", "--fqdn", "--short"} else (
            BLOCK, "`hostname NAME` renames the sensor")
    if cmd in ("ss", "netstat"):
        return (BLOCK, "`ss -K` kills sockets") if any(a == "--kill" or "K" in short_flags(a) for a in args) else None
    if cmd in PLAIN_READ:
        return None
    return ASK, f"`{cmd}` is not on the sensor read-only list"


def bounding_stage(argv):
    """True if this stage limits or aggregates what comes back: head/tail with a small count, wc, grep -c, ..."""
    _, argv = strip_assignments(strip_keywords(argv)[0])
    argv, _ = strip_remote_wrappers(argv)
    if not argv:
        return False
    cmd, args = os.path.basename(argv[0]), argv[1:]
    if cmd in BOUNDING:
        return True
    if cmd in ("head", "tail"):
        if "-f" in args or "-F" in args or "--follow" in args:
            return False
        counts = [args[k + 1] for k, a in enumerate(args) if a in ("-n", "-c", "--lines", "--bytes") and k + 1 < len(args)]
        counts += [a[2:] for a in args if re.match(r"^-[nc]\d", a)] + [a[1:] for a in args if re.match(r"^-\d+$", a)]
        limit = 1000
        return bool(counts) and all(re.fullmatch(r"\d+", c) and int(c) <= (limit if "-c" not in args else 65536)
                                    for c in counts) or (not counts and cmd == "head")
    if cmd in ("grep", "zgrep") and any(a in ("-c", "--count", "-l", "-q") or short_flags(a) & {"c", "l", "q"}
                                        for a in args):
        return True
    return cmd == "uniq" and any("c" in short_flags(a) or a == "--count" for a in args)


def bounded(pipe):
    """The last bounding stage of a pipeline may only be followed by stages that transform, not expand."""
    last = max((k for k, argv in enumerate(pipe) if bounding_stage(argv)), default=None)
    if last is None:
        return False
    for argv in pipe[last + 1:]:
        argv, _ = strip_remote_wrappers(strip_assignments(argv)[1])
        cmd = os.path.basename(argv[0]) if argv else ""
        if not (cmd in TRANSFORM or (cmd.startswith("python") and argv[1:3] == ["-m", "json.tool"])):
            return False
    return True


def is_snapshot_form(args):
    """`python3 [-I] - --days N --logdir X --pattern X --work-hours X` (tools/snapshot.sh)."""
    i = 2 if args[:2] == ["-I", "-"] else 1 if args[:1] == ["-"] else 0
    rest = args[i:]
    return bool(i) and len(rest) % 2 == 0 and set(rest[::2]) <= {"--days", "--logdir", "--pattern", "--work-hours"} \
        and all(not v.startswith("-") for v in rest[1::2])


def stdin_is_snapshot(stdin, project, cwd):
    if not stdin or stdin in ("pipe", "multiple", "heredoc") or not project:
        return False
    path = pathlib.Path(stdin)
    path = path if path.is_absolute() else pathlib.Path(cwd or project) / path
    return os.path.normpath(path) == os.path.normpath(pathlib.Path(project) / "tools" / "sensor_snapshot.py")


def sensor_write(why, approved):
    if approved:
        return ASK, f"sensor change for card {approved}: {why} - confirm this exact command"
    return BLOCK, (f"sensor is read-only: {why}. Changes go through the sensor-change skill (backup, test, "
                   "rollback) and an explicit yes; prefix the reviewed command with SENSOR_CHANGE=<card-id>.")


def complex_verdict(text, why):
    """A sensor reference the guard cannot parse exactly: a write verb anywhere -> block, else ask."""
    words = {os.path.basename(w) for w in re.split(r"[\s'\";|&(){}`$<>=,\[\]]+", text) if w}
    hits = sorted(words & REMOTE_WRITE)
    if re.search(r"\bsudo\s+(?:-\w*[is]\w*\b|--login|--shell)|\bsudo\s*['\"]?\s*(?:<|$)", text):
        hits.append("sudo shell")
    if re.search(r"(?:^|[\s'\"])-m\s+['\"]?(?:shell|command|raw|copy|file|script|lineinfile|template|service|systemd)",
                 text):
        hits.append("ansible module that changes the host")
    if hits:
        return BLOCK, f"{why}, with write verbs {hits} - run one plain read-only ssh command instead"
    return ASK, f"{why} - the guard cannot verify it is read-only"


def check_remote(remote, stdin, approved, ctx, project, cwd, depth=0):
    """Command string that runs on the sensor. stdin: None, 'pipe', 'heredoc', 'multiple' or a local file."""
    if depth > 3:
        return [(BLOCK, "remote command nested too deeply to analyse")]
    if re.search(r"[<>]\(|`|\$\(|<<", remote):
        return [complex_verdict(remote, "remote command uses substitution or a here-document")]
    try:
        segments = split_commands(remote)
    except ValueError:
        return [(BLOCK, f"remote command could not be parsed: {remote!r}")]
    verdicts, snapshot = [], False
    for argv, piped in segments:
        argv, keywords = strip_keywords(argv)
        if keywords:
            return [complex_verdict(remote, "remote shell control flow (loop, if, subshell)")]
        assigns, argv = strip_assignments(argv)
        odd_env = [k for k in assigns if not SAFE_REMOTE_ENV.match(k)]
        argv, root_shell = strip_remote_wrappers(argv)
        if root_shell:
            verdicts.append(sensor_write(root_shell, approved))
            continue
        if not argv or argv[0].startswith("$"):
            verdicts.append(sensor_write("interactive or variable shell on the sensor", approved))
            continue
        if os.path.basename(argv[0]) == "busybox" and len(argv) > 1:
            argv = argv[1:]
        cmd, args = os.path.basename(argv[0]), argv[1:]
        why = ask = None
        if odd_env:
            ask = f"environment {odd_env} changes what `{cmd}` loads"
        if cmd in SHELLS:
            flag = next((a for a in args if "c" in short_flags(a)), None)
            if flag and args.index(flag) + 1 < len(args):
                verdicts += check_remote(args[args.index(flag) + 1], None, approved, ctx, project, cwd, depth + 1)
                continue
            if stdin or piped:
                why = "text fed into a remote shell"
            else:
                ask = f"remote `{cmd}` script"
        elif cmd in INTERPRETERS:
            if cmd.startswith("python") and len(segments) == 1 and is_snapshot_form(args) and not odd_env and \
                    stdin_is_snapshot(stdin, project, cwd) and not redirects(argv):
                snapshot = True
                continue  # the reviewed, read-only snapshot script (tools/snapshot.sh)
            if cmd.startswith("python") and args[:2] == ["-m", "json.tool"] and len(args) <= 3 and not odd_env:
                continue
            if stdin or piped:
                why = f"text fed into a remote `{cmd}` (only tools/sensor_snapshot.py via stdin is approved)"
            else:
                ask = f"`{cmd}` code on the sensor"
        elif cmd == "xargs":
            k = 0
            while k < len(args) and args[k].startswith("-"):
                k += 2 if args[k] in ("-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a") else 1
            inner = " ".join(shlex.quote(a) for a in args[k:]) or "echo"
            verdicts += check_remote(inner, None, approved, ctx, project, cwd, depth + 1)
            continue
        elif cmd in REMOTE_WRITE:
            why = f"`{cmd}` changes the sensor"
        else:
            res = remote_read_check(cmd, args)
            if res:
                why, ask = (res[1], ask) if res[0] == BLOCK else (None, res[1])
        for op, target in redirects(argv):
            if target not in SAFE_REDIRECT:
                why = f"redirect `{op} {target}` writes on the sensor"
        if why:
            verdicts.append(sensor_write(why, approved))
        elif ask:
            verdicts.append((ASK, f"{ask} - confirm it only reads"))
    if not snapshot:
        for pipe in pipelines(segments):
            text = " ".join(" ".join(a) for a in pipe)
            if ctx.raw_telemetry(text) and not bounded(pipe):
                verdicts.append((ASK, "unbounded read of raw telemetry - it must stay on the sensor; end the "
                                      "pipeline with head -n N (<= 1000), wc, grep -c or sort | uniq -c"))
    return verdicts


# ---------- local ----------

def check_ssh(argv, stdin, approved, ctx, project, cwd):
    args, i, verdicts = argv[1:], 0, []
    while i < len(args) and args[i].startswith("-"):
        opt = args[i]
        if opt == "--":
            i += 1
            break
        if opt.startswith("-o"):
            value = opt[2:] or (args[i + 1] if i + 1 < len(args) else "")
            key = re.split(r"[=\s]", value, 1)[0].lower()
            if key not in SAFE_SSH_OPTIONS:
                verdicts.append((ASK, f"ssh option `-o {value}`"))
            i += 1 if opt[2:] else 2
        elif short_flags(opt) and short_flags(opt) <= SAFE_SSH_FLAGS:
            i += 1
        elif opt in SAFE_SSH_ARG_FLAGS:
            i += 2
        else:
            verdicts.append((ASK, f"ssh option `{opt}` (proxy, forwarding, config or command)"))
            i += 2 if len(opt) == 2 and opt[1] in SSH_ARG_FLAGS else 1
    if i >= len(args):
        return [(BLOCK, "ssh without a host")]
    rest = args[i + 1:]
    while rest and rest[0].startswith("-"):  # OpenSSH also parses options after the host
        if rest[0] == "--":
            rest = rest[1:]
            break
        verdicts.append((ASK, f"ssh option `{rest[0]}` after the host"))
        rest = rest[2:] if rest[0] in ("-o", "-i", "-p", "-l", "-F", "-L", "-R", "-D", "-J") else rest[1:]
    remote = []
    for a in rest:
        if a in ("<", "0<", ">", ">>", "2>", "2>>", "&>", "<<", "<<<", "<<-"):
            break
        remote.append(a)
    if not remote:
        verdicts.append(sensor_write("shell on the sensor fed from stdin", approved) if stdin else
                        (BLOCK, "interactive ssh session - run one bounded read-only command instead"))
        return verdicts
    return verdicts + check_remote(" ".join(remote), stdin, approved, ctx, project, cwd)


def check_copy(cmd, args, approved):
    if cmd == "sftp":
        if any(a == "-b" or a.startswith("-b") for a in args):
            return [sensor_write("sftp batch file", approved)]
        return [(ASK, "sftp session - files must not be copied onto or off the sensor without review")]
    if any(a.startswith(("--rsync-path", "--remove-source-files", "--delete")) for a in args):
        return [sensor_write(f"`{cmd}` runs a command or deletes files on the remote side", approved)]
    hosts = [a for a in args if re.match(r"^[^/\s]*[^/\s:]::?", a) and not a.startswith("-")]
    if any(re.search(r"[;|&`$]|\$\(", h) for h in hosts):
        return [sensor_write(f"`{cmd}` remote path with shell metacharacters", approved)]
    if any(a.startswith(("-o", "--rsh")) or a in ("-F", "-e", "-S") or re.match(r"^-\w*e$", a) for a in args):
        return [(ASK, f"`{cmd}` with custom ssh options or command")]
    if not hosts:
        return []
    paths = [a for a in args if not a.startswith("-")]
    if paths and paths[-1] in hosts:
        return [sensor_write(f"`{cmd}` copies files onto the sensor", approved)]
    return [(ASK, f"`{cmd}` copies files off the sensor - raw telemetry must stay there; aggregates only")]


def git_verdicts(argv):
    assigns, argv = strip_assignments(argv)
    out = []
    if {"GIT_SSH_COMMAND", "GIT_SSH", "GIT_EXEC_PATH"} & set(assigns):
        out.append((ASK, "git with a custom ssh or exec command"))
    args, i = argv[1:], 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-c" and i + 1 < len(args):
            key = args[i + 1].split("=", 1)[0].lower()
            if key.startswith("alias.") or key in ("core.sshcommand", "core.hookspath", "core.pager", "core.editor"):
                out.append((ASK, f"git -c {key} can run arbitrary commands"))
            i += 2
        elif args[i] in ("-C", "--git-dir", "--work-tree", "--namespace", "--exec-path"):
            i += 2
        else:
            i += 1
    sub = args[i] if i < len(args) else ""
    if sub in GIT_ASK or (sub == "reset" and "--hard" in args):
        out.append((ASK, f"`git {sub}` needs the user's explicit yes"))
    return out


def gh_verdicts(args):
    rest, i = [], 0
    while i < len(args):
        if args[i] in ("-R", "--repo", "--hostname"):
            i += 2
        else:
            if not args[i].startswith(("--repo=", "--hostname=")):
                rest.append(args[i])
            i += 1
    words = [a for a in rest if not a.startswith("-")]
    group, sub = (words + ["", ""])[:2]
    if (group, sub) in GH_ASK or group in GH_ASK_GROUPS:
        return [(ASK, f"`gh {group} {sub}` is outward-facing - needs the user's explicit yes")]
    if group == "api":
        method = next((rest[k + 1] for k, a in enumerate(rest) if a in ("-X", "--method") and k + 1 < len(rest)),
                      next((a.split("=", 1)[1] for a in rest if a.startswith("--method=")), "GET"))
        if method.upper() != "GET" or set(rest) & {"-f", "-F", "--field", "--raw-field", "--input"}:
            return [(ASK, f"`gh api` {method.upper()} with fields changes GitHub state")]
    return []


def upload_verdicts(cmd, args):
    out = []
    for k, a in enumerate(args):
        flag, _, inline = a.partition("=") if a.startswith("--") else (a, "", "")
        if flag not in UPLOAD_FLAGS:
            continue
        value = inline or (args[k + 1] if k + 1 < len(args) else "")
        if "@" in value:
            src = value.split("@", 1)[1]
        elif flag in ("-T", "--upload-file", "-K", "--config", "--post-file", "--body-file"):
            src = value
        else:
            continue
        if src == "-" or norm_rel(src).startswith(SENSITIVE_PATHS):
            out.append((BLOCK, f"`{cmd}` uploads {'stdin' if src == '-' else src} - telemetry and inventory stay here"))
        else:
            out.append((ASK, f"`{cmd}` uploads the file {src}"))
    return out


def write_targets(cmd, args, argv):
    """Local files this simple command writes to."""
    out = [t for _, t in redirects(argv)]
    paths = [a for a in args if not a.startswith("-")]
    if cmd == "tee":
        out += paths
    elif cmd in ("cp", "mv", "install", "ln", "rsync") and paths:
        out.append(paths[-1])
    elif cmd == "dd":
        out += [a[3:] for a in args if a.startswith("of=")]
    elif cmd in ("sed", "perl") and any(re.match(r"^-[A-Za-z]*i", a) or a.startswith("--in-place") for a in args):
        out += paths[1:]
    elif cmd in ("rm", "truncate", "chmod", "touch"):
        out += paths
    return out


def remote_exec_tool(cmd, args):
    if REMOTE_EXEC.match(cmd):
        return True
    return cmd in REMOTE_EXEC_SUB and REMOTE_EXEC_SUB[cmd] in args


def check_bash(command, ctx, project, cwd):
    analysed = strip_heredocs(command)
    try:
        segments = split_commands(analysed)
    except ValueError as e:
        return [(ASK, f"command could not be parsed ({e}) - confirm it")]
    verdicts, executors = [], []
    writes = "<<" in command
    changes_dir = False
    for argv, piped in segments:
        argv, keywords = strip_keywords(argv)
        full = argv
        assigns, argv = strip_assignments(argv)
        if not argv:
            continue
        approved = assigns.get("SENSOR_CHANGE")
        cmd, args = os.path.basename(argv[0]), argv[1:]
        if cmd == "timeout" and not keywords:  # `timeout 60 ssh ...` is still a plain ssh
            k = 0
            while k < len(args) and (args[k].startswith("-") or re.match(r"^\d", args[k])):
                k += 2 if args[k] in ("-s", "--signal", "-k", "--kill-after") else 1
            if k < len(args) and args[k] in PLAIN_SENSOR_TOOLS:
                argv = args[k:]
                cmd, args = argv[0], argv[1:]
        seg_text = " ".join(argv)
        changes_dir = changes_dir or cmd in ("cd", "pushd", "popd")
        writes = writes or bool(redirects(argv)) or cmd in ("tee", "dd", "cp", "mv", "install") or (
            cmd == "sed" and any(re.match(r"^-[A-Za-z]*i", a) or a.startswith("--in-place") for a in args))
        private_ip = any(_private(_norm_ip(ip)) for ip in IPV4.findall(seg_text))
        if cmd in PLAIN_SENSOR_TOOLS and not keywords:
            stdins = stdin_sources(argv)
            stdin = "pipe" if piped else ("multiple" if len(stdins) > 1 else stdins[0] if stdins else None)
            if changes_dir and stdin not in (None, "pipe", "heredoc", "multiple"):
                stdin = "moved"  # after cd, a relative stdin path no longer means the project's file
            if cmd == "ssh":
                verdicts += check_ssh(argv, stdin, approved, ctx, project, cwd)
            else:
                verdicts += check_copy(cmd, args, approved)
                if cmd == "sftp" and (piped or stdins):
                    verdicts.append(sensor_write("sftp commands fed from stdin", approved))
        elif cmd == "ssh-copy-id":
            verdicts.append(sensor_write("`ssh-copy-id` changes authorized keys on the remote host", approved))
        elif remote_exec_tool(cmd, args):
            verdicts.append(complex_verdict(seg_text, f"`{cmd}` runs commands on a remote host"))
        elif cmd in PLAIN_SENSOR_TOOLS or (keywords and ctx.mentions_sensor(seg_text)):
            executors.append(seg_text)
        elif (cmd in EXECUTORS or "$" in argv[0]) and (ctx.mentions_sensor(seg_text) or private_ip):
            executors.append(seg_text)
        elif piped and cmd in INTERPRETERS and ctx.mentions_sensor(analysed):
            executors.append(seg_text)  # `... | bash` runs whatever the previous segment printed
        if cmd == "git":
            verdicts += git_verdicts(full)
        if cmd == "gh":
            verdicts += gh_verdicts(args)
        if cmd in EGRESS:
            verdicts += upload_verdicts(cmd, args)
        if cmd in EGRESS or cmd == "gh" or (cmd in INTERPRETERS and EGRESS_TEXT.search(seg_text)) or \
                EGRESS_TEXT.search(" ".join(argv[:1])):
            leaked = ctx.internal_identifiers(seg_text)
            if leaked:
                verdicts.append((BLOCK, f"internal identifiers {leaked} would leave for the web or an external service"))
        if any(p in t for t in write_targets(cmd, args, argv) for p in PROTECTED) or (
                cmd in INTERPRETERS and any(p in analysed for p in PROTECTED)):
            verdicts.append((ASK, "this changes the guard, its registration or a script it trusts - confirm"))
    if executors:
        verdicts.append(complex_verdict(analysed, "sensor reference inside a loop, subshell, wrapper or interpreter"))
    if writes:
        verdicts += [(BLOCK, f"writing a {what} into a file - secrets never go into files")
                     for _, what in secrets_in(command)]
        if re.search(r"(?i)(?:passw(?:or)?d|passwd|secret|token|api[_-]?key|cred)\w*['\"]?\s*[:=]\s*['\"]?(?:%s|\$)",
                     command):
            verdicts.append((ASK, "a credential from a variable or argument is written into a file"))
    return verdicts


def secrets_in(text):
    found = [(m.group(0)[:12] + "...", what) for rx, what in SECRET_PATTERNS for m in rx.finditer(text)]
    for m in CRED_KEY.finditer(text):
        value = next(g for g in m.groups() if g is not None).strip()
        if len(value) >= 6 and not PLACEHOLDER.match(value) and not re.search(r"[()\[\]]", value):
            found.append((m.group(0)[:12] + "...", "credential assignment"))
    return found


# ---------- other tools ----------

def check_file_write(tool_input, project):
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    texts = [tool_input.get(k, "") for k in ("content", "new_string", "new_source")]
    texts += [e.get("new_string", "") for e in tool_input.get("edits") or []]
    found = {what for t in texts for _, what in secrets_in(t)}
    out = [(BLOCK, f"{what} in {path} - secrets never go into files (ssh uses keys/agent, SIEM queries are "
                   "run by the user)") for what in sorted(found)]
    rel = norm_rel(os.path.relpath(path, project) if project and os.path.isabs(path) else path)
    if rel.startswith(PROTECTED) or any(rel.endswith("/" + p) for p in PROTECTED if not p.endswith("/")):
        out.append((ASK, f"{rel} is the guard, its registration or a script it trusts - confirm this change"))
    return out


def check_web(tool_input, ctx):
    keys = ("url", "query", "prompt", "allowed_domains", "blocked_domains")
    text = " ".join(json.dumps(tool_input.get(k, "")) for k in keys)
    leaked = ctx.internal_identifiers(text)
    return [(BLOCK, f"internal identifiers {leaked} must not be sent to web search or external services")] if leaked else []


REQUIRED = {"Bash": ["command"], "Write": ["file_path", "content"], "Edit": ["file_path", "new_string"],
            "MultiEdit": ["file_path"], "NotebookEdit": ["new_source"], "WebFetch": ["url"], "WebSearch": ["query"]}


def invalid_input(tool_name, tool_input):
    """Types Claude Code sends for these tools; anything else is not analysable -> block."""
    if not isinstance(tool_input, dict):
        return "tool_input is not an object"
    for key in REQUIRED[tool_name]:
        if not isinstance(tool_input.get(key), str):
            return f"{key} is missing or not a string"
    for key in ("content", "new_string", "new_source", "prompt"):
        if key in tool_input and not isinstance(tool_input[key], str):
            return f"{key} is not a string"
    edits = tool_input.get("edits")
    if edits is not None and not (isinstance(edits, list) and all(
            isinstance(e, dict) and isinstance(e.get("new_string", ""), str) for e in edits)):
        return "edits is not a list of objects with a string new_string"
    return None


def decide(tool_name, tool_input, ctx, project="", cwd=None):
    """Pure decision function: (decision, [reasons])."""
    if tool_name not in REQUIRED:
        return ALLOW, []
    bad = invalid_input(tool_name, tool_input)
    if bad:
        return BLOCK, [f"unexpected input for {tool_name}: {bad}"]
    if tool_name == "Bash":
        verdicts = check_bash(tool_input["command"], ctx, project, cwd or project)
    elif tool_name in ("WebFetch", "WebSearch"):
        verdicts = check_web(tool_input, ctx)
    else:
        verdicts = check_file_write(tool_input, project)
    if not verdicts:
        return ALLOW, []
    top = max(RANK[v] for v, _ in verdicts)
    decision = [d for d, r in RANK.items() if r == top][0]
    return decision, list(dict.fromkeys(r for v, r in verdicts if v == decision))


def main():
    event = json.load(sys.stdin)
    if not isinstance(event, dict):
        raise ValueError("hook input is not a JSON object")
    project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
    ctx = Context.load(project)
    decision, reasons = decide(event.get("tool_name", ""), event.get("tool_input"), ctx, project,
                               event.get("cwd") or project)
    if decision == BLOCK:
        print("guard: blocked - " + "; ".join(reasons), file=sys.stderr)
        return 2
    if decision == ASK:
        note = f" ({ctx.warning})" if ctx.warning else ""
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                 "permissionDecisionReason": "guard: " + "; ".join(reasons) + note}}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # fail closed: a broken guard must not wave calls through
        print(f"guard: internal error, call blocked (fail closed): {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
