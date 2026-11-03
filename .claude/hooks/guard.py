#!/usr/bin/env python3
"""PreToolUse guard: turns the kit's safety rules (docs/SAFETY.md) from advice into enforcement.

Decisions, strongest wins:
  block - exit 2, reason on stderr (Claude sees it and must change course)
  ask   - the user confirms in Claude Code's permission prompt
  allow - silent exit 0

What it enforces:
  - the sensor is read-only over ssh: write/restart/install verbs, redirects, piping a script into a remote
    interpreter and copying files to the sensor are blocked; a reviewed change prefixed with
    SENSOR_CHANGE=<card-id> (the sensor-change skill) is routed to the user instead;
  - commit / push / merge request / visibility changes need the user (ask);
  - internal identifiers (RFC 1918 addresses, inventory hostnames, the sensor) never go to the web;
  - secrets (tokens, passwords, private keys) are never written into files.

Fail closed: any internal error blocks the call. The guard reads the command line Claude runs - it is a
seatbelt, not a sandbox; the boundary on the sensor is the read-only account (docs/SAFETY.md)."""
import ipaddress
import json
import os
import pathlib
import re
import shlex
import sys

BLOCK, ASK, ALLOW = "block", "ask", "allow"
RANK = {ALLOW: 0, ASK: 1, BLOCK: 2}

WRAPPERS = {"sudo", "nohup", "time", "env", "command", "exec", "nice", "timeout", "stdbuf"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
INTERPRETERS = SHELLS | {"python", "python3", "perl", "ruby", "node", "php"}
REMOTE_WRITE = {"rm", "rmdir", "mv", "cp", "tee", "dd", "truncate", "install", "ln", "mkdir", "touch", "chmod",
                "chown", "chgrp", "kill", "pkill", "killall", "reboot", "shutdown", "halt", "poweroff", "crontab",
                "useradd", "usermod", "userdel", "passwd", "tcpreplay", "suricata-update", "curl", "wget", "scp",
                "rsync", "shred", "unlink", "patch", "logrotate", "vi", "vim", "nano", "ed", "emacs", "tar",
                "unzip", "gzip", "gunzip", "bzip2", "xz", "iptables", "nft", "ifconfig", "mount",
                "umount", "modprobe", "sysctl", "visudo", "git"}
# Remote allowlist: read-only commands an agent needs for facts and aggregates. Anything that is neither
# here nor a known write is unknown -> ask the user (a denylist alone never ends).
REMOTE_READ = {"cat", "zcat", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "wc", "ls", "stat", "find", "awk",
               "gawk", "sed", "sort", "uniq", "cut", "tr", "jq", "column", "df", "du", "free", "uptime", "date",
               "hostname", "id", "whoami", "uname", "ps", "pgrep", "ss", "netstat", "test", "[", "echo", "printf",
               "true", "md5sum", "sha256sum", "file", "readlink", "realpath", "dirname", "basename", "which",
               "systemctl", "service", "journalctl", "suricatasc", "suricata", "xargs", "dpkg-query", "lsof",
               "nproc", "lscpu", "ip", "ethtool", "comm", "diff", "tac", "nl", "dpkg", "rpm"}
ETHTOOL_WRITE = {"-s", "-A", "-C", "-E", "-G", "-K", "-L", "-N", "-U", "-W", "-X", "-f", "-r", "-p", "--flash",
                 "--reset"}  # -S/-T/-P/-i/-k/-g read
SURICATA_READ = {"-V", "--build-info", "-T", "--list-keywords", "--list-app-layer-protos", "--dump-config"}
SERVICE_READ = {"status", "is-active", "is-enabled", "is-failed", "show", "cat", "list-units", "list-timers"}
PKG_WRITE = {"install", "remove", "purge", "upgrade", "update", "erase", "reinstall", "autoremove", "dist-upgrade"}
SURICATASC_READ = {"version", "uptime", "running-mode", "capture-mode", "dump-counters", "iface-list",
                   "iface-stat", "memcap-list", "ruleset-stats", "ruleset-failed-rules", "help"}
EGRESS = {"curl", "wget", "http", "https", "httpie", "nc", "ncat", "netcat", "telnet", "ftp", "aria2c"}
SSH_OPTS_WITH_ARG = set("BbcDEeFIiJLlmOoPpQRSWw")
GIT_OPTS_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
SAFE_REDIRECT = {"/dev/null", "/dev/stderr", "/dev/stdout"}

SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"(?i)authorization:\s*(?:basic|bearer)\s+[A-Za-z0-9+/=._-]{12,}"), "HTTP credentials"),
    (re.compile(r"(?i)\b[\w-]*(?:passw(?:or)?d|passwd|secret|token|api[_-]?key)[\w-]*\s*[:=]\s*"
                r"[\"']?(?![\"']?(?:\$|<|\{|changeme|example|placeholder|xxx|\*{3}))[^\s\"']{8,}"), "credential assignment"),
]
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]  # RFC 1918 - lab-data: allow
IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.]*\d)")
HOSTNAME = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]*\b", re.I)


class Context:
    """Environment-specific identifiers: the sensor host and inventory names (both git-ignored files)."""

    def __init__(self, sensor_host="", internal_names=()):
        self.sensor_host = sensor_host
        self.internal_names = {n.lower() for n in internal_names if n}

    @classmethod
    def load(cls, project_dir):
        root = pathlib.Path(project_dir)
        sensor, names = "", set()
        env = root / "config" / "environment.env"
        if env.is_file():
            for tok in shlex.split(env.read_text(), comments=True):
                key, _, value = tok.partition("=")
                if key == "SENSOR_SSH":
                    sensor = value.rsplit("@", 1)[-1]
        hosts = root / "inventory" / "hosts.md"
        if hosts.is_file():
            names = {h for h in HOSTNAME.findall(hosts.read_text()) if not h.lower().endswith((".md", ".env"))}
        names.add(sensor)
        return cls(sensor, names)

    def internal_identifiers(self, text):
        found = [ip for ip in IPV4.findall(text) if _private(ip)]
        low = text.lower()
        found += [n for n in self.internal_names
                  if re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", low)]
        found += [h for h in HOSTNAME.findall(low) if h.endswith((".local", ".internal", ".corp", ".lan"))]
        return sorted(set(found))


def _private(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in PRIVATE_NETS)


# ---------- shell parsing ----------

def split_commands(command):
    """Shell command line -> list of simple commands (token lists), split on ; && || | & and newlines.
    Command substitutions $(...) and `...` are pulled out and analysed as commands of their own."""
    subs = re.findall(r"\$\(([^()]*)\)|`([^`]*)`", command)
    lex = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=";&|<>")
    lex.whitespace_split = True
    lex.commenters = ""
    segments, cur = [], []
    for tok in lex:
        if tok in (";", "&&", "||", "|", "&", ";;", "|&"):
            if cur:
                segments.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        segments.append(cur)
    for a, b in subs:
        segments += split_commands(a or b)
    return segments


def strip_prefix(argv):
    """Drop VAR=value assignments and wrappers (sudo -n, env, timeout 5 ...). Returns (assignments, argv)."""
    assigns, i = {}, 0
    while i < len(argv):
        tok = argv[i]
        if "=" in tok and re.match(r"^[A-Za-z_]\w*=", tok):
            k, _, v = tok.partition("=")
            assigns[k] = v
            i += 1
        elif os.path.basename(tok) in WRAPPERS:
            i += 1
            while i < len(argv) and (argv[i].startswith("-") or (os.path.basename(argv[i - 1]) == "timeout"
                                                                  and re.match(r"^\d", argv[i]))):
                i += 2 if argv[i] in ("-u", "-g", "-C", "-p") else 1
        else:
            break
    return assigns, argv[i:]


def redirects(argv):
    """[(operator, target)] for output redirects in a token list."""
    out = []
    for i, tok in enumerate(argv):
        if set(tok) <= set("><&") and ">" in tok:
            target = argv[i + 1] if i + 1 < len(argv) else ""
            if not tok.endswith("&") and not target.startswith("&"):
                out.append((tok, target.lstrip("&")))
    return out


def stdin_source(argv):
    for i, tok in enumerate(argv):
        if tok == "<" and i + 1 < len(argv):
            return argv[i + 1]
    return None


def _git_subcommand(args):
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in GIT_OPTS_WITH_ARG else 1
    return args[i] if i < len(args) else ""


# ---------- rules ----------

def check_remote(remote, local_argv, ctx, approved):
    """Command that runs on the sensor. Read-only is allowed; anything else is blocked or, with an
    approved change marker, routed to the user."""
    verdicts = []
    try:
        segments = split_commands(remote)
    except ValueError:
        return [(BLOCK, f"remote command could not be parsed: {remote!r}")]
    for seg in segments:
        _, argv = strip_prefix(seg)
        if not argv:
            continue
        why, unknown = remote_write_reason(argv, local_argv), None
        cmd, args = os.path.basename(argv[0]), argv[1:]
        if why == "approved-snapshot":
            continue  # the reviewed, read-only snapshot script (tools/snapshot.sh)
        if cmd == "xargs":
            rest = [a for a in args if not a.startswith("-")]
            verdicts += check_remote(" ".join(shlex.quote(a) for a in rest), local_argv, ctx, approved) if rest else []
        elif not why and cmd not in REMOTE_READ:
            unknown = f"`{cmd}` is not on the sensor read-only list"
        for op, target in redirects(argv):
            if target not in SAFE_REDIRECT:
                why = f"redirect `{op} {target}` writes on the sensor"
        if unknown and not why:
            verdicts.append((ASK, f"{unknown} - confirm it only reads"))
        if why:
            if approved:
                verdicts.append((ASK, f"sensor change for card {approved}: {why} - confirm this exact command"))
            else:
                verdicts.append((BLOCK, f"sensor is read-only: {why}. Changes go through the sensor-change skill "
                                        "(backup, test, rollback) and an explicit yes; prefix the reviewed command "
                                        "with SENSOR_CHANGE=<card-id> to ask the user."))
    return verdicts


def remote_write_reason(argv, local_argv):
    """Why this remote simple command changes the sensor, or None."""
    cmd, args = os.path.basename(argv[0]), argv[1:]
    joined = " ".join(args)
    if cmd in REMOTE_WRITE:
        return f"`{cmd}` changes the sensor"
    if cmd in ("systemctl", "service") and not (set(args) & SERVICE_READ):
        return f"`{cmd} {joined}` changes service state"
    if cmd in ("apt", "apt-get", "dnf", "yum", "pip", "pip3", "snap", "rpm", "dpkg") and \
            set(args) & (PKG_WRITE | {"-i", "-U", "-e", "--install", "--purge", "-r", "-P"}):
        return "package installation on the sensor"
    if cmd in ("sed", "perl") and any(a == "-i" or a.startswith(("-i", "--in-place")) for a in args):
        return f"in-place edit with `{cmd} -i`"
    if cmd in ("awk", "gawk") and re.search(r"system\s*\(|\|\s*\"|>\s*\"|getline", joined):
        return f"`{cmd}` program runs commands or writes files"
    if cmd == "suricatasc" and not any(a in SURICATASC_READ for a in args):
        return "suricatasc command that is not read-only (reload/shutdown/...)"
    if cmd == "suricata" and not set(args) & SURICATA_READ:
        return "starting a second Suricata instance on the sensor"
    if cmd == "find" and set(args) & {"-delete", "-exec", "-execdir", "-ok", "-fprint", "-fprintf", "-fls"}:
        return "`find` that deletes, executes or writes"
    if cmd == "journalctl" and any(a.startswith(("--vacuum", "--rotate", "--flush", "--relinquish")) for a in args):
        return "`journalctl` that deletes or rotates logs"
    if cmd == "ip" and set(args) & {"set", "add", "del", "delete", "flush", "change", "replace", "append"}:
        return "`ip` that changes interfaces or routes"
    if cmd == "ethtool" and any(a in ETHTOOL_WRITE or a.startswith(("--set", "--change")) for a in args):
        return "`ethtool` that changes NIC settings"
    if cmd in INTERPRETERS and ("-c" in args or "-e" in args):
        return f"inline `{cmd}` code on the sensor"
    if cmd in INTERPRETERS:
        src = stdin_source(local_argv)
        if ("-" in args or "-s" in args or not args) and src and \
                pathlib.PurePath(src).as_posix().endswith("tools/sensor_snapshot.py"):
            return "approved-snapshot"
        return f"`{cmd}` running a script on the sensor (only tools/sensor_snapshot.py via stdin is approved)"
    return None


def check_ssh(argv, ctx, approved):
    args, i = argv[1:], 0
    while i < len(args) and args[i].startswith("-"):
        opt = args[i]
        i += 2 if len(opt) == 2 and opt[1] in SSH_OPTS_WITH_ARG else 1
    if i >= len(args):
        return [(BLOCK, "ssh without a host")]
    remote_tokens = []
    for a in args[i + 1:]:
        if a in ("<", ">", ">>"):
            break  # local redirect of ssh itself, not part of the remote command
        remote_tokens.append(a)
    if not remote_tokens:
        return [(BLOCK, "interactive ssh session - run one bounded read-only command instead")]
    return check_remote(" ".join(remote_tokens), argv, ctx, approved)


def check_copy(cmd, args, approved):
    remote = [a for a in args if re.match(r"^[^/\s]*[^/\s:]:", a) and not a.startswith("-")]
    if not remote:
        return []
    dest = [a for a in args if not a.startswith("-")][-1:]
    if dest and dest[0] in remote:
        verdict = ASK if approved else BLOCK
        return [(verdict, f"`{cmd}` copies files onto the sensor")]
    return [(ASK, f"`{cmd}` copies files off the sensor - raw telemetry must stay there; aggregates only")]


def check_bash(command, ctx, depth=0):
    if depth > 4:
        return [(BLOCK, "command nested too deeply to analyse")]
    try:
        segments = split_commands(command)
    except ValueError as e:
        return [(ASK, f"command could not be parsed ({e}) - confirm it")]
    verdicts = []
    for seg in segments:
        assigns, argv = strip_prefix(seg)
        if not argv:
            continue
        approved = assigns.get("SENSOR_CHANGE")
        cmd, args = os.path.basename(argv[0]), argv[1:]
        if cmd in SHELLS and "-c" in args and args.index("-c") + 1 < len(args):
            verdicts += check_bash(args[args.index("-c") + 1], ctx, depth + 1)
        elif cmd == "eval":
            verdicts += check_bash(" ".join(args), ctx, depth + 1)
        elif cmd == "ssh":
            verdicts += check_ssh(argv, ctx, approved)
        elif cmd in ("scp", "rsync", "sftp"):
            verdicts += check_copy(cmd, args, approved)
        elif cmd == "git":
            sub = _git_subcommand(args)
            if sub in ("commit", "push", "merge", "rebase", "tag") or (sub == "reset" and "--hard" in args):
                verdicts.append((ASK, f"`git {sub}` needs the user's explicit yes"))
        elif cmd == "gh" and args[:2] in (["pr", "create"], ["pr", "merge"], ["repo", "edit"], ["repo", "delete"],
                                          ["release", "create"], ["repo", "create"]):
            verdicts.append((ASK, f"`gh {' '.join(args[:2])}` is outward-facing - needs the user's explicit yes"))
        if cmd in EGRESS:
            leaked = ctx.internal_identifiers(" ".join(args))
            if leaked:
                verdicts.append((BLOCK, f"`{cmd}` with internal identifiers {leaked} - nothing internal goes to "
                                        "the web or external services"))
        for op, target in redirects(argv):
            for _, what in secrets_in(" ".join(argv)):
                verdicts.append((BLOCK, f"writing a {what} into {target} - secrets never go into files"))
    return verdicts


def secrets_in(text):
    return [(m.group(0)[:12] + "...", what) for rx, what in SECRET_PATTERNS for m in rx.finditer(text)]


def check_file_write(tool_input):
    path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
    texts = [tool_input.get(k, "") for k in ("content", "new_string", "new_source")]
    texts += [e.get("new_string", "") for e in tool_input.get("edits", []) or []]
    found = {what for t in texts if isinstance(t, str) for _, what in secrets_in(t)}
    return [(BLOCK, f"{what} in {path} - secrets never go into files (ssh uses keys/agent, SIEM queries are "
                    "run by the user)") for what in sorted(found)]


def check_web(tool_input, ctx):
    text = " ".join(str(tool_input.get(k, "")) for k in ("url", "query", "prompt"))
    leaked = ctx.internal_identifiers(text)
    return [(BLOCK, f"internal identifiers {leaked} must not be sent to web search or external services")] if leaked else []


def decide(tool_name, tool_input, ctx):
    """Pure decision function: (decision, [reasons])."""
    if tool_name == "Bash":
        verdicts = check_bash(tool_input.get("command", ""), ctx)
    elif tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        verdicts = check_file_write(tool_input)
    elif tool_name in ("WebFetch", "WebSearch"):
        verdicts = check_web(tool_input, ctx)
    else:
        verdicts = []
    if not verdicts:
        return ALLOW, []
    top = max(RANK[v] for v, _ in verdicts)
    decision = [d for d, r in RANK.items() if r == top][0]
    return decision, [r for v, r in verdicts if v == decision]


def main():
    event = json.load(sys.stdin)
    project = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
    decision, reasons = decide(event.get("tool_name", ""), event.get("tool_input") or {}, Context.load(project))
    if decision == BLOCK:
        print("guard: blocked - " + "; ".join(reasons), file=sys.stderr)
        return 2
    if decision == ASK:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                 "permissionDecisionReason": "guard: " + "; ".join(reasons)}}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # fail closed: a broken guard must not wave calls through
        print(f"guard: internal error, call blocked (fail closed): {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
