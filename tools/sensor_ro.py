#!/usr/bin/env python3
"""Sensor-side boundary: an ssh ForceCommand for the kit's read-only account.

The laptop guard (.claude/hooks/guard.py) can be bypassed by whatever runs on the laptop; this cannot - sshd
runs it for every login of the key, whatever command was requested. Two adversarial reviews shaped it:

  - No shell. The command is tokenised here (quotes honoured, nothing expanded) and run as argv; the only
    operators are `|` (the pipeline is built in Python) and `2>/dev/null` / `2>&1`. The first version checked
    with shlex and ran `bash -c` - two readings of one string.
  - An allowlist of flags per command (COMMANDS). Any option nobody listed is refused - the second version reused
    the laptop guard's list of *dangerous* options, and `sed --expression=w FILE`, `awk --dump-variables=FILE`
    and `ss -D FILE` wrote files on the sensor.
  - Files are read only by the first stage of a pipeline; raw telemetry (anything under the Suricata log
    directory except suricata.log/stats.log, any eve*.json or pcap) must come back bounded: the first stage
    bounds it (head/tail -n <= 1000, wc, grep -c) or the pipeline ends in one (`sort | uniq -c | head -n 20`),
    followed only by transformers. The executable is resolved on a fixed PATH; output, run time, CPU and
    written file size are limited; awk and sed are accepted only in exact shapes.
  - The snapshot (`python3 -I - --days N ...` with the script on stdin) runs only if the script's sha256 is
    allowlisted. An optional exact `sudo -n` prefix passes through - sudoers decides what root may read.
  - Every command has its own allowlist - nothing is delegated to the laptop guard's checks any more (a sixth
    review found `suricata -T`, allowed there, writing log files in the live log directory).
Every decision goes to syslog (auth, tag sensor-ro) with SSH_CONNECTION and, with ExposeAuthInfo, the key.

Install (by the sensor's admin): deploy/sensor/README.md.
Env: SENSOR_RO_ALLOWLIST (default /etc/sensor-ro/allowed-sha256), SENSOR_RO_LOGDIR (default /var/log/suricata),
     SENSOR_RO_DRY_RUN=1 prints the decision only."""
import hashlib
import os
import re
import shlex
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for candidate in (HERE, os.path.join(HERE, "..", ".claude", "hooks")):  # installed next to it / in the repo
    if os.path.exists(os.path.join(candidate, "guard.py")):
        sys.path.insert(0, os.path.abspath(candidate))
        break
import guard  # noqa: E402 - read-form checks for ip, ethtool, suricata, suricatasc, rpm

ALLOWLIST = os.environ.get("SENSOR_RO_ALLOWLIST", "/etc/sensor-ro/allowed-sha256")
LOGDIR = os.environ.get("SENSOR_RO_LOGDIR", "/var/log/suricata").rstrip("/")
PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": PATH, "LANG": "C.UTF-8"}
MAX_SCRIPT, MAX_OUTPUT, TIMEOUT = 2 * 1024 * 1024, 5 * 1024 * 1024, 120
MAX_LINES, MAX_BYTES = 1000, 65536
OPERATOR_CHARS = set("|&;<>()")


class Denied(Exception):
    pass


# ---------- per-command allowlist ----------
# flags: options without a value (single letters may be clustered: -ci); args: options that take a value
# (`-n 5`, `-n5`, `--lines=5`); pos: what positionals are - "files", "none", or a list of leading non-file
# positionals ("pattern", "program", "script", "filter", "sets", "words"), the rest being files.
COMMANDS = {
    "cat": dict(flags="nAvbs", pos="files"),
    "zcat": dict(flags="", pos="files"),
    "head": dict(flags="q", args={"-n", "-c", "--lines", "--bytes"}, pos="files", bound=True, max_files=1),
    "tail": dict(flags="q", args={"-n", "-c", "--lines", "--bytes"}, pos="files", bound=True, max_files=1),
    "grep": dict(flags="cihHlnoqvwxEFsL", args={"-e", "-m", "-A", "-B", "-C", "--max-count"}, pos=["pattern"]),
    "zgrep": dict(flags="cihHlnoqvwxEFs", args={"-e", "-m"}, pos=["pattern"]),
    "wc": dict(flags="lcwmL", pos="files"),
    "sort": dict(flags="nrufhVbM", args={"-k", "-t", "--key", "--field-separator"}, pos="files"),
    "uniq": dict(flags="cdui", pos="files", max_files=1),
    "cut": dict(flags="s", args={"-d", "-f", "-c", "--delimiter", "--fields"}, pos="files"),
    "tr": dict(flags="dsc", pos="sets"),
    "jq": dict(flags="rcsSen", pos=["filter"]),
    "awk": dict(args={"-F"}, pos=["program"]),
    "gawk": dict(args={"-F"}, pos=["program"]),
    "mawk": dict(args={"-F"}, pos=["program"]),
    "sed": dict(flags="n", pos=["script"]),
    "column": dict(flags="t", args={"-s"}, pos="files"),
    "nl": dict(flags="", pos="files"),
    "tac": dict(flags="", pos="files"),
    "comm": dict(flags="123", pos="files"),
    "diff": dict(flags="uq", pos="files"),
    "ls": dict(flags="lahtr1dSi", pos="files"),
    "stat": dict(flags="L", pos="files"),
    "readlink": dict(flags="fe", pos="files"),
    "realpath": dict(flags="e", pos="files"),
    "file": dict(flags="bL", pos="files"),
    "md5sum": dict(flags="", pos="files"),
    "sha256sum": dict(flags="", pos="files"),
    "du": dict(flags="shc", args={"--max-depth"}, pos="files"),
    "df": dict(flags="hTi", pos="files"),
    "free": dict(flags="mgh", pos="none"),
    "uptime": dict(flags="p", pos="none"),
    "date": dict(flags="uR", args={"-d", "--date"}, pos="date"),
    "hostname": dict(flags="fsI", pos="none"),
    "id": dict(flags="", pos="words"),
    "whoami": dict(flags="", pos="none"),
    "uname": dict(flags="arnmspo", pos="none"),
    "nproc": dict(flags="", pos="none"),
    "lscpu": dict(flags="", pos="none"),
    "ps": dict(flags="ef", args={"-o", "-p"}, pos="ps"),
    "pgrep": dict(flags="alfx", pos="words"),
    "pidof": dict(flags="", pos="words"),
    "ss": dict(flags="tulnpasimeox", pos="none"),
    "lsof": dict(flags="nPi", args={"-p", "-c"}, pos="none"),
    "echo": dict(flags="n", pos="words"),
    "printf": dict(flags="", pos="words"),
    "true": dict(flags="", pos="none"),
    "test": dict(flags="", pos="words", any_flags=True),
    "systemctl": dict(flags="l", args={"-p", "--property", "-t", "--type", "--state", "-n", "--lines"},
                      longs={"--no-pager", "--full", "--all", "--plain", "--no-legend"}, pos="systemctl"),
    "journalctl": dict(flags="krbqx", args={"-u", "--unit", "-n", "--lines", "--since", "--until", "-p",
                                            "--priority", "-o", "--output", "-S", "-U"},
                       longs={"--no-pager", "--utc", "--no-hostname"}, pos="none", needs_count=True),
    "dpkg-query": dict(flags="Wls", args={"-f", "--showformat"}, pos="words"),
    "python3": dict(pos="json.tool"),
    # Formerly delegated to the guard's checks; a review showed `suricata -T` (allowed there) writes eve.json,
    # fast.log and suricata.log in the live log directory as root. Own allowlists now, no `-T` on this account.
    "suricata": dict(flags="V", longs={"--build-info", "--list-keywords", "--list-app-layer-protos",
                                       "--dump-config"}, pos="none"),
    "suricatasc": dict(args={"-c"}, pos="none", needs_command=True),
    "ip": dict(flags="sd46jpo", dash_words={"-br", "-brief", "-stats", "-details", "-json", "-pretty", "-oneline"},
               pos="ip"),
    "ethtool": dict(flags="SikglacTP", pos="ethtool"),
    "rpm": dict(flags="qailfcd", pos="rpm"),
    "dpkg": dict(flags="lsLS", pos="dpkg"),
}
IP_OBJECTS = {"link", "addr", "address", "route", "neigh", "neighbour", "rule"}
# Long spellings map to one key, so `head -n 5 --lines=100000` is "given twice", not two options (review round 4).
ALIASES = {"--lines": "-n", "--bytes": "-c", "--max-count": "-m", "--key": "-k", "--field-separator": "-t",
           "--delimiter": "-d", "--fields": "-f", "--unit": "-u", "--since": "-S", "--until": "-U",
           "--priority": "-p", "--output": "-o", "--property": "-p", "--type": "-t", "--date": "-d",
           "--showformat": "-f"}
BOUNDING = {"wc", "md5sum", "sha256sum", "stat", "ls", "du", "file", "readlink", "realpath", "test"}
TRANSFORM = {"jq", "sort", "uniq", "cut", "tr", "column", "grep", "awk", "gawk", "mawk", "sed", "nl", "tac", "cat",
             "python3", "head", "tail", "wc"}
# Exact shapes, not a general program check (review: `print "}" > f`, ARGV[1]=file, `awk -- prog` got through).
SAFE_SED = re.compile(r"^(?:\d+|\$)(?:,(?:\d+|\$))?p$|^\d+q$|^s/[^/\\]*/[^/\\]*/g?$")
SAFE_AWK = re.compile(r"^(?:NR\s*>\s*\d+\s*)?\{\s*print(?:\s+\$\d+(?:\s*,\s*\$\d+)*)?\s*\}$")
REFUSED_PATHS = ("/dev", "/proc", "/sys")
FSIZE_LIMIT, CPU_LIMIT = 8 * 1024 * 1024, 60
SYSTEMCTL_VERBS = {"status", "show", "is-active", "is-enabled", "is-failed", "list-units", "list-timers", "cat"}
JOURNAL_OUTPUTS = {"short", "short-iso", "short-precise", "cat", "json", "json-pretty", "verbose"}


def tokenize(command):
    """[(text, is_operator)]. Quotes are honoured and removed, a backslash outside single quotes escapes the
    next character, nothing is expanded. Unquoted runs of `|&;<>()` are operators; quoted ones are text."""
    out, cur, have, i, n = [], [], False, 0, len(command)
    while i < n:
        ch = command[i]
        if ch in " \t":
            if have:
                out.append(("".join(cur), False))
                cur, have = [], False
            i += 1
        elif ch == "'":
            end = command.find("'", i + 1)
            if end < 0:
                raise Denied("unbalanced single quote")
            cur.append(command[i + 1:end])
            have, i = True, end + 1
        elif ch == '"':
            i += 1
            while i < n and command[i] != '"':
                if command[i] == "\\" and i + 1 < n and command[i + 1] in '"\\$`':
                    i += 1
                cur.append(command[i])
                i += 1
            if i >= n:
                raise Denied("unbalanced double quote")
            have, i = True, i + 1
        elif ch == "\\":
            if i + 1 >= n:
                raise Denied("trailing backslash")
            cur.append(command[i + 1])
            have, i = True, i + 2
        elif ch in OPERATOR_CHARS:
            if have:
                out.append(("".join(cur), False))
                cur, have = [], False
            j = i
            while j < n and command[j] in OPERATOR_CHARS:
                j += 1
            out.append((command[i:j], True))
            i = j
        else:
            cur.append(ch)
            have, i = True, i + 1
    if have:
        out.append(("".join(cur), False))
    return out


def parse(command):
    """command -> [(argv, stderr)] with stderr None, 'null' or 'stdout'."""
    if not command.strip():
        raise Denied("interactive session - the kit runs one bounded read-only command per login")
    if "\n" in command or "\r" in command or "\0" in command:
        raise Denied("one command per login - no newlines")
    tokens, stages, cur, redirect, i = tokenize(command), [], [], None, 0
    while i < len(tokens):
        text, op = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ("", False)
        if op and text == "|":
            if not cur:
                raise Denied("empty pipeline stage")
            stages.append((cur, redirect))
            cur, redirect = [], None
        elif op and text in (">", ">&") and cur and cur[-1] == "2" and not nxt[1] and \
                (text, nxt[0]) in ((">", "/dev/null"), (">&", "1")):
            cur.pop()
            redirect, i = ("null" if text == ">" else "stdout"), i + 1
        elif op:
            raise Denied(f"operator {text!r} - only pipes, 2>/dev/null and 2>&1 are supported")
        else:
            cur.append(text)
        i += 1
    if not cur:
        raise Denied("empty pipeline stage")
    stages.append((cur, redirect))
    return stages


def split_options(cmd, spec, args):
    """-> (positionals, {option: value}) or Denied for any option not in the spec."""
    flags, takes, longs = set(spec.get("flags", "")), spec.get("args", set()), spec.get("longs", set())
    pos, opts, i = [], {}, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            pos += args[i + 1:]
            break
        if not a.startswith("-") or a == "-" or (cmd == "date" and a.startswith("+")) or spec.get("any_flags"):
            pos.append(a)
        elif a.startswith("--"):
            name, eq, value = a.partition("=")
            if name in takes:
                if not eq:
                    if i + 1 >= len(args):
                        raise Denied(f"`{cmd} {name}` needs a value")
                    value, i = args[i + 1], i + 1
                set_once(opts, ALIASES.get(name, name), value)
            elif name not in longs or eq:
                raise Denied(f"`{cmd}` option {name} is not allowed for this account")
        elif a[:2] in takes:
            if len(a) > 2:
                set_once(opts, a[:2], a[2:])
            elif i + 1 < len(args):
                set_once(opts, a, args[i + 1])
                i += 1
            else:
                raise Denied(f"`{cmd} {a}` needs a value")
        elif a in spec.get("dash_words", ()):  # iproute2's single-dash long options
            opts[a] = True
        elif cmd in ("head", "tail") and re.fullmatch(r"-\d+", a):
            set_once(opts, "-n", a[1:])
        elif all(c in flags for c in a[1:]):
            opts.update({f"-{c}": True for c in a[1:]})
        else:
            raise Denied(f"`{cmd}` option {a} is not allowed for this account")
        i += 1
    return pos, opts


def set_once(opts, key, value):
    if key in opts:
        raise Denied(f"option {key} given twice - each value is checked once")
    opts[key] = value


def executable(argv):
    """argv with the command resolved on the fixed PATH (at execution time, so dry runs work anywhere)."""
    sudo = argv[:2] == ["sudo", "-n"]
    name = argv[2] if sudo else argv[0]
    path = shutil.which(name, path=PATH)
    if not path:
        raise Denied(f"`{name}` not found on the sensor")
    rest = argv[3:] if sudo else argv[1:]
    return (["sudo", "-n", path] if sudo else [path]) + rest


def is_telemetry(path):
    norm = os.path.realpath(path)  # //var/log/..., symlinks and /proc/self/root/... resolve to the real file
    if re.search(r"eve[\w.*-]*\.json|\.pcap", norm, re.I) or "filestore" in norm:
        return True
    logdir = os.path.realpath(LOGDIR)
    inside = norm == logdir or norm.startswith(logdir + "/")
    return inside and not re.fullmatch(r"(suricata|stats)\.log(\.\d+)?", os.path.basename(norm))


def check_stage(argv, first):
    """-> (files, bounding, transforms_only) for one stage, or Denied."""
    sudo = argv[:2] == ["sudo", "-n"]
    rest = argv[2:] if sudo else argv
    if not rest:
        raise Denied("sudo without a command")
    name, args = rest[0], rest[1:]
    if "/" in name:
        raise Denied("commands by name only - a path would run whatever file is called that")
    spec = COMMANDS.get(name)
    if spec is None:
        raise Denied(f"`{name}` is not on the sensor allowlist")
    if spec.get("pos") == "json.tool":
        if args != ["-m", "json.tool"]:
            raise Denied("python3 only as `python3 -m json.tool` reading stdin")
        return [], False, True
    pos, opts = split_options(name, spec, args)
    kind, files = spec["pos"], []
    if isinstance(kind, list):
        lead = 0 if name in ("grep", "zgrep") and "-e" in opts else len(kind)
        lead_args, files = pos[:lead], pos[lead:]
        if len(lead_args) < lead:
            raise Denied(f"`{name}` needs its {kind[0]}")
        if name == "sed" and not SAFE_SED.match(lead_args[0]):
            raise Denied("sed only as `sed -n 'Np'`, `'N,Mp'`, `'Nq'` or `'s/a/b/g'`")
        if name in ("awk", "gawk", "mawk") and not SAFE_AWK.match(lead_args[0].strip()):
            raise Denied("awk only as `awk [-F X] '{print $N, ...}'`, optionally `NR>N {print ...}`")
    elif kind == "files":
        files = pos
    elif kind == "systemctl":
        if not pos or pos[0] not in SYSTEMCTL_VERBS:
            raise Denied(f"systemctl verb {pos[:1]} is not read-only")
    elif kind == "date":
        if any(not p.startswith("+") for p in pos):
            raise Denied("`date` with a value would set the clock")
    elif kind == "ip":
        verb = pos[1] if len(pos) > 1 else "show"
        verbs = ("show", "list", "ls") + (("get",) if pos and pos[0] == "route" else ())
        if not pos or pos[0] not in IP_OBJECTS or verb not in verbs:
            raise Denied("ip forms: ip [-s -d -j -br ...] link|addr|route|neigh|rule show|list [filters]")
    elif kind == "ethtool":
        if len(pos) != 1 or len([o for o in opts if o.startswith("-")]) > 1:
            raise Denied("ethtool forms: ethtool [one of -S -i -k -g -l -a -c -T -P] <interface>")
    elif kind == "rpm":
        if "-q" not in opts:
            raise Denied("rpm queries only: rpm -q[ilfcd] <package>")
    elif kind == "dpkg":
        if len([o for o in opts if o.startswith("-")]) != 1:
            raise Denied("dpkg forms: dpkg -l|-s|-L|-S <names>")
    elif kind == "ps":
        if any(p not in ("aux", "ax", "-ef") for p in pos):
            raise Denied("ps forms: aux, -ef, -o, -p")
    elif kind == "sets" and len(pos) > 2:
        raise Denied("`tr` takes at most two sets and reads stdin")
    elif kind == "none" and pos:
        raise Denied(f"`{name}` takes no arguments here")
    if name == "journalctl" and opts.get("-o", opts.get("--output", "short")) not in JOURNAL_OUTPUTS:
        raise Denied("journalctl output formats: short, cat, json, verbose")
    if name in ("systemctl", "journalctl") and str(opts.get("-n", "0")).isdigit() is False:
        raise Denied(f"`{name} -n` needs a number")
    if name == "systemctl" and int(opts.get("-n", "0")) > MAX_LINES:
        raise Denied(f"`systemctl -n` at most {MAX_LINES} journal lines")
    if spec.get("needs_command"):
        command = str(opts.get("-c", ""))
        if (command.split() or [""])[0] not in guard.SURICATASC_READ or len(command.split()) > 2:
            raise Denied(f"suricatasc read commands only: {sorted(guard.SURICATASC_READ)}")
    if spec.get("needs_count"):
        count = str(opts.get("-n") or "")
        if not count.isdigit() or int(count) > MAX_LINES:
            raise Denied(f"`{name}` needs -n N (<= {MAX_LINES})")
    for f in files:
        real = os.path.realpath(f)
        literal = os.path.normpath(f)
        if f.startswith("//") or real == "/" or any(p == d or p.startswith(d + "/") for p in (real, literal)
                                                    for d in REFUSED_PATHS):
            raise Denied(f"{f}: not readable through this account (device, /proc, /sys or a `//` path)")
    if len(files) > spec.get("max_files", 64):
        raise Denied(f"`{name}` takes at most {spec['max_files']} file(s) here (an output file, or a bound per file)")
    if files and not first:
        raise Denied("only the first stage of a pipeline reads files; later stages read stdin")
    count_ok = True
    if spec.get("bound"):
        if "-n" in opts and "-c" in opts:
            raise Denied(f"`{name}` takes one count (-n or -c), not both")
        count = opts.get("-n") or opts.get("-c")
        limit = MAX_BYTES if "-c" in opts else MAX_LINES
        count_ok = bool(count) and re.fullmatch(r"\d+", str(count)) is not None and int(count) <= limit
    bounding = (name in BOUNDING) or (spec.get("bound") and count_ok) or \
        (name in ("grep", "zgrep") and bool({"-c", "-l", "-q", "-L"} & set(opts)))
    # not `uniq -c`: `grep -h . eve.json | uniq -c` is the raw log with counts in front
    return files, bounding, name in TRANSFORM


def snapshot_argv(command):
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    sudo, rest = (argv[:2], argv[2:]) if argv[:2] == ["sudo", "-n"] else ([], argv)
    if rest and rest[0] in ("python3", "/usr/bin/python3") and guard.is_snapshot_form(rest[1:]):
        flags = dict(zip(rest[3::2], rest[4::2])) if rest[1:3] == ["-I", "-"] else dict(zip(rest[2::2], rest[3::2]))
        if flags.get("--logdir", LOGDIR).rstrip("/") != LOGDIR or \
                not re.fullmatch(r"[\w.*?-]+", flags.get("--pattern", "eve.json*")):
            return None  # the snapshot reads the Suricata log directory, nothing else
        return sudo + ["/usr/bin/python3"] + rest[1:]
    return None


def allowed_hashes(path=ALLOWLIST):
    try:
        with open(path) as f:
            return {line.split()[0].lower() for line in f if line.strip() and not line.startswith("#")}
    except OSError:
        return set()


def decide(command, script=None, hashes=None):
    """(allowed, reason, plan) - plan is ('snapshot', argv) or ('pipeline', [(argv, stderr)])."""
    argv = snapshot_argv(command)
    if argv:
        digest = hashlib.sha256(script or b"").hexdigest()
        if digest in (allowed_hashes() if hashes is None else hashes):
            return True, f"snapshot script sha256 {digest[:12]} is allowlisted", ("snapshot", argv)
        return False, f"snapshot script sha256 {digest[:12]} is not in the allowlist", None
    try:
        stages = parse(command)
        checked = [check_stage(a, n == 0) for n, (a, _) in enumerate(stages)]
        if any(is_telemetry(f) for files, _, _ in checked for f in files):
            last_bound = max((n for n, (_, b, _) in enumerate(checked) if b), default=None)
            if last_bound is None or not all(t for _, _, t in checked[last_bound + 1:]):
                raise Denied("unbounded read of raw telemetry - bound the first stage (head -n N <= 1000, wc, "
                             "grep -c) or end the pipeline with one (... | sort | uniq -c | head -n N)")
    except Denied as e:
        return False, f"{e} (this account is read-only)", None
    return True, "read-only form", ("pipeline", stages)


def limits():
    """In each child: written files <= FSIZE_LIMIT (backstop against any write path, and sort/tac temp files
    filling the disk), CPU seconds <= CPU_LIMIT."""
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_LIMIT, FSIZE_LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT, CPU_LIMIT))


def run_pipeline(stages):
    """Run argv stages connected by pipes; copy at most MAX_OUTPUT bytes; kill everything after TIMEOUT."""
    procs, prev = [], subprocess.DEVNULL
    for argv, redirect in stages:
        stderr = subprocess.DEVNULL if redirect == "null" else subprocess.STDOUT if redirect == "stdout" else None
        p = subprocess.Popen(argv, stdin=prev, stdout=subprocess.PIPE, stderr=stderr, env=ENV, preexec_fn=limits)
        if prev is not subprocess.DEVNULL:
            prev.close()  # upstream gets SIGPIPE when a later stage exits (head)
        prev = p.stdout
        procs.append(p)
    import threading
    timer = threading.Timer(TIMEOUT, lambda: [p.kill() for p in procs])
    timer.start()
    sent, out = 0, sys.stdout.buffer
    try:
        for chunk in iter(lambda: prev.read(65536), b""):
            if sent + len(chunk) > MAX_OUTPUT:
                out.write(chunk[:MAX_OUTPUT - sent])
                print(f"\nsensor-ro: output capped at {MAX_OUTPUT} bytes", file=sys.stderr)
                for p in procs:
                    p.kill()
                break
            out.write(chunk)
            sent += len(chunk)
        out.flush()
    finally:
        timer.cancel()
    return [p.wait() for p in procs][-1]


def log(message):
    try:
        import syslog
        syslog.openlog("sensor-ro", 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, message[:900])
    except Exception:  # noqa: BLE001 - logging must never decide
        pass


def main():
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    script = None
    if snapshot_argv(command):
        script = sys.stdin.buffer.read(MAX_SCRIPT + 1)
        if len(script) > MAX_SCRIPT:
            script = b""
    ok, reason, plan = decide(command, script)
    who = os.environ.get("SSH_CONNECTION", "?").split(" ")[0]
    key = next((line for line in (os.environ.get("SSH_USER_AUTH") or "").splitlines() if line), "")
    log(f"{'ALLOW' if ok else 'DENY'} from={who} key={key[:80]!r} cmd={command!r} reason={reason}")
    if os.environ.get("SENSOR_RO_DRY_RUN"):
        print(f"{'ALLOW' if ok else 'DENY'}: {reason}")
        return 0 if ok else 126
    if not ok:
        print(f"sensor-ro: denied - {reason}", file=sys.stderr)
        return 126
    kind, what = plan
    if kind == "snapshot":
        return subprocess.run(what, input=script, env=ENV, timeout=TIMEOUT, preexec_fn=limits).returncode
    import tempfile
    ENV["TMPDIR"] = tempfile.mkdtemp(prefix="sensor-ro-")  # sort/tac temp files: private, size-limited dir
    try:
        stages = [(executable(argv), err) for argv, err in what]
        return run_pipeline(stages)
    except Denied as e:
        print(f"sensor-ro: denied - {e}", file=sys.stderr)
        return 126
    finally:
        shutil.rmtree(ENV["TMPDIR"], ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - fail closed
        print(f"sensor-ro: internal error, denied: {type(e).__name__}", file=sys.stderr)
        sys.exit(126)
