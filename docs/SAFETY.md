# Safety model

The kit is designed so that an agent mistake costs a wrong proposal, not a blind SOC.

## What agents may do

| Action | `propose` (default) | `safe-auto` |
|---|---|---|
| Read the sensor (aggregates, rule text, counters) | yes | yes |
| Write snapshots, cards, journal, local tests | yes | yes |
| Edit Wazuh rules on a feature branch (no commit) | yes | yes |
| `DISABLE` a pure parser/decoder-noise SID on the sensor, with backup | ask | yes, then report |
| Anything that reduces visibility of a security signal (`LOWER`, level change) | ask | ask |
| Host/route exceptions, policy decisions | ask | ask |
| Commit, push, merge request, deploy | ask | ask |

## What agents never do
- Use passwords or tokens, or work around a failed BatchMode ssh.
- Restart services, generate or replay traffic on production, or install packages without an approved sensor change.
- Copy raw EVE events, payloads or pcaps off the sensor.
- Send internal identifiers to web search or other external services.
- Claim an evidence level that did not run (see docs/PLAYBOOK.md).

## Enforcement: the PreToolUse guard
Instructions (CLAUDE.md, skills) are context, not enforcement. `.claude/hooks/guard.py` runs before every
Bash, file-write and web tool call. Its principle: **recognise the safe path exactly, send everything else to
a human, block known writes.** Hunting for dangerous strings in arbitrary shell does not work - the first
version did that and an adversarial review found dozens of bypasses (loops, `bash -lc`, `sudo -s < script`,
`systemctl stop x status`, ...). They are now rows in `tests/unit/test_guard.py`.

| Decision | What |
|---|---|
| block (exit 2) | on the sensor: known write/restart/install verbs, output redirects, in-place edits, root shells (`sudo -i/-s`, `su`, empty `sudo`), text piped into a remote shell or interpreter (only `tools/sensor_snapshot.py` in its exact form is approved), interactive sessions, copying files onto it; a sensor reference inside loops, `bash -c`, wrappers or interpreters **when a write verb appears**; internal identifiers (RFC 1918/6598/4193 in any notation, inventory names, the sensor) or local telemetry/inventory files sent by web tools; secrets written into files; malformed tool input |
| ask (user prompt) | a remote command that is not a known read form; unbounded reads of raw EVE/pcap (they must stay on the sensor); sensor references the guard cannot parse exactly; unusual ssh options (proxy, forwarding, config); copying files off the sensor; `SENSOR_CHANGE=<card-id>` changes; `git commit/push/merge/...`, `gh pr/issue/release/gist/...`, `gh api` writes; credentials from variables written into files |
| allow | everything else, incl. the documented read-only forms: `ssh sensor "$SENSOR_SUDO grep ..."`, `systemctl status`, `suricatasc -c dump-counters`, `journalctl -u suricata -n 50`, `tools/snapshot.sh` |

It fails closed twice: the script exits 2 on invalid input or any internal error, and the hook is
registered with `"onFailure": "block"` (Claude Code >= 2.1.295), so a missing interpreter or a timeout also
blocks. Verified in a live session: a `tee` over ssh was blocked with the reason shown to the model, and a
hook pointing at a missing script blocked the call.

Changing the guard, its registration (`.claude/settings.json`, `hooks.json`) or the scripts it trusts
(`tools/sensor_snapshot.py`, `tools/snapshot.sh`) always asks the user - otherwise an agent could relax its own
limits or turn the approved snapshot into arbitrary code. Fail closed has a cost: while developing the guard,
a broken version blocked every Edit (including the fix). Recovery is from the user's own terminal.

Limits - it is a seatbelt, not a sandbox. It reads the command line Claude runs, not what a local script
does inside (`bash evil.sh` is allowed); shell it cannot parse is asked about. **The boundary must be on the
sensor** - see below. The guard makes the safe path frictionless and every other path visible to a human.

## The boundary on the sensor
`tools/sensor_ro.py` is an ssh `ForceCommand` for the kit's read-only account (install: `deploy/sensor/`).
sshd runs it for every login with that key, whatever command the laptop sent, so nothing on the laptop can
bypass it. **No shell runs the command**: it is split into argv, the only operators are `|` (the pipeline is
built in Python) and `2>/dev/null` / `2>&1`, so nothing expands and the checker cannot read the string
differently from the executor. The first version validated and then ran `bash -c`; the review rejected it,
and a mutant that restores `bash -c` deletes `suricata.yaml` in the lab test. The second version reused the
guard's list of *dangerous* options, and the next review wrote files on the lab sensor with options nobody had
listed (`sed --expression=w FILE`, `awk --dump-variables=FILE`, `ss -D FILE`). Now each allowed command has an
allowlist of flags, and anything else is refused:

| | laptop guard | sensor ForceCommand |
|---|---|---|
| unknown command | ask the user | refuse |
| options | known-dangerous ones blocked | per-command allowlist of flags; any other option refused |
| files in a pipeline | any stage | first stage only; later stages read stdin |
| command given as a path (`/tmp/x/cat`) | parsed by name | refused; names resolve on a fixed PATH |
| awk / sed programs | checked for dangerous constructs | exact shapes only: `awk [-F X] '{print $N, ...}'`, `sed -n 'Np'` |
| `suricata -T` (config test) | allowed | refused - it opens every output and wrote eve.json/fast.log/suricata.log in the live log directory; config tests belong to `sensor-change` |
| paths | as written | real path; `/dev`, `/proc`, `/sys` and `//` refused; telemetry = anything under the log dir |
| output, run time, written files | unlimited | 5 MB output, 120 s, 60 s CPU, files written by a child <= 8 MB, private TMPDIR |
| `;`, `&&`, `$(...)`, backticks, globs, braces, `~` | parsed, often allowed | `;`/`&&`/`(` refused; the rest is a literal argument (no shell) |
| interpreters, `env`, `xargs`, `find`, `jq --rawfile` | asked about | refused (only `python3 -m json.tool` on stdin) |
| snapshot via stdin | allowed when the stdin path is the project's script | allowed only if the script's sha256 is pinned on the sensor |
| unbounded raw EVE / pcap | ask | refuse |
| decisions logged | no | syslog `auth`, tag `sensor-ro` |

Read access itself should come from ACLs or group membership, not sudo (`deploy/sensor/README.md`); if sudo is
unavoidable, `sudoers.example` lists exact commands without file wildcards. Evidence: `make test-sensor-ro` runs
every case for real in a Suricata container - reads succeed, refused writes leave `suricata.yaml` unchanged,
no option writes a file, a modified snapshot script does not run; mutating the wrapper (`bash -c` back, hash
check off, flag allowlist off) fails it.

## Guard rails in the repo
- `config/environment.env`, `inventory/hosts.md`, `snapshots/`, `cards/`, `journal/` are git-ignored.
- `tools/lint_rules.py` fails on unanchored pcre2, unpinned tuning rules and literal IPs in descriptions.
- `tools/check_lab_data.py` (part of `make lint` and CI) fails on any address outside the lab/documentation
  ranges or internal-looking hostname outside `*.lab.local` in tracked and untracked-not-ignored files.
- Logtest and pcap tests run in containers with `--network none`.
