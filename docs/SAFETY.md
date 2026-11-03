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
sensor**: a dedicated account whose sudoers entry allows only read commands on Suricata paths (no shell,
no editors), ideally behind an ssh `ForceCommand` wrapper that accepts the same read forms. The guard makes
the safe path frictionless and every other path visible to a human.

## Guard rails in the repo
- `config/environment.env`, `inventory/hosts.md`, `snapshots/`, `cards/`, `journal/` are git-ignored.
- `tools/lint_rules.py` fails on unanchored pcre2, unpinned tuning rules and literal IPs in descriptions.
- `tools/check_lab_data.py` (part of `make lint` and CI) fails on any address outside the lab/documentation
  ranges or internal-looking hostname outside `*.lab.local` in tracked and untracked-not-ignored files.
- Logtest and pcap tests run in containers with `--network none`.
