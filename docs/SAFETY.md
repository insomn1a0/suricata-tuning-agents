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
Bash, file-write and web tool call and decides:

| Decision | What |
|---|---|
| block (exit 2) | over ssh/scp: write/delete/restart/install verbs, output redirects, in-place edits, scripts piped into a remote interpreter (except `tools/sensor_snapshot.py`), interactive sessions, copying files onto the sensor; internal identifiers (RFC 1918, inventory names, the sensor) in curl/wget/WebFetch/WebSearch; tokens, passwords and private keys written into files |
| ask (user prompt) | a remote command that is neither a known read nor a known write; copying files off the sensor; `SENSOR_CHANGE=<card-id>`-prefixed sensor changes; `git commit/push/merge/tag`, `gh pr create/merge`, repo visibility |
| allow | everything else, incl. read-only `ssh sensor 'sudo -n cat ...'` |

It fails closed twice: the script exits 2 on any internal error, and the hook is registered with
`"onFailure": "block"` (Claude Code >= 2.1.295), so a missing interpreter or a timeout also blocks.
Verified in a live session: a `tee` over ssh was blocked with the reason shown to the model, and a hook
pointing at a missing script blocked the call.

Limits - it is a seatbelt, not a sandbox: it reads the command line Claude runs, not what a script does
inside; obfuscation it cannot parse is asked about, not allowed. The boundary on the sensor is still the
read-only account.

## Guard rails in the repo
- `config/environment.env`, `inventory/hosts.md`, `snapshots/`, `cards/`, `journal/` are git-ignored.
- `tools/lint_rules.py` fails on unanchored pcre2, unpinned tuning rules and literal IPs in descriptions.
- `tools/check_lab_data.py` (part of `make lint` and CI) fails on any address outside the lab/documentation
  ranges or internal-looking hostname outside `*.lab.local` in tracked and untracked-not-ignored files.
- Logtest and pcap tests run in containers with `--network none`.
