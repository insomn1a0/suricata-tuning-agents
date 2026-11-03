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

## Guard rails in the repo
- `config/environment.env`, `inventory/hosts.md`, `snapshots/`, `cards/`, `journal/` are git-ignored.
- `tools/lint_rules.py` fails on unanchored pcre2, unpinned tuning rules and literal IPs in descriptions.
- Logtest and pcap tests run in containers with `--network none`.
