# Tuning Suricata → Wazuh without hiding attacks - and what the tests caught

## The problem

A default ET ruleset on a corporate network produces hundreds of Suricata alerts a day. Most are "true but
useless": a workstation opened an installer on the software distribution share, again. Analysts learn to
skim, and the usual fix - suppress whatever is loud - quietly creates blind spots. The same SID that is noise
on the distribution share is lateral tool transfer when the target is another workstation's admin share.

Tuning is a configuration change with security consequences, made by hand, rarely tested and almost never
re-checked. This project treats it like code: every decision is reviewed, rendered, tested on the real
engines and kept honest by tests that try to prove it wrong.

## The approach

- **The model stays out of the alert path.** Agents (Claude Code) work offline: they collect aggregates,
  write a triage card per SID with one decision (KEEP / ENRICH / LOWER / DISABLE / RAISE / ASK), and turn
  an approved card into an intent. A human approves; deterministic engines verify.
- **Decisions are data.** One YAML intent per decision - exact routes (address + port), the SID's real
  metadata, rationale, risk, compensating control. `make render` produces the Wazuh 4.x XML, Suricata
  threshold/disable files and the test cases. Wazuh 5 drops XML rules; intents do not change.
- **The engines are the oracle.** Wazuh logtest says which rule is actually selected; Suricata replays pcaps.
  A regression corpus of synthetic attacks goes through both with the generated rules: every attack must stay
  visible. Plausible-but-wrong intents (mutants) must make that fail.
- **Safety is enforced, not requested.** A PreToolUse hook checks every command an agent runs; an ssh
  ForceCommand on the sensor executes only bounded reads, without a shell.

## What the tests and reviews caught

Every row happened during development, and every fix is now a test. Most were found by making a test fail
on purpose (mutation) or by an adversarial review agent whose only job was to break the batch.

| What was wrong | How it was found | Now |
|---|---|---|
| Logtest assertions passed while analysisd could not compile its CDB lists in the container | the checker refuses a run with engine `ERROR` lines | ownership fixed; engine errors still fail the run |
| The DCSync pcap test keyed alerts by IP pair - a signature firing on the wrong DCE/RPC opnum passed | mutation: opnum 3 → 12, the test stayed green | expectations keyed by session; unit test pins it |
| `make` read the shell env file and kept the quotes: the image tag became `"8.0"` | reading why a user's run would differ from CI | one config source, parsed with shlex |
| The README linked an example that `.gitignore` had silently kept out of the repo | a link checker added to lint | anchored ignore patterns |
| Guard v1 (a denylist) let all 7 probes through: `vim`, `xargs rm`, `awk system()`, `tar -x`, ... | probing before merge | allowlist of read forms; unknown asks |
| Guard v2 rejected with dozens of bypasses: `ssh host 'sudo -s' < script`, `for ... do ssh ... rm`, `systemctl stop x status`, secrets in JSON | adversarial review agent | recognise the safe path exactly, ask about the rest; ~250-row table |
| A broken guard blocked every edit, including its own fix (fail closed working as designed) | developing the guard with the guard active | fuzz test: the old parser crashed on 817 of 3000 random commands |
| Wazuh orders sibling rules by level, not file order - the test model assumed file order | review, confirmed on Wazuh 4.14.9 | engine-order model; overlapping decisions refused |
| A `rationale` text could close the XML comment and inject a level-0 rule that lint accepted | review, confirmed on the engine | escaping + the rendered rule IDs must equal the declared ones |
| Test events copied the parent's metadata, so they reached the parent by construction | review | intents carry the SID's real metadata, checked against the rule text and EVE |
| A suppress intent did nothing: Suricata drops a threshold line that ends in a comment | **a mutant survived** the corpus | comments on their own line; any Suricata `E:` fails the run |
| The sensor wrapper validated with shlex and executed with `bash -c` - two readings of one string | review | no shell at all; a mutant that restores `bash -c` deletes `suricata.yaml` in the lab |
| The "read-only" `suricata -T` config test opened every configured output and created root-owned log files in the live log directory | review of the checks the wrapper delegated to the guard; reproduced in the lab | own allowlists for every command; `-T` is not a read |
| A RAISE intent was impossible for a hidden Minor/Medium alert: it lands on the stock rule, which is not a leaf | triaging the whole demo - the first real RAISE | ladder leaf 100207, hidden as before; logtest pins it |
| The sensor-lab test wrote events with a fixed date: a week after release they fell out of the 7-day window | rerunning the full suite before v1.0 | events dated relative to now |
| The demo data claimed `rev 1` for every SID while the rule text said 2 or 3 | the triage agent compared EVE with the rule text | real revisions in the generator |
| Metrics treated a disabled SID as still visible | adding the first DISABLE intent | disabled SIDs never visible; unit test |
| The triage agent proposed "KEEP at level 3" for cleartext credentials after a fix - a regression would be archived | human review of the card | RAISE to a visible level |
| The README said "~2.5 alerts/day" after tuning | computing it: 3.6 (each DC now has its own `ignore` window) | numbers generated by `make metrics`, checked in lint |

The pattern: the most valuable failures came from tests built to be wrong (mutants, probes, a reviewer told
to reject), not from tests built to pass.

## Evidence, not claims

Every result carries a label and never more than what ran: `static`, `lint`, `logtest <version>`,
`pcap-lab <version>`, `sensor-lab <version>`, `live-sensor`, `siem-query`. On the demo week the generated rules
take visible alerts from 367 to 59 a day (-84%) - while raising 50 a day of hidden cleartext credentials - and
the lateral-transfer events stay visible 3/3; the corpus keeps 5/5 attacks visible on Suricata 8.0.8 + Wazuh
4.14.9 and kills every mutant. The whole loop, step by step: [WALKTHROUGH.md](WALKTHROUGH.md).

## Limits

The data is synthetic and the kit has not run against a production sensor yet. The corpus proves that tuning
keeps an attack visible, not that a given ruleset detects it (the ET rules are not vendored; lab stand-ins
fire instead). The laptop guard reads command lines, not what a script does - the boundary that holds is the
ForceCommand on the sensor. The README metrics come from the rule model that the generated logtest cases
verify, because replaying a week through logtest cannot reproduce `ignore` windows.

## Lessons

- Ask "what does the analyst do when this fires?", never "how often does it fire?".
- A test that never failed proves nothing - break it once on purpose.
- If the checker and the executor parse differently, the checker is decoration.
- Fail closed, and plan the recovery path: the first lockout will be your own.
- Generated tests check consistency; only an independent corpus checks the decision.
