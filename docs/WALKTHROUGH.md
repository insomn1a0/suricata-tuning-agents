# Walkthrough - two demo weeks through the whole loop

Everything below can be regenerated from a clone: synthetic data (`make demo`), the kit's own agents, the real
engines in throwaway containers. The command output is copied from a run, not typed. The owner answers in step 3
are part of the demo scenario - in a real deployment they come from the people who own the hosts.

## 1. Snapshot and diff

```
$ make demo
alerts 6222 -> 6118, visible 2572 -> 2818, sids 6 -> 6

NEW SIDs (1):
     9100001 L13      0.1/d LOCAL Possible DCSync - DRSUAPI DRSGetNCChanges from non-DC

DISAPPEARED SIDs (1) - if they were steady, check for breakage:
     9900003 L3      50.0/d days_seen_before=7 EXAMPLE HTTP Basic Authorization over Cleartext

SPIKES / DROPS x5 (1):
     9900002 L8       5.0/d -> 40.0/d EXAMPLE TLS SNI of Remote Administration Tool Relay
```

Six SIDs, 888 alerts a day, 367 of them at the analyst-visible level. The diff points at three of them; the
volume table (README) at the other three.

## 2. Triage by the agent

`noise-analyst` (a cheaper model, `.claude/agents/noise-analyst.md`) got the two snapshots, the rule text, the
inventory and the Wazuh ladder, and wrote one card per SID. 2025701 was already decided
([card](../examples/cards/2025701.md)).

| SID | Per day | Level | Agent's decision | Why it did not decide more |
|---|---|---|---|---|
| [2025709](../examples/cards/2025709.md) DLL over SMB | 28.6 | 6 | ASK | all of it goes to print01, but "these are driver reads" is a hypothesis about the share |
| [9900001](../examples/cards/9900001.md) ad/tracking DNS | 120.0 | 6 | ASK | whether ad lookups matter is policy; a route on the shared resolver is the shape the playbook warns about |
| [9900002](../examples/cards/9900002.md) remote-admin relay | 5 -> 40 | 8 | ENRICH | one DHCP workstation, around the clock: actionable, but the alert does not say what to check |
| [9900003](../examples/cards/9900003.md) cleartext Basic auth | 50 -> 0 | 3 (hidden) | ASK | unknown host, and a SID that vanishes must be explained before the quiet counts as a fix |
| [2210020](../examples/cards/2210020.md) stream out of window | 471.4 | 3 (hidden) | ASK | no per-alert action, but it may be the only sign of capture loss or evasion |
| [9100001](../examples/cards/9100001.md) DCSync | 0.1 (new) | 13 | KEEP | a non-DC asking a DC to replicate at 02:34 - act now |

Four ASKs out of six is the intended behaviour: the agent may lower only what it can verify, and an inventory row
with a role is not proof of what a share contains. It also caught a bug in the demo generator - EVE said `rev 1`
while the rule text said `rev 3`.

## 3. Owner answers and the human review

| SID | Owner answer (demo scenario) | Final |
|---|---|---|
| 2025709 | print$ holds drivers only, clients read, FIM on print$ | **LOWER** print01:445 |
| 9900001 | policy, not security; RPZ blocks the suffix, query log kept 30 days | **LOWER** dns1:53 |
| 9900002 | the lease was a helpdesk laptop; the tool is not approved - incident open | **ENRICH** (as proposed) |
| 9900003 | intranet01, legacy HR app; HTTPS enforced on 2026-01-12, passwords reset | **RAISE** |
| 2210020 | capture drops and reassembly gaps are alerted from Suricata stats | no change (DISABLE rejected in review) |
| 9100001 | nobody else replicates; a contractor laptop - incident open | **KEEP** |

Three points where a review changed or questioned a proposal:

- **9900003**: the card proposed "moved to HTTPS -> keep it at level 3 so a regression shows". At level 3 a
  regression is archived, not shown. Cleartext credentials have a clear analyst action anywhere, so: RAISE.
  The first real RAISE then exposed a gap in the kit: Minor/Medium lands on the stock rule 86601, which is not a
  leaf, so no RAISE rule could attach. Ladder leaf 100207 (level 3, hidden as before) fixed it.
- **9900001**: the intent has the same shape (dst resolver + 53) as the corpus mutant `lower-internal-resolver`,
  with the opposite decision. That is the point: the question is what the analyst does, not where the event goes.
  The corpus has to show the difference (step 5).
- **2210020**: with the owner's counters confirmed, the human decision was DISABLE - 471 events a day of archive
  and indexer load. The adversarial `reviewer` rejected it: out-of-window packets are exactly what the stream engine
  does not reassemble, so in an insertion attempt this event is the only trace, and the counters show loss per
  sensor, not per flow. Volume is not a reason to delete. Reverted to the agent's proposal: hidden, archived,
  huntable. The demo has no honest DISABLE - the class is shown by a mutant the corpus catches (step 5).

## 4. Intents and render

One YAML per decision in [`tuning/intents/`](../tuning/intents/), with route, risk and compensating control.

```
$ make render
render: 6 intents -> 26 files (0 changed)
```

Generated: Wazuh 4.x rules (100220-100226), Suricata `threshold.config`/`disable.conf` (empty in this demo), the
Wazuh 5 rule set, and logtest cases with the negatives each decision must not touch (look-alike addresses and
SIDs, reverse direction, other port, neighbour SID, the attack the card names). The RAISE and the ENRICH have no
routes: they apply to every event of their SID.

## 5. Verification on the engines

```
$ make test-logtest
engine: Wazuh v4.14.9 (revision rc2)
intent-dns-adtrack-resolver: 8 events, 8 cases, 0 failed
intent-http-basic-cleartext-raise: 3 events, 3 cases, 0 failed
intent-remote-admin-relay-context: 3 events, 3 cases, 0 failed
intent-smb-dll-print-drivers: 8 events, 8 cases, 0 failed
intent-smb-exe-distribution-share: 9 events, 9 cases, 0 failed
intent-smb-exe-domain-controllers: 17 events, 17 cases, 0 failed
severity-ladder: 8 events, 8 cases, 0 failed
smb-tuning: 11 events, 11 cases, 0 failed

$ make test-e2e          # corpus pcaps -> Suricata (with disable.conf) -> Wazuh with the generated rules
dcsync: 1 alerts, 0 problems
dns-tunnel: 6 alerts, 0 problems
http-beacon: 1 alerts, 0 problems
smb-dll: 2 alerts, 0 problems
smb-exe: 3 alerts, 0 problems
attacks visible 6/6, noise hidden 4/4, context as expected 1/1
```

`dns-tunnel` sends the tunnel, an ad lookup and a beacon hiding under the ad suffix through the same resolver: the
ad lookups are lowered by 100224, the tunnel signature still fires visibly for both tunnels. That is a regression
guard for the 9900001 decision, not a detection claim. `smb-dll` drops a DLL on a workstation's admin share next
to a driver read from print$.

Generated tests check that a rule does what its intent says. Mutants check that the corpus catches a wrong
decision - and a mutant counts as killed only if an attack was lost, not merely any check. Two were added with
this batch, one of them the DISABLE nobody should make:

```
$ make test-e2e-mutant
mutant killed: tests/corpus/mutants/disable-dll-family.yaml
mutant killed: tests/corpus/mutants/lower-admin-workstation.yaml
mutant killed: tests/corpus/mutants/lower-dll-second-print-server.yaml
mutant killed: tests/corpus/mutants/lower-internal-resolver.yaml
mutant killed: tests/corpus/mutants/suppress-admin-workstation.yaml

$ tools/corpus_test.py --extra-intent tests/corpus/mutants/lower-dll-second-print-server.yaml
FAIL smb-dll: DLL dropped on another workstation's admin share: expected visible, got rule 100227 level 3 0/1 alerts visible
attacks visible 5/6, noise hidden 4/4, context as expected 1/1
```

## 6. Effect

From the rule model that the logtest cases verify (`make metrics`, week 1): visible alerts **367 -> 59 a day
(-84%)**, while 50 a day of hidden cleartext-credential alerts become visible and the three lateral-transfer
events stay visible. Table: [README](../README.md#one-example).

## 7. The same snapshot over ssh

`make test-sensor-ssh` builds a lab sensor the way [`deploy/sensor/`](../deploy/sensor/README.md) tells an
administrator to (read-only account, the README's ACL commands verbatim, `install.sh`, the line from
`authorized_keys.example`) and runs the kit's `tools/snapshot.sh` from an analyst container:

```
PASS tools/snapshot.sh over ssh
PASS remote snapshot equals local (6118 alerts, 6 SIDs)
PASS rotated file read via the default ACL
PASS bounded EVE read
PASS config read
PASS second command refused
PASS write refused (a file the account owns stays)
PASS unbounded EVE dump refused
PASS terminal refused (no-pty)
PASS login without a command refused
PASS stdio forwarding refused (no-port-forwarding)
PASS modified snapshot script refused
PASS suricata.yaml unchanged
PASS sshd accepted the kit key
sensor-ssh: 14 checks, 0 failed
```

Broken on purpose: without the forced command the refusal checks fail; without the default ACL the snapshot fails on
the file rotated in later.

## What this does not prove

The traffic is synthetic and the owners are fictional; the decisions are only as good as their answers. The corpus
proves that tuning keeps an attack visible when its signature fires, not that the ruleset detects it. The lab
sensor is a container on one machine, not a production sensor with real capture.
