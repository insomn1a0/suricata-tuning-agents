# Wazuh rules

`rules/100200-suricata_rules.xml` - severity x confidence ladder for Suricata alerts (hand-written).
`rules/100220-suricata_tuning.xml` - tuning rules GENERATED from `tuning/intents/` by `make render`; do not edit.
Analyst-visible level in this kit: 6 (`WAZUH_ALERT_LEVEL`).

## Registry (range 100200-100299)

| ID | Level | Parent | What | Card / tests |
|---|---|---|---|---|
| 100200 | 10 | 86601 | Critical | severity-ladder |
| 100201 | 11 | 100200 | Critical / Medium confidence | severity-ladder |
| 100202 | 13 | 100200 | Critical / High confidence | severity-ladder |
| 100203 | 7 | 86601 | Major | severity-ladder |
| 100204 | 8 | 100203 | Major / Medium confidence | severity-ladder |
| 100205 | 9 | 100203 | Major / High confidence | severity-ladder |
| 100206 | 6 | 86601 | Minor / High confidence | severity-ladder |
| 100207 | 3 | 86601 | Minor / Medium confidence (hidden; parent for RAISE) | severity-ladder |
| 100220 | 3 | 100206 | 2025701 on software distribution share (LOWER) | intent smb-exe-distribution-share, smb-tuning |
| 100221 | 6, ignore 3600 | 100206 | 2025701 on dc1 (ENRICH, rate-limited) | intent smb-exe-domain-controllers, smb-tuning |
| 100222 | 6, ignore 3600 | 100206 | 2025701 on dc2 (ENRICH, rate-limited) | intent smb-exe-domain-controllers |
| 100223 | 3 | 100206 | 2025709 on print01 print$ (LOWER) | intent smb-dll-print-drivers |
| 100224 | 3 | 100206 | 9900001 via the internal resolver (LOWER, demo) | intent dns-adtrack-resolver |
| 100225 | 8 | 100204 | 9900002 with what to check (ENRICH, demo) | intent remote-admin-relay-context |
| 100226 | 7 | 100207 | 9900003 cleartext credentials (RAISE, demo) | intent http-basic-cleartext-raise |
| 100227 | 3 | 100206 | corpus mutant only - never deployed | tests/corpus/mutants/lower-dll-second-print-server.yaml |
| 100228 | 3 | 100204 | corpus mutant only - never deployed | tests/corpus/mutants/lower-internal-resolver.yaml |
| 100229 | 3 | 100206 | corpus mutant only - never deployed | tests/corpus/mutants/lower-admin-workstation.yaml |

Held: 100208-100219 (ladder extensions).
Retired: none. Never reuse a retired ID.
`tools/sensor_snapshot.py::predicted()` mirrors 100200-100207 - change both together.

Moving alerts onto the ladder changes their `rule.id`, description and groups (`suricata,custom` instead of the
stock `ids,suricata`): saved searches on `rule.id:86601` or `rule.groups:ids` miss them - search `rule.groups:suricata`.
Stock siblings of the ladder: Wazuh's threat-intel rules 99915-99918 (level 9, children of 86601) still win over
any ladder or tuning rule below level 9 when an address or domain is on their list.
Metadata arrays: the engine matches a value anywhere in the array (`confidence: [Medium, High]` lands on 100206);
the rule model and the snapshot read the first value - the engine side is the more visible one.
