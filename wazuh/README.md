# Wazuh rules

`rules/100200-suricata_rules.xml` - severity x confidence ladder for Suricata alerts and example tuning rules.
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
| 100220 | 3 | 100206 | 2025701 on software distribution share (LOWER) | examples/cards/2025701.md, smb-tuning |
| 100221 | 6, ignore 3600 | 100206 | 2025701 on domain controllers (ENRICH, rate-limited) | examples/cards/2025701.md, smb-tuning |

Held: 100207-100219 (ladder extensions). Retired: none. Never reuse a retired ID.
`tools/sensor_snapshot.py::predicted()` mirrors 100200-100206 - change both together.
