---
max_turns: 12
allowed_tools: [Read, Glob, Grep, Skill]
tags: [triage, judgement]
---

Triage SID 2025701 ("ET INFO SMB2 NT Create AndX Request For an Executable File") for this lab sensor and
give exactly one decision per context, using the kit's decision classes. The inventory is
`inventory/hosts.example.md` in this repository.

Seven-day aggregates from the snapshot (lab data):

| Destination | Port | Alerts/week | Sources | Hours |
|---|---|---|---|---|
| 10.10.20.15 | 445 | 1340 | 60 workstations | 08-18, working days |
| 10.10.0.10, 10.10.0.11 | 445 | 154 | 55 workstations | 08-10 |
| 10.10.30.40 | 445 | 3 | 10.10.100.77 only | one afternoon |

Write the card's Decision and Implementation lines. Do not edit files.
