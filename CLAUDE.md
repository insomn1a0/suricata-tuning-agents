# Suricata -> Wazuh tuning kit (instructions for Claude Code)

Developing the kit itself (open stages in PLAN.md): follow PLAN.md and do NOT run onboarding - there is no real sensor here.
Using the kit on a real sensor: if `config/environment.env` is missing, run the `onboarding` skill first.
Every session: read `PLAN.md` (current stage), `journal/WORK.md` (git-ignored; absent while developing the kit),
then `docs/PROCESS.md`. Lessons: `docs/PLAYBOOK.md`. Limits: `docs/SAFETY.md`.

## Ground rules
- Goal: alerts a human must act on; everything else prioritised; nothing with security value hidden.
- Talk to the user in their language; cards and journal in `$CARD_LANGUAGE`; everything in git in English.
- Git: feature branch only; commit / push / MR / deploy only after the user's explicit yes.
- Sensor: read-only through `sensor-collector`. Writes only via the `sensor-change` skill after an explicit yes.
- Exceptions for hosts/routes live in Wazuh rules, not in Suricata. Unknown host -> ASK.
- Rule IDs only from `$RULE_ID_RANGE`, checked against `wazuh/README.md`.
- Label evidence (static / lint / logtest / pcap-lab / sensor-lab / live-sensor / siem-query). Never claim more than ran.
- Raw telemetry never leaves the sensor/laptop; no internal identifiers to web or external services.

## Tools
- `tools/snapshot.sh [days]` - per-SID aggregates -> `snapshots/`; `tools/diff_snapshots.py` - compare two.
- `make lint test-unit test-logtest test-pcap` - static, unit, Wazuh logtest, Suricata pcap.
- SIEM: prepare `siem-query` aggregations; the user runs them.

## Token policy
Main loop on the strong model. Bulk/mechanical work to `.claude/agents` on cheaper models;
the `reviewer` (strong) once per batch or before risky sensor changes.
