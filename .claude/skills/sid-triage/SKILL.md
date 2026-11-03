---
name: sid-triage
description: Triage one Suricata SID (noisy, hidden or new) into KEEP/ENRICH/LOWER/DISABLE/RAISE/ASK and write a card in cards/. Use when deciding what to do with an alert type.
---
# SID triage

1. **Data**: the SID's entry in the latest `snapshots/*-7d.json` (count, per_day, pairs, ports, worktime_share,
   predicted_level). Rule text from the sensor (read-only, see sensor-collector). Read what the rule
   actually matches - keywords, direction, buffers - not only its `msg`.
2. **Context**: roles from `inventory/hosts.md`; current handling in `wazuh/rules/*.xml`; earlier cards.
3. **The question**: "If an analyst sees this alert, what do they do?" If the answer is "nothing", it is empty -
   but only in the exact context where you verified that.
4. **Decide one class** (definitions in docs/PROCESS.md):
   - KEEP - actionable as is.
   - ENRICH - actionable, but the alert does not say what to check: better description, level or correlation.
   - LOWER - empty only in an exact, verified context (SID + route + port) -> Wazuh child rule below the
     visible level. Never by volume alone; every host involved must be in the inventory.
   - DISABLE - no value in any context (parser/decoder noise) -> `disable.conf` on the sensor.
   - RAISE - hidden (below visible level) but a human should look.
   - ASK - needs the user's knowledge; write the exact question.
5. **Card** `cards/<SID>.md` from `templates/card.md`, in `$CARD_LANGUAGE`. Mandatory fields: what could be
   missed after the change, compensating control, positive AND negative test cases.
6. Status starts as `proposed`. Only the user moves it to `approved`.
