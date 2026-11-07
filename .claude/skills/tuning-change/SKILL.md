---
name: tuning-change
description: Turn an approved triage card into a tuning intent (tuning/intents/*.yaml), render it into Wazuh rules / Suricata threshold files with derived tests, and verify. Use for any tuning decision that changes what analysts see.
---
# Tuning change

The decision is the intent; XML, threshold.config and the logtest cases are generated from it.
Never edit `wazuh/rules/100220-suricata_tuning.xml`, `suricata/generated/`, `wazuh5/` or
`tests/logtest/intent-*` by hand. On Wazuh 5 (experimental) read `wazuh5/GAPS.md` before deploying.

1. Only for a card with status `approved`. Work on a feature branch; never commit/push without the user's explicit yes.
2. **Write the intent** `tuning/intents/<id>.yaml` (schema: `tuning/schema.json`; examples next to it):
   - `action`: `lower` / `enrich` / `raise` keep the event in Wazuh archives; `suppress` drops it in Suricata
     (only by one address side - it cannot pin ports); `disable` turns the signature off everywhere.
     Prefer `lower` for anything with possible security value: a suppressed event cannot be hunted later.
   - `routes`: the exact verified contexts. Several routes = a union; each becomes its own rule, so `(A->X) or
     (B->Y)` never turns into a Cartesian product. A list inside one route is a deliberate product.
   - `rationale`, `risk`, `compensating_control`, `card` are required - they go into the rule comment.
   - `status: approved` is required (a draft is never rendered); `metadata` is the SID's real
     `signature_severity`/`confidence` from the rule text - it decides the ladder parent, and `wazuh.parent`
     must be that leaf. `make render` checks it against the rule text it can see: the repo's rules and
     `$SURICATA_RULES_CACHE` (git-ignored). Add the SID's rule line to the cache first (sensor-collector:
     `ssh -o BatchMode=yes "$SENSOR_SSH" "$SENSOR_SUDO grep -h 'sid:<SID>;' $SURICATA_RULES_FILE" >> "$SURICATA_RULES_CACHE"`);
     the corpus run also compares it with what Suricata writes into EVE. `lower` needs `dst` + `dst_port` and level >= 1; `rate_limit` only for `enrich`,
     one address per route. Routes of different intents must not overlap: Wazuh picks among siblings by
     level (level 0 first, then higher), not by file order.
   - Rule IDs from `$RULE_ID_RANGE`, free in the repo, the registry (`wazuh/README.md`, never reuse retired
     IDs) and the stock rules of the same version:
     `docker run --rm --entrypoint "" wazuh/wazuh-manager:$WAZUH_VERSION sh -c 'grep -rhoE "id=\"1[0-9]{5}\"" /var/ossec/ruleset/rules/'`.
   - `tests.neighbour_sids`: siblings of the family that must stay untouched; `tests.extra`: hand cases.
3. `make render` - generates the rules and the tests: positives, neighbour SIDs, prefix addresses on both
   sides, reverse direction, other port, crossed route pairs, repeats inside `ignore`.
4. `make lint test-unit`, then `make test-logtest` (or the validator agent); signatures also `make test-pcap`.
   Generated tests follow the intent - they cannot tell a wrong decision. The corpus (`make test-e2e`) can.
   Label results honestly (docs/PLAYBOOK.md).
5. Update the registry `wazuh/README.md`, the card (`Implementation:` -> the intent) and the journal.
