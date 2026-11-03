---
name: wazuh-rule-change
description: Add or change a Wazuh rule for Suricata alerts on a feature branch, with ID check, lint, logtest cases and registry update. Use for any edit in wazuh/rules.
---
# Wazuh rule change

1. Only for a card with status `approved`. Work on a feature branch; never commit/push without the user's explicit yes.
2. Keep parents before children; reuse an existing logical `<group>`; one rule per behaviour (merge two only
   if level, groups, parent and all other predicates agree).
3. ID inside `$RULE_ID_RANGE`, free in: the repo (`grep -rn 'id="<ID>"' wazuh/`), the registry `wazuh/README.md`
   (never reuse retired IDs), and stock rules of the same version:
   `docker run --rm --entrypoint "" wazuh/wazuh-manager:$WAZUH_VERSION sh -c 'grep -rhoE "id=\"1[0-9]{5}\"" /var/ossec/ruleset/rules/'`.
4. Predicates: `type="pcre2"` with `^...$` anchors for exact values; every predicate needs a written reason.
   A lowering rule pins the SID and the verified route. Union of routes is not a Cartesian product:
   `(A->X) OR (B->Y)` needs negatives for A->Y and B->X.
5. Descriptions in English, with decoded fields (`$(src_ip)`, `$(dest_ip)`), "possible/verify" when unproven.
   No literal IPs in descriptions.
6. Tests: `tests/logtest/<topic>.txt` (one EVE JSON per line) + `<topic>.expect`
   (`event_no rule_id level yes|no  # note`). Include positives, negatives, neighbour SIDs under the same
   parent, prefix addresses, reverse direction, other port, missing metadata, and repeats if `ignore` is used.
7. `make lint test-unit`, then `make test-logtest` (or the validator agent). Label results honestly (docs/PLAYBOOK.md).
8. Update `wazuh/README.md` (registry) and the journal.
