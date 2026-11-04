---
name: onboarding
description: First-run setup - interview the user about their Suricata/Wazuh environment and policy, fill config/environment.env and inventory/hosts.md, verify read-only access and versions, and start the journal. Use when config/environment.env is missing or the user asks to set up / reconfigure the kit.
---
# Onboarding

Goal: the other agents work on *this* environment and *this* user's policy, not on defaults.
Nothing here writes to the sensor or the SIEM.

0. **Workspace** - if `tools/snapshot.sh` is missing here, the kit was installed as a plugin into an empty
   directory. Ask the user, then run `"${CLAUDE_PLUGIN_ROOT}/tools/init_workspace.sh" .` (copies tools, rules,
   tests, templates and CLAUDE.md; never overwrites) and suggest `git init` so tuning work goes on branches.

1. **Interview** (one short question at a time, offer the default from `config/environment.example.env`):
   - Sensor: ssh target for a read-only account, whether sudo is needed to read, EVE log dir and file
     pattern (single `eve.json` or a separate alerts file), Suricata version.
   - Wazuh: version, which level analysts actually see (alert level / dashboard filter), how the sensor's
     events arrive (agent id + location string), a free custom rule ID range.
   - Policy: working hours, card language, autonomy (`propose` or `safe-auto`, see docs/SAFETY.md),
     who approves lowering rules, where the merge request goes.
   - Inventory: known servers with roles and owners; DHCP ranges. Write `inventory/hosts.md` from
     `inventory/hosts.example.md`. Unknown is fine - those hosts will produce ASK decisions.
2. **Write** `config/environment.env` and `inventory/hosts.md` (both git-ignored). No passwords, tokens or keys.
3. **Verify, read-only**, and report each check as OK / FAIL with the command output:
   - `ssh -o BatchMode=yes "$SENSOR_SSH" 'id; id'` - `sensor-ro: denied` means the sensor-side boundary
     (`deploy/sensor/`) is installed (it runs one command per login); two `id` lines mean it is not: tell the
     user, it is the sensor admin's job.
   - `ssh -o BatchMode=yes "$SENSOR_SSH" true`
   - `ssh ... "$SENSOR_SUDO suricata -V"` - compare with `SURICATA_VERSION`
   - `ssh ... "$SENSOR_SUDO ls -la $SURICATA_LOG_DIR"` - the alert files exist and are fresh
   - `ssh ... "$SENSOR_SUDO grep -c '^alert' $SURICATA_RULES_FILE"` - ruleset is where we think
   - `docker image inspect wazuh/wazuh-manager:$WAZUH_VERSION` (or pull) - logtest will match production
   - `RULE_ID_RANGE=... python3 tools/lint_rules.py` - no collisions with the repo rules
4. **First snapshot**: `tools/snapshot.sh 7`, then show the top 10 SIDs by volume and the top 10 visible ones.
5. **Journal**: create `journal/WORK.md` from `templates/journal.md` with the setup facts and open questions.
6. Tell the user what was configured, what failed, and the next step (usually: triage the top visible SIDs).
