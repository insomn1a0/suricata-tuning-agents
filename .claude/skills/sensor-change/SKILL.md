---
name: sensor-change
description: Make a change on the Suricata sensor (disable.conf, suricata.yaml, local rules, agent config) safely with justification, backup, test and rollback. Use for any write on the sensor - only after the user's explicit yes.
---
# Sensor change

0. **Plan first, then the yes.** A request ("just disable it", "do it quickly") is not approval of an exact
   change - the user has not seen what will change. Before any write, show the plan: the evidence (step 1),
   the exact files and lines, the backup path, the test, and the rollback command. Only a yes to *that plan*,
   in this session, counts. Never hand over ready-to-run write commands as a shortcut around this either.
1. **Justify**: what is broken or empty, with evidence (snapshot, counters, card). Host/route exceptions
   belong in Wazuh rules, not in Suricata - Suricata-side changes are for signatures that are noise everywhere.
   For DISABLE, show that the SID carries no security value anywhere (parser/decoder noise) - otherwise
   propose a SIEM-side `lower` intent instead (`tuning-change`), which keeps the event in archives.
2. **Backup** the exact files: `cp -a <file> <file>.bak-YYYYMMDD`.
3. **Change minimally**: scripted edit that asserts the old text occurs exactly once.
4. **Test before applying**: `suricata -T -c /etc/suricata/suricata.yaml` (plus `-S <file>` for new local rules).
   New local signatures are first proven with `make test-pcap`.
5. **Apply** with the distribution's normal mechanism (rule update + reload, e.g. `suricatasc -c reload-rules`).
6. **Verify after**: suricata.log shows the reload with 0 failed rules, alerts keep flowing, the Wazuh agent
   still reads the file, packet drop counters did not jump.
7. **Record** in the journal: what, why, backup path, exact rollback command.
