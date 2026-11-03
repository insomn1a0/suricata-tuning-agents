---
name: sensor-change
description: Make a change on the Suricata sensor (disable.conf, suricata.yaml, local rules, agent config) safely with justification, backup, test and rollback. Use for any write on the sensor - only after the user's explicit yes.
---
# Sensor change

0. The user said yes to this exact change in this session. Otherwise stop.
1. **Justify**: what is broken or empty, with evidence (snapshot, counters, card). Host/route exceptions
   belong in Wazuh rules, not in Suricata - Suricata-side changes are for signatures that are noise everywhere.
2. **Backup** the exact files: `cp -a <file> <file>.bak-YYYYMMDD`.
3. **Change minimally**: scripted edit that asserts the old text occurs exactly once.
4. **Test before applying**: `suricata -T -c /etc/suricata/suricata.yaml` (plus `-S <file>` for new local rules).
   New local signatures are first proven with `make test-pcap`.
5. **Apply** with the distribution's normal mechanism (rule update + reload, e.g. `suricatasc -c reload-rules`).
6. **Verify after**: suricata.log shows the reload with 0 failed rules, alerts keep flowing, the Wazuh agent
   still reads the file, packet drop counters did not jump.
7. **Record** in the journal: what, why, backup path, exact rollback command.
