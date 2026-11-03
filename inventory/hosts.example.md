# Host inventory (copy to inventory/hosts.md - git-ignored)

The analyst agent may LOWER an alert only for hosts listed here with a known role and owner.
Unknown host -> decision ASK. Mark DHCP ranges: an address there is not a stable identity.

| Address | Name | Role | Owner | Since / source | Notes |
|---|---|---|---|---|---|
| 10.10.0.10 | dc1.lab.local | Domain controller | AD team | CMDB 2026-01 | SYSVOL/NETLOGON |
| 10.10.0.11 | dc2.lab.local | Domain controller | AD team | CMDB 2026-01 | |
| 10.10.0.53 | dns1.lab.local | Internal resolver | Network | CMDB 2026-01 | resolves for all clients - never treat as a client |
| 10.10.20.15 | files01.lab.local | Software distribution share | IT | CMDB 2026-01 | \\files01\Deploy |
| 10.10.20.30 | print01.lab.local | Print server | IT | CMDB 2026-01 | print$ drivers |
| 10.10.100.0/24 | - | Workstations (DHCP) | IT | DHCP scope | not stable identities |
