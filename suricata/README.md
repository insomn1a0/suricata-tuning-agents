# Local Suricata signatures

SID range 9100000-9199999. Every signature ships with a pcap case in `tests/pcap/cases.json`.

| SID | What | ATT&CK | Needs | Tested |
|---|---|---|---|---|
| 9100001 | DCSync: DRSUAPI `IDL_DRSGetNCChanges` (opnum 3) from a non-DC to a DC | T1003.006 | `DC_SERVERS` address group | pcap: workstation opnum 3 alerts; opnum 12 and DC->DC do not |

Known limits of 9100001: sees DCE/RPC over TCP; blind to SMB3-encrypted transport; legitimate
callers of GetNCChanges other than DCs (e.g. directory sync services) must be added to the exclusion
or to `DC_SERVERS`; every new DC/RODC must be added to `DC_SERVERS`.
