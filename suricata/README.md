# Local Suricata signatures

SID range 9100000-9189999. Every signature ships with a corpus case in `tests/corpus/<case>/` (pcap +
suricata-verify style `test.yaml` + `siem.yaml`). 9190000-9199999 is reserved for corpus-only lab rules.

`generated/` holds `threshold.config` and `disable.conf` rendered from `tuning/intents/` - do not edit.

| SID | What | ATT&CK | Needs | Tested |
|---|---|---|---|---|
| 9100001 | DCSync: DRSUAPI `IDL_DRSGetNCChanges` (opnum 3) from a non-DC to a DC | T1003.006 | `DC_SERVERS` address group | corpus `dcsync`: workstation opnum 3 alerts; opnum 12 and DC->DC do not |

Known limits of 9100001: sees DCE/RPC over TCP; blind to SMB3-encrypted transport; legitimate
callers of GetNCChanges other than DCs (e.g. directory sync services) must be added to the exclusion
or to `DC_SERVERS`; every new DC/RODC must be added to `DC_SERVERS`.

## Corpus stand-ins (`tests/corpus/lab-standins.rules`, never deployed)

The ET ruleset is not vendored. The corpus needs signatures that fire on its attacks, so it carries lab
stand-ins: `2025701` mimics the ET INFO SMB executable signature the tuning intents refer to (same SID and
metadata), `9190001` (beacon-like repeated HTTP check-ins) and `9190002` (DNS labels of 40+ characters) are
deliberately simple. They exist to prove that tuning does not hide an attack, not to detect one in production -
real beaconing and tunnelling detection belongs to behavioural analytics (PLAN, "Later").

`make test-et-open` swaps the stand-ins for the real ET Open rules with the same SIDs (2025701, 2025709;
`tests/corpus/suite.yaml`), downloaded by `tools/fetch_et_rules.py` at test time: the bundled LICENSE must
declare them BSD-licensed, and a changed `rev` is reported as drift. On the synthetic sessions the real 2025701
alerts twice per session (on the data packet and at stream close) - exact counts are relaxed to "at least one"
for those SIDs, visibility checks are unchanged.
