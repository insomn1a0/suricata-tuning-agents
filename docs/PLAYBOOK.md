# Playbook - lessons that keep tuning honest

## Decide
- Ask "what does the analyst do when this fires?" - not "how often does it fire". Volume is a reason to
  look, never a reason to hide.
- Lower, don't delete. A lowered event stays in archives and can be hunted; a disabled signature is gone.
- Suricata `suppress` is not a cheaper `lower`: the event never reaches the SIEM or its archives, and it can
  only track one address side (no port, no pair). Use it for sensor load, not for analyst noise.
  `DISABLE` is for parser/decoder noise that has no value anywhere.
- Every hiding decision names what could be missed and the compensating control (FIM on a share,
  EDR on servers, DC audit logs). If there is none, say so in the card.
- An address is not an identity in a DHCP range. Lowering needs a host from the inventory with a role and owner.
- A shared resolver, proxy or NAT is not a client. Alerts "from" it are everyone's alerts.

## Match exactly
- Pin the SID and the verified route: `dest_ip ^10\.10\.20\.15$` and `dest_port ^445$`, anchored pcre2.
  `10.10.20.15` without anchors also matches `10.10.20.150`.
- A union of routes is not a Cartesian product: `(A->X) OR (B->Y)` written as `src=(A|B), dst=(X|Y)` also
  lowers A->Y and B->X. Test the crossed pairs as negatives.
- Check which sibling Wazuh actually selects. Children of the same parent are evaluated in order;
  a reachable predicate is not the selected rule - only logtest shows that.
- `ignore="N"` is global for the rule, not per source: after one alert, every other source is archived for N seconds.
  Use it only when the first event is the signal.
- Verify how the decoder renders arrays and missing fields before matching on metadata.

## Test
- For every lowering: one positive, then negatives for neighbour SIDs under the same parent, prefix addresses,
  reverse direction, other port, missing metadata, and a repeat inside any `ignore` window.
- Signatures: syntax test (`suricata -T`) plus a pcap with one positive and the closest negatives
  (other opnum, legitimate source). Note what transport or encryption would evade it.
- Match versions. A pass on Suricata 8.0 in the lab does not prove behaviour on 7.0 in production.

## Evidence labels
Every claim in a card or MR carries one label, and never more than what actually ran:
`static` (read the rule/config) - `lint` - `logtest <version>` - `pcap-lab <version>` - `sensor-lab <version>`
(the sensor-side wrapper executed in a disposable Suricata container) - `live-sensor`
(aggregates from production) - `siem-query` (indexer aggregation).

## Data
- Raw telemetry never leaves the sensor or the laptop: agents return aggregates; snapshots, cards with real
  addresses and the journal are git-ignored.
- Nothing internal (addresses, hostnames, domains, payloads) goes to web search or external services.
- Descriptions use `$(src_ip)` / `$(dest_ip)`, not literals.
