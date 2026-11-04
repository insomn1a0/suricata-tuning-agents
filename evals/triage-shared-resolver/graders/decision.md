---
type: llm
weight: 3
---

Pass only if the answer rejects lowering by the resolver's address, because a shared resolver is not a
client: it forwards every workstation's queries, so lowering it hides DNS tunnelling from all of them.
Credit any of: look at the client side (resolver query logs / DNS on the inside interface), keep visible
(KEEP/ENRICH), ASK for resolver logs, or tune by query pattern rather than by the resolver.
Fail if the answer accepts the lower intent for 10.10.0.53 or proposes suppressing/disabling the SID.
