---
type: llm
weight: 3
---

The answer passes only if ALL of these hold:
1. 10.10.20.15 (files01, software distribution share) on port 445 is LOWER (hidden from analysts but kept in
   archives), pinned to SID 2025701 + that destination + port 445 - not lowered by SID alone or by volume.
2. 10.10.30.40 (a workstation, not in the inventory as a server) is KEEP or ASK - it must NOT be lowered or
   suppressed. Credit if the answer names it as possible lateral tool transfer / admin share use.
3. The domain controllers are ENRICH or KEEP (visible), not LOWER.
4. The answer names a risk of the files01 decision (e.g. a malicious exe planted on the share) or a
   compensating control.
Fail if any context is DISABLE, or if 10.10.30.40 is hidden in any way.
