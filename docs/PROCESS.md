# Process

## The loop (one batch of work)

1. **Snapshot** - `tools/snapshot.sh 7`: per-SID aggregates from the sensor. Compare with the previous one
   (`tools/diff_snapshots.py`): new SIDs, spikes, SIDs that disappeared (possible breakage).
2. **Triage** - for candidates (top visible, top volume, new) the `noise-analyst` writes `cards/<SID>.md`
   with exactly one decision:

   | Class | Meaning | Where it is implemented |
   |---|---|---|
   | `KEEP` | actionable as is | nothing |
   | `ENRICH` | actionable, but the alert does not say what to check | Wazuh description / level / correlation |
   | `LOWER` | empty in an exact, verified context (SID + route + port) | Wazuh child rule below the visible level |
   | `DISABLE` | no value in any context (parser/decoder noise) | `disable.conf` on the sensor |
   | `RAISE` | hidden but a human should look | Wazuh child rule at/above the visible level |
   | `ASK` | needs the owner's knowledge (host role, policy) | a question in the card and the journal |

3. **Decision** - the user approves cards (`proposed` -> `approved`).
4. **Implementation** - Wazuh rule on a branch (`wazuh-rule-change`) or sensor change (`sensor-change`).
5. **Verification** - `make lint test-unit test-logtest` (+ `test-pcap` for signatures), then a SIEM
   query (`siem-query`) after deployment.
6. **Review** - `reviewer` agent once per batch, before the merge request.
7. **Journal** - `journal/WORK.md`: done / next / later / questions.

## Looking further (weekly, `scout`)

Trends between snapshots, ATT&CK coverage vs what is visible on the wire, unused engine features,
public rule sources. Ideas go to the journal with value and effort; nothing is implemented from here directly.

## Team and model choice

| Agent | Model | Job |
|---|---|---|
| `sensor-collector` | haiku | read-only facts from the sensor, aggregates only |
| `noise-analyst` | sonnet | triage cards: hypotheses, context, a proposal |
| `validator` | haiku | run tests, report raw PASS/FAIL/NOT_RUN |
| `reviewer` | opus | adversarial review of a batch before MR |
| `scout` | sonnet | trends, gaps, ideas |

Mechanical work goes to cheap models; judgement (main loop, review) to the strong one.
