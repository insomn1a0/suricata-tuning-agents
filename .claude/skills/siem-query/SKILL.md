---
name: siem-query
description: Prepare Wazuh indexer (OpenSearch Dev Tools) aggregation queries for the user to run - delivery checks, rule-ID/level distributions, before/after comparisons. Use whenever manager-side evidence is needed.
---
# SIEM queries

- The user runs them and pastes back `hits.total` and `aggregations` only (`size: 0`). Never ask for raw hits,
  except `size: 1` with `_source` limited to named fields when a format must be confirmed.
- Indices: `wazuh-alerts-*` (alerts at or above the alert level), `wazuh-archives-*` (everything ingested, if enabled).
- Time field `timestamp`; use closed windows in UTC (end in the past) and compute the sensor-side reference
  number first, so the answer can be compared to something.
- Useful aggregations: `date_histogram` on `timestamp`, `terms` on `rule.id`, `rule.level`, `data.alert.signature_id`.

```json
GET wazuh-alerts-*/_search
{"size": 0, "track_total_hits": true,
 "query": {"bool": {"filter": [
   {"term": {"agent.id": "<sensor agent id>"}},
   {"range": {"timestamp": {"gte": "<UTC start>", "lt": "<UTC end>"}}}]}},
 "aggs": {"rule": {"terms": {"field": "rule.id", "size": 50},
   "aggs": {"sid": {"terms": {"field": "data.alert.signature_id", "size": 10}}}}}}
```
- Check `sum_other_doc_count` and `doc_count_error_upper_bound` before claiming a top-N is complete.
