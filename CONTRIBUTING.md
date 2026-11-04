# Contributing

## Ground rules

- **Lab data only.** Addresses from 10.10.0.0/16 and the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24), hostnames `*.lab.local`. Nothing from a real network - `make lint` rejects it.
- **Never claim more than ran.** Results carry an evidence label (`docs/PLAYBOOK.md`); a PR description says which
  suites ran where.
- **Generated files are not edited by hand**: `wazuh/rules/100220-suricata_tuning.xml`, `suricata/generated/`,
  `tests/logtest/intent-*`, the README metrics block, `docs/attack-layer.json`, `tests/corpus/*/input.pcap`.

## Setup and checks

```bash
make venv                  # PyYAML (+ `pip install -r requirements-dev.txt` for ruff)
make lint test-unit        # static: generated files current, rule lint, lab data, links, unit tests
make test-logtest test-pcap test-e2e test-e2e-mutant test-sensor-ro   # engines in Docker
ruff check .
```

Optional: `pip install pre-commit && pre-commit install` runs ruff and `make lint` before each commit.

## Changing things

- **A tuning decision**: an intent in `tuning/intents/` (see `.claude/skills/tuning-change/SKILL.md`), then
  `make render`. If the decision could hide an attack class the corpus does not cover, add a corpus case.
- **A guard or wrapper fix**: add the failing input as a row first (`tests/unit/test_guard.py`,
  `tests/unit/test_sensor_ro.py`, `tests/sensor/run_cases.py`), then fix. A test that never failed proves nothing.
- **A signature**: `suricata/rules/local.rules` plus a corpus case with positive and closest-negative traffic.
- Commits: small, imperative subject; one PR per change; CI green before review.
