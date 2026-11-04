# Changelog

## Unreleased

- Sensor-side boundary: `tools/sensor_ro.py` ssh ForceCommand - no shell, per-command flag allowlist, files only
  in the first pipeline stage, bounded raw telemetry, snapshot pinned by sha256, rlimits; `deploy/sensor/`;
  `make test-sensor-ro` (lab container). Five adversarial review rounds.
- Intent metadata checked against the rule text (`make render`) and against EVE (corpus run).
- Generated README metrics (`make metrics`) and ATT&CK Navigator layer (`make attack-layer`), both checked in lint;
  CI job summary with the engine-verified corpus result.
- Agent behaviour evals (`evals/`, `make evals`); the sensor-change skill now requires a plan and a yes to it.
- Engine images pinned by digest; ruff config, pre-commit, SECURITY.md, CONTRIBUTING.md, `docs/WRITEUP.md`.

## Stage 4 - regression corpus (#5)

- `tests/corpus/`: synthetic attacks and benign traffic (suricata-verify style checks, SIEM expectations).
- `make test-e2e`: corpus → Suricata (with generated threshold/disable) → Wazuh with generated rules.
- `make test-e2e-mutant`: plausible-but-wrong intents must fail the corpus. A surviving mutant exposed that
  Suricata ignores threshold lines with a trailing comment.

## Stage 3 - backend-neutral tuning intents (#4)

- `tuning/intents/*.yaml` + schema; `make render` → Wazuh 4.x XML, Suricata threshold/disable, logtest cases.
- Engine-order model of Wazuh sibling selection, overlap refusal, escaping, real SID metadata.

## Stage 2 - enforced guard and plugin (#3)

- PreToolUse guard (fails closed), two review rounds; plugin + marketplace manifests; gitleaks in CI.

## Stage 1 - green baseline (#1, #2)

- First run of the Docker suites and the fixes they needed; single config source; lab-data and link checks.
