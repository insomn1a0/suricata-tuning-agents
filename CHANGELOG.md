# Changelog

## v1.0.0 - 2026-11-13

The whole loop on the demo, with the kit's own agents. Lab-tested only (logtest, pcap-lab, sensor-lab evidence).

- Every demo SID triaged by `noise-analyst` (cards in `examples/cards/`), owner answers as a demo scenario, a
  human review on top: all six decision classes, `docs/WALKTHROUGH.md` with the real command output.
- New intents: LOWER print drivers on print01, LOWER ad/tracking lookups via the resolver, ENRICH the remote-admin
  relay, RAISE cleartext Basic auth, DISABLE stream out-of-window noise.
- Ladder leaf 100207 (Minor/Medium, hidden as before): a RAISE needs a leaf parent, and the stock rule is not one -
  the documented RAISE class could not be implemented for the typical hidden alert.
- Corpus case `smb-dll` and DNS ad lookup next to the tunnel (same route, opposite decision); mutants
  `lower-dll-second-print-server` and `disable-dll-family` killed.
- `make test-sensor-ssh`: an sshd lab sensor set up with `install.sh` and the forced command; `tools/snapshot.sh`
  over real ssh equals a local snapshot of the same files; writes, chains, dumps, a shell, forwarding refused.
- Metrics count disabled SIDs as never visible; demo signature text for the fictional SIDs; real rule revisions
  in the demo data (the triage agent caught the mismatch).
- Fix: the sensor-lab test used a fixed date that fell out of the 7-day window a week after release.

## v0.1.0 - 2026-11-08

First release: stages 1-5 of PLAN.md. Lab-tested only (logtest, pcap-lab, sensor-lab evidence).

- README rewritten around "understand it in two minutes"; PLAN trimmed (history lives here and in WRITEUP).

- Real ET Open rules in the corpus (`make test-et-open`, CI job `real-ruleset`): fetched at test time from the
  BSD-licensed SID range, never committed; intent metadata checked against the real rule text; mutants killed.
- Corpus visibility means "seen at least once" (repeats archived by an ENRICH window are expected).
- Sensor wrapper: own flag allowlists for ip, ethtool, suricata, suricatasc, rpm, dpkg (no longer delegated to
  the guard); `suricata -T` refused - it wrote into the live log directory (review, reproduced in the lab).
- Experimental Wazuh 5 adapter (`wazuh5/rules/*.yml`, `wazuh5/GAPS.md`) after the 5.0.0-rc2 migration guide:
  LOWER as an exclusion in a per-SID rule, rate limits listed as gaps; rule model equals the 4.x cases; pySigma
  syntax check.

## 2026-11-04

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
