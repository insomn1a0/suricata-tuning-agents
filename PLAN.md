# PLAN - from working prototype to a publishable project

Read this file first in every session. Work stage by stage; one feature branch and one PR per stage.
Tick tasks off here (`[x]`) as they are done and keep the "Status" line of each stage current.

## Hard constraints (apply to every stage)

- **Public repo, lab data only.** Addresses from 10.10.0.0/16 and documentation ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24); hostnames `*.lab.local`. No data, names, addresses, configs or
  numbers from any real employer environment - never ask for them, never read files outside this repo.
- Everything in git in English. Talk to the user in Russian.
- Never claim a test passed unless it ran in this session or in CI; label evidence (docs/PLAYBOOK.md).
- Never commit or push without the user's explicit "да". Small, reviewable commits.
- The user wants to understand every decision: after each stage, explain in Russian in 5-10 lines what
  changed and why, and list 2-3 questions an interviewer could ask about it.

## Background (researched 2026-11-03 - re-verify versions before pinning)

- Wazuh: latest stable 4.14.7; 5.0 is in beta. 5.0 drops XML rules (`etc/rules` does not exist; rules become
  Sigma-style YAML in the indexer, decoders YAML assets). Migration of custom rules is the user's job.
  -> The kit must not be married to 4.x XML: decisions are backend-neutral, XML is one adapter.
- Claude Code: CLAUDE.md is context, not enforcement. A PreToolUse hook that exits with code 2 blocks the tool
  call and shows stderr to Claude; any other non-zero exit does NOT block. Plugins bundle skills, agents, hooks
  and MCP servers and install as one unit. Verify current syntax in https://code.claude.com/docs before writing.
- Suricata: 8.0.x current. suricata-verify (OISF) is the standard pcap test format: `test.yaml` with `checks:`
  of `filter: {count: N, match: {alert.signature_id: X}}`. Suricata 8 has the `requires` keyword.
- Positioning: comparable projects put an LLM in the alert path (classify each alert at runtime).
  This kit keeps the LLM offline: it proposes configuration changes, deterministic engines verify them,
  no model runs in the alert path.

## Stage 1 - Green baseline
Status: done (PR #1) - all four suites green locally (macOS arm64) and in CI; repo private until made public.
- [x] `git init`, first commit of the current tree (after the user's yes), create GitHub repo `suricata-tuning-agents`.
- [x] Run `make lint test-unit demo`, then `make test-logtest` and `make test-pcap` locally with Docker.
      Fixed: CDB list ownership in the logtest container; analysisd fd limit on CI runners; pcap expectations
      keyed by IP pair (a wrong-opnum signature passed - found by mutation); make's `-include` of the shell
      env file kept quotes (-> `tools/kitconfig.py`).
- [x] Bump default `WAZUH_VERSION` to the latest 4.14.x stable: 4.14.9 (2026-10-15, not 4.14.7); Suricata pinned 8.0.8.
- [x] CI green on GitHub for all three jobs. Plus: SHA-pinned actions, least-privilege token, dependabot,
      ubuntu-24.04 runner, lab-data-only guard (`tools/check_lab_data.py`) in `make lint`.
Done when: all four suites pass locally and in CI; README test-status table matches reality.

## Stage 2 - Enforced safety (hooks) and plugin packaging
Status: done - guard (68-case table, mutation-checked, live-session verified), plugin installs with 5 skills,
5 agents, 1 hook.
- [x] `.claude/hooks/guard.py` + registration in `.claude/settings.json` (PreToolUse, matcher Bash and file tools):
      block (exit 2, clear stderr reason) - ssh to the sensor with write/restart/install verbs
      (rm, mv, cp, tee, >, sed -i, systemctl, kill, apt/dnf/pip install, tcpreplay, suricatasc reload) unless
      the command is the approved sensor-change path; `git push` / `git commit` (ask the user instead);
      reading or printing `config/environment.env` secrets is fine but writing tokens/passwords into any file is not;
      any command sending internal identifiers to the web (curl/wget with 10.x, hostnames from inventory).
- [x] Fail closed: if the guard crashes, the call is blocked (check docs for the current option).
      `onFailure: "block"` (>= 2.1.295) + exit 2 on any exception; both verified in a live session.
      Design change: remote commands use an allowlist (unknown -> ask); the first denylist version let
      vim, xargs rm, awk system(), tar -x, journalctl --vacuum, ip link set through. The reviewer then
      REJECTED v2 (dozens of bypasses: loops, `bash -lc`, `sudo -s < script`, `systemctl stop x status`,
      secrets in JSON); v3 recognises the safe path exactly and asks about the rest - all findings are table rows.
- [x] Unit tests for the guard: table of commands -> allow/block (at least 25 cases, incl. tricky quoting,
      `ssh host 'sudo -n cat x'` allowed vs `ssh host "sudo tee x"` blocked).
- [x] Package agents, skills and hooks as a Claude Code plugin + marketplace manifest in this repo, so users
      install with one command. Document install in README.
      Agents under `.claude/` are not loaded by plugins (found by `claude plugin details`): `agents` is a
      symlink to `.claude/agents`. Plugin mode lacks tools/ and CLAUDE.md -> `tools/init_workspace.sh`
      (onboarding step 0).
Done when: guard tests pass; plugin installs into a clean Claude Code session and the onboarding skill is visible.

## Stage 3 - Backend-neutral tuning intents
Status: done - two example intents render to the same rule behaviour (36/36 logtest cases on Wazuh 4.14.9, incl. the
hand-written smb-tuning oracle); a renderer that drops `$` is caught by generated and hand cases alike.
The reviewer REJECTED the first version (confirmed on 4.14.9): Wazuh orders siblings by level, not file
order; rationale text could inject a rule; test events copied the parent's metadata. Fixed: engine-order
model + overlap refusal, escaping + rule-ID assertion, intent carries the SID's real metadata and the parent
must be the ladder leaf it lands on; status required; lower needs dst+port and level >= 1.
- [x] Schema `tuning/schema.json` + one YAML file per decision in `tuning/intents/`, e.g. fields:
      id, sid(s), action (lower|enrich|raise|suppress|disable), match {src, dst, dst_port, proto, direction},
      rate_limit, visible_level, rationale, risk, compensating_control, card, tests {positive[], negative[]}.
- [x] `tools/render.py` adapters: `wazuh4-xml` (generates wazuh/rules from intents - the current XML becomes generated),
      `suricata-threshold` (threshold.config suppress/rate_filter + disable.conf), stub `wazuh5` with a clear TODO.
- [x] Tests derive from intent: the negative-case generator automatically adds prefix-IP, reverse direction,
      other port, neighbour SID and crossed pairs for multi-route intents. Logtest runs against generated XML.
- [x] Document the trade-off: Suricata `suppress` removes the event entirely; Wazuh lowering keeps it in archives.
- [x] Update skills (wazuh-rule-change -> tuning-change) and the example card to point at the intent.
      Decisions made: PyYAML is the only dependency (`make venv`; sensor-side code stays stdlib); schema is
      validated by a small built-in subset validator (no jsonschema); one rule per route; suppress refuses
      contexts Suricata cannot pin; lint rejects `^a|b$` (top-level alternation); 110.10/16 is allowed (only in generated intent tests)
      in lab data as the anchoring probe.
Done when: `make render && make test` regenerates identical XML for the two example intents and all tests pass.

## Stage 4 - Native Suricata tests in suricata-verify format + regression corpus
Status: done - attacks visible 4/4 on Suricata 8.0.8 + Wazuh 4.14.9; both mutants killed in CI.
- [x] Convert `tests/pcap/` to suricata-verify layout (`tests/suricata/<name>/test.yaml`, `test.rules`, pcap)
      and run it with the suricata-verify runner in Docker (or a compatible minimal runner if that is impractical -
      document why).
      Done as `tests/corpus/<case>/{input.pcap,test.yaml,siem.yaml}` with a minimal runner
      (`tools/corpus_test.py`): suricata-verify's run.py expects a source/build tree, the kit tests the
      packaged image. Rules and address groups are shared (`lab-standins.rules`, `suite.yaml`), not per test.
- [x] Regression corpus `tests/corpus/`: synthetic pcaps (stdlib/scapy generators, no third-party captures
      with unclear licence) for DCSync, SMB exe to admin share, periodic beacon to 203.0.113.x, DNS tunnelling-like
      long labels. Each with the expected *visible* outcome after all intents are applied.
- [x] CI job "no attack lost": corpus -> Suricata -> EVE -> Wazuh logtest with generated rules -> assert every corpus
      attack is still visible (level >= WAZUH_ALERT_LEVEL).
Done when: the end-to-end job is green and fails when a deliberately bad intent (e.g. lowering by subnet) is added.

## Stage 5 - Presentation
Status: not started
- [ ] Metrics in CI on demo data: visible alerts/day before vs after intents; corpus attacks visible N/N.
      Print as a job summary and as a README table generated by a script (no hand-typed numbers).
- [ ] ATT&CK Navigator layer generated from local signatures + corpus coverage.
- [ ] README: lead with the positioning (LLM offline, engines verify), architecture diagram, 60-second demo GIF
      or asciinema of `make demo` + one triage card, honest limitations, Wazuh 5 status.
- [ ] Short write-up `docs/WRITEUP.md` (later a blog post): problem, approach, what the tests caught.
Done when: a stranger can understand the project from the README in two minutes.

## Ideas found along the way (pick into a stage when it fits)
- Agent evals: synthetic snapshots with an expected decision per SID (e.g. 2025701 on the distribution share ->
  LOWER, to a workstation admin share -> KEEP); run the `noise-analyst` and score - tests the LLM behaviour,
  not just the code. Fits Stage 2 (plugin eval) or Stage 5.
- Mutation testing as a CI job: apply known-bad mutations (unanchor, drop `!$DC_SERVERS`, wrong opnum,
  widen a route) and assert the suites fail - turns the manual checks of Stage 1 into a guarantee. Fits Stage 4.
- Sensor-side boundary: `tools/sensor_ro.py` as an ssh `ForceCommand` that accepts only the guard's
  read forms (same validator code) + a sudoers template - moves enforcement from the laptop to the sensor.
- Pin engine images by digest (tag + sha256) in kitconfig; dependabot/renovate for the Docker tags.
- `ruff` + pre-commit (lint, lab-data guard) for contributors.
- Release tags per stage (`v0.1.0` = green baseline) with a CHANGELOG.
- Observed: the `wazuh/wazuh-manager:4.14.9` image reports `WAZUH_REVISION="rc2"`; keep the engine-reported
  version in evidence labels, not the tag.

## Later (not now)
- Behavioural analytics over EVE flow/krb5/dns (Kerberoasting, password spraying, DNS tunnelling, lateral fan-out).
- Sensor health check as a Wazuh command monitor.
- Wazuh 5 adapter once 5.0 is GA and its rule format is documented.
