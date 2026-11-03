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
Status: not started
- [ ] `git init`, first commit of the current tree (after the user's yes), create GitHub repo `suricata-tuning-agents`.
- [ ] Run `make lint test-unit demo`, then `make test-logtest` and `make test-pcap` locally with Docker.
      These two have NEVER been executed yet - expect fixes (logtest container setup, `--set` of the
      DC_SERVERS address group, jasonish/suricata entrypoint/permissions, eve.json path).
- [ ] Bump default `WAZUH_VERSION` to the latest 4.14.x stable (check), keep it configurable.
- [ ] CI green on GitHub for all three jobs.
Done when: all four suites pass locally and in CI; README test-status table matches reality.

## Stage 2 - Enforced safety (hooks) and plugin packaging
Status: not started
- [ ] `.claude/hooks/guard.py` + registration in `.claude/settings.json` (PreToolUse, matcher Bash and file tools):
      block (exit 2, clear stderr reason) - ssh to the sensor with write/restart/install verbs
      (rm, mv, cp, tee, >, sed -i, systemctl, kill, apt/dnf/pip install, tcpreplay, suricatasc reload) unless
      the command is the approved sensor-change path; `git push` / `git commit` (ask the user instead);
      reading or printing `config/environment.env` secrets is fine but writing tokens/passwords into any file is not;
      any command sending internal identifiers to the web (curl/wget with 10.x, hostnames from inventory).
- [ ] Fail closed: if the guard crashes, the call is blocked (check docs for the current option).
- [ ] Unit tests for the guard: table of commands -> allow/block (at least 25 cases, incl. tricky quoting,
      `ssh host 'sudo -n cat x'` allowed vs `ssh host "sudo tee x"` blocked).
- [ ] Package agents, skills and hooks as a Claude Code plugin + marketplace manifest in this repo, so users
      install with one command. Document install in README.
Done when: guard tests pass; plugin installs into a clean Claude Code session and the onboarding skill is visible.

## Stage 3 - Backend-neutral tuning intents
Status: not started
- [ ] Schema `tuning/schema.json` + one YAML file per decision in `tuning/intents/`, e.g. fields:
      id, sid(s), action (lower|enrich|raise|suppress|disable), match {src, dst, dst_port, proto, direction},
      rate_limit, visible_level, rationale, risk, compensating_control, card, tests {positive[], negative[]}.
- [ ] `tools/render.py` adapters: `wazuh4-xml` (generates wazuh/rules from intents - the current XML becomes generated),
      `suricata-threshold` (threshold.config suppress/rate_filter + disable.conf), stub `wazuh5` with a clear TODO.
- [ ] Tests derive from intent: the negative-case generator automatically adds prefix-IP, reverse direction,
      other port, neighbour SID and crossed pairs for multi-route intents. Logtest runs against generated XML.
- [ ] Document the trade-off: Suricata `suppress` removes the event entirely; Wazuh lowering keeps it in archives.
- [ ] Update skills (wazuh-rule-change -> tuning-change) and the example card to point at the intent.
Done when: `make render && make test` regenerates identical XML for the two example intents and all tests pass.

## Stage 4 - Native Suricata tests in suricata-verify format + regression corpus
Status: not started
- [ ] Convert `tests/pcap/` to suricata-verify layout (`tests/suricata/<name>/test.yaml`, `test.rules`, pcap)
      and run it with the suricata-verify runner in Docker (or a compatible minimal runner if that is impractical -
      document why).
- [ ] Regression corpus `tests/corpus/`: synthetic pcaps (stdlib/scapy generators, no third-party captures
      with unclear licence) for DCSync, SMB exe to admin share, periodic beacon to 203.0.113.x, DNS tunnelling-like
      long labels. Each with the expected *visible* outcome after all intents are applied.
- [ ] CI job "no attack lost": corpus -> Suricata -> EVE -> Wazuh logtest with generated rules -> assert every corpus
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

## Later (not now)
- Behavioural analytics over EVE flow/krb5/dns (Kerberoasting, password spraying, DNS tunnelling, lateral fan-out).
- Sensor health check as a Wazuh command monitor.
- Wazuh 5 adapter once 5.0 is GA and its rule format is documented.
