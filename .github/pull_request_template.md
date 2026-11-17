## What and why

<!-- One change per PR. For a tuning decision, link the card or describe the context it is based on. -->

## Evidence

<!-- Which suites ran and where; label results (static / lint / logtest / pcap-lab / sensor-lab). Never claim more than ran. -->

- [ ] `make lint test-unit`
- [ ] Engine suites touched by the change (`test-logtest`, `test-pcap`, `test-e2e`, `test-e2e-mutant`, `test-sensor-ro`, `test-sensor-ssh`)

## Checklist

- [ ] Lab data only (10.10.0.0/16, documentation ranges, `*.lab.local`)
- [ ] Generated files come from `make render` / `make metrics`, not hand edits
- [ ] A new hiding decision has a corpus case or mutant that fails if it hides too much
- [ ] CHANGELOG updated for user-visible changes
