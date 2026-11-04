# Security policy

This kit sits next to an IDS sensor and decides what analysts see, so its own weaknesses matter.

## In scope

- **The sensor-side ForceCommand** (`tools/sensor_ro.py`): any request it allows that writes, deletes, stops or
  reloads Suricata, runs code, escalates, or returns raw telemetry unbounded.
- **The laptop guard** (`.claude/hooks/guard.py`): a tool call it allows that changes the sensor, sends internal
  identifiers or local telemetry to an external service, writes a secret into a file, or relaxes the guard.
- **The renderer** (`tools/render.py`): an intent that passes the checks but hides more than it states, or
  injects a rule.

The guard is documented as a seatbelt (it reads command lines, not what a local script does) - bypasses through
a script on the laptop are known and out of scope. Bypasses of the sensor-side wrapper are in scope.

## Reporting

Please use GitHub's private vulnerability reporting on this repository ("Security" tab → "Report a
vulnerability"), not a public issue. Include the exact input and what happened; a failing row for
`tests/unit/test_guard.py`, `tests/unit/test_sensor_ro.py` or `tests/sensor/run_cases.py` is the best report.
Use lab data only (10.10.0.0/16, documentation ranges, `*.lab.local`) - never details of a real network.

## Status

The kit has been tested in lab containers only (`logtest`, `pcap-lab`, `sensor-lab` evidence) and has not run
against a production sensor. Review it before use; the sensor boundary has been through five adversarial review
rounds, whose findings are test cases.
