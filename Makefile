# Suricata -> Wazuh tuning kit
# .venv (make venv) when present: tools/render.py needs PyYAML; everything on the sensor stays stdlib.
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
export PY
# Config (engine versions, alert level, ID range) is read by tools/kitconfig.py, not by make:
# environment.env is shell syntax. Override per run: make test-logtest WAZUH_VERSION=4.14.8

.PHONY: help venv render demo lint test test-unit test-logtest test-pcap snapshot diff clean

help:
	@echo "make venv          local virtualenv with requirements.txt (PyYAML for tuning intents)"
	@echo "make render        tuning/intents -> Wazuh XML, Suricata threshold/disable, logtest cases"
	@echo "make demo          synthetic two-week dataset -> snapshots -> diff (no sensor, no Docker)"
	@echo "make lint          rule lint, generated files current, lab-data-only guard, doc links"
	@echo "make test-unit     unit tests (stdlib only)"
	@echo "make test-logtest  Wazuh logtest in Docker (wazuh/wazuh-manager:\$$WAZUH_VERSION)"
	@echo "make test-pcap     Suricata pcap tests in Docker (jasonish/suricata:\$$SURICATA_VERSION)"
	@echo "make test          all of the above"
	@echo "make snapshot      7-day snapshot from the sensor in config/environment.env"

demo:
	$(PY) examples/lab/make_sample_eve.py examples/lab/data
	@mkdir -p snapshots
	$(PY) tools/sensor_snapshot.py --eve-glob 'examples/lab/data/week1/*.json' --now 2026-01-12T00:00:00+01:00 > snapshots/demo-week1-7d.json
	$(PY) tools/sensor_snapshot.py --eve-glob 'examples/lab/data/week2/*.json' --now 2026-01-19T00:00:00+01:00 > snapshots/demo-week2-7d.json
	$(PY) tools/diff_snapshots.py snapshots/demo-week1-7d.json snapshots/demo-week2-7d.json

venv:
	python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt

render:
	$(PY) tools/render.py

lint:
	$(PY) tools/render.py --check
	$(PY) tools/lint_rules.py
	$(PY) tools/check_lab_data.py
	$(PY) tools/check_links.py

test-unit:
	$(PY) -m unittest discover -s tests/unit -t .

test-logtest:
	$(PY) tools/check_logtest.py

test-pcap:
	$(PY) tools/pcap_test.py

test: lint test-unit test-logtest test-pcap

snapshot:
	tools/snapshot.sh 7

diff:
	$(PY) tools/diff_snapshots.py

clean:
	rm -rf examples/lab/data snapshots/demo-*.json
