# Suricata -> Wazuh tuning kit
# .venv (make venv) when present: tools/render.py needs PyYAML; everything on the sensor stays stdlib.
PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
export PY
# Config (engine versions, alert level, ID range) is read by tools/kitconfig.py, not by make:
# environment.env is shell syntax. Override per run: make test-logtest WAZUH_VERSION=4.14.8

.PHONY: help venv render demo lint test test-unit test-logtest test-pcap test-e2e test-e2e-mutant test-sensor-ro metrics attack-layer evals snapshot diff clean

help:
	@echo "make venv          local virtualenv with requirements.txt (PyYAML for tuning intents)"
	@echo "make render        tuning/intents -> Wazuh XML, Suricata threshold/disable, logtest cases"
	@echo "make metrics       recompute the README metrics block (demo week through the rule model)"
	@echo "make attack-layer  ATT&CK Navigator layer from local signatures + corpus (docs/attack-layer.json)"
	@echo "make evals         agent behaviour evals (claude plugin eval; costs model usage, not part of make test)"
	@echo "make demo          synthetic two-week dataset -> snapshots -> diff (no sensor, no Docker)"
	@echo "make lint          rule lint, generated files current, lab-data-only guard, doc links"
	@echo "make test-unit     unit tests (stdlib only)"
	@echo "make test-logtest  Wazuh logtest in Docker (wazuh/wazuh-manager:\$$WAZUH_VERSION)"
	@echo "make test-pcap     corpus pcaps -> Suricata, test.yaml checks (jasonish/suricata:\$$SURICATA_VERSION)"
	@echo "make test-e2e      corpus -> Suricata -> Wazuh with generated rules: no attack lost"
	@echo "make test-e2e-mutant  every bad intent in tests/corpus/mutants must make test-e2e fail"
	@echo "make test-sensor-ro   ssh ForceCommand wrapper with real execution in a Suricata container"
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

metrics:
	$(PY) tools/metrics.py --write

attack-layer:
	$(PY) tools/attack_layer.py

# Agent behaviour, not code: does the triage agent keep attacks visible, ask about unknown hosts, refuse to
# change the sensor without a plan and a yes, keep internal names off the web? Costs model usage (~$1/run).
evals:
	claude plugin eval . --runs 3 --no-publish --max-cost-usd 5

lint:
	$(PY) tools/render.py --check
	$(PY) tools/metrics.py --check
	$(PY) tools/attack_layer.py --check
	$(PY) tools/lint_rules.py
	$(PY) tools/check_lab_data.py
	$(PY) tools/check_links.py

test-unit:
	$(PY) -m unittest discover -s tests/unit -t .

test-logtest:
	$(PY) tools/check_logtest.py

test-pcap:
	$(PY) tools/corpus_test.py --engine

test-e2e:
	$(PY) tools/corpus_test.py

# A mutant is a plausible but wrong intent; the corpus must catch it (exit 1). Exit 2 = not run = failure.
test-e2e-mutant:
	@for m in tests/corpus/mutants/*.yaml; do \
	  $(PY) tools/corpus_test.py --extra-intent $$m > /dev/null; rc=$$?; \
	  if [ $$rc -eq 1 ]; then echo "mutant killed: $$m"; \
	  elif [ $$rc -eq 0 ]; then echo "MUTANT SURVIVED: $$m - the corpus does not cover this mistake"; exit 1; \
	  else echo "NOT_RUN: $$m (exit $$rc)"; exit 1; fi; done

# A disposable Suricata container plays the sensor; the wrapper runs every case for real (evidence: sensor-lab).
test-sensor-ro:
	docker run --rm --network none --entrypoint python3 \
	  -v "$(CURDIR)/tools/sensor_ro.py:/opt/sensor-ro/sensor_ro.py:ro" \
	  -v "$(CURDIR)/.claude/hooks/guard.py:/opt/sensor-ro/guard.py:ro" \
	  -v "$(CURDIR)/tools/sensor_snapshot.py:/opt/sensor-ro/sensor_snapshot.py:ro" \
	  -v "$(CURDIR)/tests/sensor:/tests:ro" \
	  "$$($(PY) tools/kitconfig.py | sed -n 's/^SURICATA_IMAGE=//p')" /tests/run_cases.py

test: lint test-unit test-logtest test-pcap test-e2e test-e2e-mutant test-sensor-ro

snapshot:
	tools/snapshot.sh 7

diff:
	$(PY) tools/diff_snapshots.py

clean:
	rm -rf examples/lab/data snapshots/demo-*.json
