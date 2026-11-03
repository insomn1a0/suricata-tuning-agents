#!/usr/bin/env bash
# Run events through Wazuh logtest with the rules/decoders from this repo, in a throwaway container
# with no network. One persistent logtest session per file, so `frequency`/`ignore` behave as live.
# Usage: tools/logtest.sh <events-file>      (line format: see tools/logtest_client.py)
# Config via tools/kitconfig.py (defaults < config/environment.env < env): WAZUH_VERSION, WAZUH_ALERT_LEVEL, WAZUH_LOCATION
# LOGTEST_DOCKER_ARGS: extra docker run flags, e.g. "--ulimit nofile=65536:65536" to reproduce CI limits.
# WAZUH_RULES_DIR: rules/decoders to load instead of ./wazuh (tools/corpus_test.py --extra-intent).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
eval "$("${PY:-python3}" "$here/kitconfig.py" --shell)"
input="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"

docker run --rm -i --network none --entrypoint "" ${LOGTEST_DOCKER_ARGS:-} \
  -e ALERT_LEVEL="$WAZUH_ALERT_LEVEL" -e LOCATION="$WAZUH_LOCATION" \
  -v "${WAZUH_RULES_DIR:-$root/wazuh}:/input/wazuh:ro" -v "$input:/input/events.txt:ro" \
  -v "$here/logtest_client.py:/input/client.py:ro" \
  "wazuh/wazuh-manager:$WAZUH_VERSION" bash -c '
set -e
cp -a /var/ossec/data_tmp/exclusion/. / 2>/dev/null || true
# The image entrypoint normally fixes ownership; we bypass it, so analysisd (running as wazuh) could not compile CDB lists.
chown -R wazuh:wazuh /var/ossec/etc/lists
# analysisd asks for 458752 fds by default; CI runners cap the container lower (ERROR "Could not set resource limit").
echo "analysisd.rlimit_nofile=$(ulimit -Hn)" >> /var/ossec/etc/local_internal_options.conf
sed -i "s|<log_alert_level>[0-9]*</log_alert_level>|<log_alert_level>${ALERT_LEVEL}</log_alert_level>|" /var/ossec/etc/ossec.conf
cp /input/wazuh/rules/*.xml /var/ossec/etc/rules/
if ls /input/wazuh/decoders/*.xml >/dev/null 2>&1; then cp /input/wazuh/decoders/*.xml /var/ossec/etc/decoders/; fi
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-db
for i in $(seq 1 50); do test -S /var/ossec/queue/db/wdb && break; sleep 0.2; done
/var/ossec/bin/wazuh-analysisd -f >/tmp/analysisd.log 2>&1 &
for i in $(seq 1 150); do test -S /var/ossec/queue/sockets/logtest && break; sleep 0.2; done
eval "$(/var/ossec/bin/wazuh-control info)"
echo "engine: Wazuh $WAZUH_VERSION (revision $WAZUH_REVISION)"
/var/ossec/framework/python/bin/python3 /input/client.py /input/events.txt "$LOCATION"
grep -E "ERROR|WARNING" /tmp/analysisd.log || true
'
