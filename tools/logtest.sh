#!/usr/bin/env bash
# Run events through Wazuh logtest with the rules/decoders from this repo, in a throwaway container
# with no network. One persistent logtest session per file, so `frequency`/`ignore` behave as live.
# Usage: tools/logtest.sh <events-file>      (line format: see tools/logtest_client.py)
# Env (from config/environment.env if present): WAZUH_VERSION, WAZUH_ALERT_LEVEL, WAZUH_LOCATION
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
[[ -f "$root/config/environment.env" ]] && source "$root/config/environment.env"
WAZUH_VERSION="${WAZUH_VERSION:-4.14.5}"
WAZUH_ALERT_LEVEL="${WAZUH_ALERT_LEVEL:-6}"
WAZUH_LOCATION="${WAZUH_LOCATION:-[001] (lab-sensor) any->/var/log/suricata/eve.json}"
input="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"

docker run --rm -i --network none --entrypoint "" \
  -e ALERT_LEVEL="$WAZUH_ALERT_LEVEL" -e LOCATION="$WAZUH_LOCATION" \
  -v "$root/wazuh:/input/wazuh:ro" -v "$input:/input/events.txt:ro" \
  -v "$here/logtest_client.py:/input/client.py:ro" \
  "wazuh/wazuh-manager:$WAZUH_VERSION" bash -c '
set -e
cp -a /var/ossec/data_tmp/exclusion/. / 2>/dev/null || true
sed -i "s|<log_alert_level>[0-9]*</log_alert_level>|<log_alert_level>${ALERT_LEVEL}</log_alert_level>|" /var/ossec/etc/ossec.conf
cp /input/wazuh/rules/*.xml /var/ossec/etc/rules/
if ls /input/wazuh/decoders/*.xml >/dev/null 2>&1; then cp /input/wazuh/decoders/*.xml /var/ossec/etc/decoders/; fi
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-db
for i in $(seq 1 50); do test -S /var/ossec/queue/db/wdb && break; sleep 0.2; done
/var/ossec/bin/wazuh-analysisd -f >/tmp/analysisd.log 2>&1 &
for i in $(seq 1 150); do test -S /var/ossec/queue/sockets/logtest && break; sleep 0.2; done
/var/ossec/framework/python/bin/python3 /input/client.py /input/events.txt "$LOCATION"
grep -E "ERROR|WARNING" /tmp/analysisd.log || true
'
