#!/usr/bin/env bash
# Install the sensor-side ForceCommand (run on the sensor, as root, from a checkout of the kit).
# Usage: deploy/sensor/install.sh <read-only-account>
# Copies tools/sensor_ro.py + the guard it reuses to /usr/local/lib/sensor-ro, creates /usr/local/bin/sensor-ro,
# and pins the sha256 of tools/sensor_snapshot.py in /etc/sensor-ro/allowed-sha256. Does not touch sshd_config
# or authorized_keys - see deploy/sensor/README.md.
set -euo pipefail
account="${1:?usage: install.sh <read-only-account>}"
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
id "$account" >/dev/null
src="$(cd "$(dirname "$0")/../.." && pwd)"
lib=/usr/local/lib/sensor-ro

install -d -m 0755 "$lib" /etc/sensor-ro
install -m 0644 "$src/tools/sensor_ro.py" "$lib/sensor_ro.py"
install -m 0644 "$src/.claude/hooks/guard.py" "$lib/guard.py"
cat > /usr/local/bin/sensor-ro <<EOF
#!/bin/sh
exec /usr/bin/python3 -I $lib/sensor_ro.py
EOF
chmod 0755 /usr/local/bin/sensor-ro
sum="$(sha256sum "$src/tools/sensor_snapshot.py" | cut -d' ' -f1)"
printf '# sha256 of scripts the kit may run via stdin - written by install.sh\n%s  tools/sensor_snapshot.py\n' "$sum" \
  > /etc/sensor-ro/allowed-sha256
chmod 0644 /etc/sensor-ro/allowed-sha256
chown -R root:root "$lib" /etc/sensor-ro
echo "installed: /usr/local/bin/sensor-ro (snapshot sha256 ${sum:0:12}) for account $account"
echo "next: forced command in ~$account/.ssh/authorized_keys - see deploy/sensor/authorized_keys.example"
