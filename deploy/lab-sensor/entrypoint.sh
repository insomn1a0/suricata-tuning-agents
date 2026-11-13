#!/usr/bin/env bash
# Lab sensor start: lab EVE from /lab/eve (mounted), the kit user's key from /lab/kit.pub with the forced
# command exactly as in deploy/sensor/authorized_keys.example, then sshd in the foreground.
set -euo pipefail
install -d -m 0755 /var/log/suricata
cp /lab/eve/* /var/log/suricata/
setfacl -R -m u:suricata-ro:rX /var/log/suricata /etc/suricata

home=/home/suricata-ro
install -d -m 0700 -o suricata-ro -g suricata-ro "$home/.ssh"
printf 'command="/usr/local/bin/sensor-ro",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-user-rc %s\n' \
  "$(cat /lab/kit.pub)" > "$home/.ssh/authorized_keys"
chown suricata-ro:suricata-ro "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"

ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=no
