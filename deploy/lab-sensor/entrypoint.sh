#!/usr/bin/env bash
# Lab sensor start, following deploy/sensor/README.md: ACLs as written there, the kit user's key (/lab/kit.pub)
# put into the line from deploy/sensor/authorized_keys.example, then sshd in the foreground.
set -euo pipefail
install -d -m 0755 /var/log/suricata /var/lib/suricata/rules
install -m 0640 /lab/eve/eve.json /var/log/suricata/eve.json

# deploy/sensor/README.md, step 1 - verbatim
setfacl -R -m u:suricata-ro:rX /var/log/suricata /etc/suricata /var/lib/suricata/rules
setfacl -R -d -m u:suricata-ro:rX /var/log/suricata          # files rotated in later

# Rotation after the ACLs, created like Suricata/logrotate do (plain open, umask 027 -> 0640): unreadable for the
# account unless the default ACL works. (Not `install -m`: coreutils install replaces inherited ACLs.)
(umask 027 && cp /lab/eve/eve.json.1.gz /var/log/suricata/eve.json.1.gz)

home=/home/suricata-ro
install -d -m 0700 -o suricata-ro -g suricata-ro "$home/.ssh"
line="$(grep -v '^#' /opt/kit/deploy/sensor/authorized_keys.example | grep .)"
printf '%s %s\n' "${line%% ssh-ed25519 *}" "$(cat /lab/kit.pub)" > "$home/.ssh/authorized_keys"
chown suricata-ro:suricata-ro "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"

ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=no
