#!/usr/bin/env bash
# Lab sensor start, following deploy/sensor/README.md: the ACL commands from it, the kit user's key (/lab/kit.pub)
# put into the line from deploy/sensor/authorized_keys.example, then sshd in the foreground.
set -euo pipefail
install -d -m 0755 /var/log/suricata /var/lib/suricata/rules
install -m 0640 /lab/eve/eve.json /var/log/suricata/eve.json

# deploy/sensor/README.md, step 1: the setfacl lines are read from the README itself, so a change there is tested
grep -E '^ +setfacl ' /opt/kit/deploy/sensor/README.md | sed 's/#.*//' > /tmp/readme-acls.sh
[ "$(wc -l < /tmp/readme-acls.sh)" -ge 2 ] || { echo "no setfacl lines in deploy/sensor/README.md" >&2; exit 1; }
bash -eu /tmp/readme-acls.sh

# Rotation after the ACLs, created like Suricata/logrotate do (plain open, umask 027 -> 0640): unreadable for the
# account unless the default ACL works. (Not `install -m`: coreutils install replaces inherited ACLs.)
(umask 027 && cp /lab/eve/eve.json.*.gz /var/log/suricata/)

home=/home/suricata-ro
install -d -m 0700 -o suricata-ro -g suricata-ro "$home/.ssh"
line="$(grep -v '^#' /opt/kit/deploy/sensor/authorized_keys.example | grep .)"
printf '%s %s\n' "${line%% ssh-ed25519 *}" "$(cat /lab/kit.pub)" > "$home/.ssh/authorized_keys"
chown suricata-ro:suricata-ro "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"

ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o PermitRootLogin=no
