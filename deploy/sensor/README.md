# Sensor-side boundary (for the sensor's administrator)

The laptop guard (`.claude/hooks/guard.py`) is a seatbelt: it reads the commands an agent runs, and anything
else on the laptop can bypass it. The boundary that holds is on the sensor. Three layers, cheapest first:

1. **A dedicated account that can only read.** No sudo if possible - give it read access to the logs instead:
   ```
   useradd --system --create-home --shell /bin/bash suricata-ro
   setfacl -R -m u:suricata-ro:rX /var/log/suricata /etc/suricata /var/lib/suricata/rules
   setfacl -R -d -m u:suricata-ro:rX /var/log/suricata          # files rotated in later
   ```
   Then set `SENSOR_SUDO=""` in the kit's `config/environment.env`. If `suricatasc` is needed, add the account
   to the group that owns the command socket instead of granting sudo.
2. **A ForceCommand for its key** - `tools/sensor_ro.py`. sshd runs it for every login, whatever was requested.
   No shell is involved: the command is split into argv, `|` pipelines are built in Python, and the only other
   operators are `2>/dev/null` and `2>&1` - so one command (or pipeline) per login, no `;` or `&&`, and nothing
   expands. Each stage must pass the guard's read-form checks; the snapshot script runs only if its sha256 is
   allowlisted. Every decision is logged to syslog (`auth`, tag `sensor-ro`, with `SSH_CONNECTION`; enable
   sshd `ExposeAuthInfo yes` to log the key as well).
3. **Optional sudo**, only if the ACLs are not possible - see `sudoers.example`. Never allow a file argument with
   a wildcard (`/usr/bin/cat /var/log/suricata/*` also allows `.../../../etc/shadow`). The wrapper passes
   `sudo -n <command>` through and sudoers decides; the example lists only `suricatasc`/`suricata` info commands,
   so the snapshot and config reads need the ACLs from step 1 (`SENSOR_SUDO=""`).

## Install

From a checkout of this repo, on the sensor, as root:
```
deploy/sensor/install.sh suricata-ro     # copies the wrapper, pins the snapshot script hash
```
Then put the kit user's public key into `~suricata-ro/.ssh/authorized_keys` with the forced command - see
`authorized_keys.example`. Re-run `install.sh` after updating the kit: it re-pins the snapshot hash, so an
unreviewed change to `tools/sensor_snapshot.py` cannot run.

## Check it from the laptop

```
ssh -o BatchMode=yes suricata-ro@sensor 'id; id'
```
`sensor-ro: denied - operator ';' ...` means the boundary is in place (the laptop guard allows two harmless
reads; only the sensor-side wrapper refuses a second command). Two `id` lines mean it is not.

Evidence for the wrapper: `make test-sensor-ro` - a Suricata container plays the sensor and every case runs for
real: reads succeed, refused writes leave `suricata.yaml` unchanged, a modified snapshot script does not run.
