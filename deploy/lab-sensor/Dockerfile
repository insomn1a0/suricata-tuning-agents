# A disposable lab sensor: the pinned Suricata image + sshd, set up the way deploy/sensor/README.md tells a
# sensor administrator to - read-only account, ACLs, ForceCommand installed by deploy/sensor/install.sh.
# Built and run by tests/sensor/ssh_e2e.py (make test-sensor-ssh); the build needs network for the packages.
ARG SURICATA_IMAGE
FROM ${SURICATA_IMAGE}

RUN dnf -y -q install openssh-server openssh-clients acl && dnf clean all

# The kit files install.sh expects, at their repo paths
COPY tools/sensor_ro.py tools/sensor_snapshot.py /opt/kit/tools/
COPY .claude/hooks/guard.py /opt/kit/.claude/hooks/
COPY deploy/sensor/install.sh /opt/kit/deploy/sensor/
COPY deploy/lab-sensor/entrypoint.sh /usr/local/sbin/lab-sensor

RUN useradd --system --create-home --shell /bin/bash suricata-ro \
 && /opt/kit/deploy/sensor/install.sh suricata-ro \
 && useradd --create-home --shell /bin/bash analyst

ENTRYPOINT ["/usr/local/sbin/lab-sensor"]
