"""The whole ssh path, for real: a lab sensor container (sshd, read-only account with ACLs, ForceCommand installed
by deploy/sensor/install.sh, authorized_keys as in the example) and an analyst container that runs the kit's own
tools/snapshot.sh and ssh reads against it over an internal Docker network. Evidence label: sensor-lab.

Checks: the remote snapshot equals a local snapshot of the same files; bounded reads work; a second command,
a write, an interactive login, stdio forwarding and a modified snapshot script are refused; nothing changed.
Exit: 0 pass, 1 a check failed, 2 not run (no docker, build failed).
Usage: ssh_e2e.py [--keep]   (--keep leaves the containers and the temp dir for debugging)"""
import datetime
import gzip
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "examples" / "lab"))
import kitconfig  # noqa: E402
import make_sample_eve  # noqa: E402

IMAGE = "sro-lab-sensor:local"
CONTEXT = ["tools/sensor_ro.py", "tools/sensor_snapshot.py", ".claude/hooks/guard.py", "deploy/sensor/install.sh",
           "deploy/lab-sensor/entrypoint.sh", "deploy/lab-sensor/Dockerfile"]
SNAP_ARGS = "--days 7 --logdir '/var/log/suricata' --pattern 'eve.json*' --work-hours '8-19'"


def sh(*cmd, stdin=None, check=False):
    r = subprocess.run(cmd, input=stdin, capture_output=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}: rc={r.returncode} {r.stderr.decode(errors='replace')[-800:]}")
    return r


def lab_data(tmp):
    """Two demo weeks ending today: week 2 is eve.json, week 1 the rotated eve.json.1.gz."""
    first = (datetime.date.today() - datetime.timedelta(days=13)).isoformat()
    make_sample_eve.main(str(tmp / "gen"), first)
    eve = tmp / "eve"
    eve.mkdir()
    shutil.copy(tmp / "gen" / "week2" / "eve.json", eve / "eve.json")
    with open(tmp / "gen" / "week1" / "eve.json", "rb") as f, gzip.open(eve / "eve.json.1.gz", "wb") as g:
        g.write(f.read())
    return eve


def build(tmp, image):
    ctx = tmp / "ctx"
    for rel in CONTEXT:
        (ctx / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, ctx / rel)
    sh("docker", "build", "-q", "-t", IMAGE, "--build-arg", f"SURICATA_IMAGE={image}",
       "-f", str(ctx / "deploy/lab-sensor/Dockerfile"), str(ctx), check=True)


def main():
    keep = "--keep" in sys.argv
    if not shutil.which("docker") or sh("docker", "info").returncode:
        print("NOT_RUN: docker is not available")
        return 2
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="sro-ssh-"))
    tag = f"sro-{os.getpid()}"
    net, sensor, client = f"{tag}-net", f"{tag}-sensor", f"{tag}-analyst"
    results = []

    def check(name, ok, detail=b""):
        results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'} {name}" + ("" if ok else f": {detail[:400]!r}"))

    try:
        eve = lab_data(tmp)
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "analyst@lab", "-f", str(tmp / "id"), check=True)
        shutil.copy(tmp / "id.pub", tmp / "kit.pub")
        try:
            build(tmp, kitconfig.images(kitconfig.load())["SURICATA_IMAGE"])
        except RuntimeError as e:
            print(f"NOT_RUN: lab sensor image did not build: {e}")
            return 2
        sh("docker", "network", "create", "--internal", net, check=True)
        sh("docker", "run", "-d", "--name", sensor, "--network", net, "--network-alias", "sensor",
           "-v", f"{eve}:/lab/eve:ro", "-v", f"{tmp / 'kit.pub'}:/lab/kit.pub:ro", IMAGE, check=True)
        for _ in range(50):
            hostkey = sh("docker", "exec", sensor, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").stdout.decode()
            if hostkey and b"Server listening" in sh("docker", "logs", sensor).stderr:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError("sshd did not start: " + sh("docker", "logs", sensor).stderr.decode()[-800:])

        # The analyst side: the kit's tools and an ssh config, as on a laptop
        cfg = tmp / "client"
        cfg.mkdir()
        shutil.copy(tmp / "id", cfg / "id")
        (cfg / "known_hosts").write_text("sensor " + " ".join(hostkey.split()[:2]) + "\n")
        (cfg / "config").write_text("Host lab-sensor\n  HostName sensor\n  User suricata-ro\n"
                                    "  IdentityFile ~/.ssh/id\n  UserKnownHostsFile ~/.ssh/known_hosts\n"
                                    "  StrictHostKeyChecking yes\n  BatchMode yes\n")
        (cfg / "environment.env").write_text('SENSOR_SSH="lab-sensor"\nSENSOR_SUDO=""\n'
                                             'SURICATA_LOG_DIR="/var/log/suricata"\nSURICATA_ALERT_GLOB="eve.json*"\n'
                                             'WORK_HOURS="8-19"\n')
        sh("docker", "run", "-d", "--name", client, "--network", net, "--entrypoint", "sleep",
           "-v", f"{ROOT / 'tools'}:/src/tools:ro", "-v", f"{cfg}:/lab:ro", IMAGE, "infinity", check=True)
        sh("docker", "exec", "-u", "analyst", client, "bash", "-c",
           "mkdir -p ~/.ssh ~/kit/config && cp /lab/id /lab/known_hosts /lab/config ~/.ssh/ && chmod 600 ~/.ssh/* "
           "&& cp -r /src/tools ~/kit/ && cp /lab/environment.env ~/kit/config/", check=True)

        def ssh(command, *opts, stdin=None):
            return sh("docker", "exec", "-i", "-u", "analyst", client, "ssh", *opts, "lab-sensor", command,
                      stdin=stdin)

        def denied(r):
            return r.returncode != 0 and b"sensor-ro: denied" in r.stderr

        config_before = sh("docker", "exec", sensor, "sha256sum", "/etc/suricata/suricata.yaml").stdout

        # 1. the kit's snapshot over ssh == the same code on the same files locally
        r = sh("docker", "exec", "-u", "analyst", client, "bash", "-c", "cd ~/kit && tools/snapshot.sh 7")
        check("tools/snapshot.sh over ssh", r.returncode == 0 and b"alerts=" in r.stdout, r.stderr or r.stdout)
        if r.returncode == 0:
            path = r.stdout.decode().split(":")[0].strip()
            remote = json.loads(sh("docker", "exec", client, "cat", path, check=True).stdout)
            local = json.loads(sh(sys.executable, str(ROOT / "tools" / "sensor_snapshot.py"), "--eve-glob",
                                  str(eve / "eve.json*"), "--days", "7", "--work-hours", "8-19",
                                  "--now", remote["generated_utc"], check=True).stdout)
            same = {k: remote[k] == local[k] for k in ("alerts", "visible", "sids")}
            check(f"remote snapshot equals local ({remote['alerts']} alerts, {len(remote['sids'])} SIDs)",
                  all(same.values()) and remote["alerts"] > 0, json.dumps(same).encode())
            check("both rotated files read", len(remote["files"]) == 2, json.dumps(remote["files"]).encode())

        # 2. bounded reads the sensor-collector uses
        r = ssh("tail -n 5 /var/log/suricata/eve.json | wc -l")
        check("bounded EVE read", r.returncode == 0 and r.stdout.strip() == b"5", r.stderr or r.stdout)
        r = ssh("grep -c '^vars:' /etc/suricata/suricata.yaml")
        check("config read", r.returncode == 0 and r.stdout.strip() == b"1", r.stderr or r.stdout)

        # 3. what the boundary must refuse, whatever the laptop sends
        check("second command refused", denied(ssh("id; id")), ssh("id; id").stdout)
        r = ssh("rm -f /etc/suricata/suricata.yaml")
        check("write refused", denied(r), r.stderr)
        r = ssh("cat /var/log/suricata/eve.json")
        check("unbounded EVE dump refused", denied(r), r.stderr)
        # no-pty refuses the terminal; the forced command then sees an empty command and runs nothing
        r = sh("docker", "exec", "-i", "-u", "analyst", client, "ssh", "-tt", "lab-sensor", stdin=b"id\nexit\n")
        check("interactive login gets no shell", r.returncode != 0 and b"uid=" not in r.stdout + r.stderr,
              f"rc={r.returncode} ".encode() + r.stdout + r.stderr)
        r = sh("docker", "exec", "-u", "analyst", client, "ssh", "-W", "sensor:22", "lab-sensor")
        check("stdio forwarding refused (no-port-forwarding)", r.returncode != 0 and b"SSH-" not in r.stdout,
              r.stdout + r.stderr)
        script = (ROOT / "tools" / "sensor_snapshot.py").read_bytes()
        r = ssh(f"python3 -I - {SNAP_ARGS}", stdin=script + b"\nimport os\n")
        check("modified snapshot script refused", denied(r) and b"allowlist" in r.stderr, r.stderr)

        config_after = sh("docker", "exec", sensor, "sha256sum", "/etc/suricata/suricata.yaml").stdout
        check("suricata.yaml unchanged", config_before == config_after and config_before != b"")
        logged = sh("docker", "logs", sensor).stderr
        check("sshd accepted the kit key", b"Accepted publickey for suricata-ro" in logged,
              logged[-400:])
    except RuntimeError as e:
        print(f"FAIL setup: {e}")
        results.append(False)
    finally:
        if keep:
            print(f"kept: containers {sensor} {client}, network {net}, {tmp}")
        else:
            sh("docker", "rm", "-f", sensor, client)
            sh("docker", "network", "rm", net)
            shutil.rmtree(tmp, ignore_errors=True)
    failed = results.count(False)
    print(f"sensor-ssh: {len(results)} checks, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
