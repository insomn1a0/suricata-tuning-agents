"""Kit configuration: defaults < config/environment.env < process environment.
The env file is shell syntax (KEY="value"  # comment) and is parsed with shlex, never executed.
Usage: kitconfig.py            print KEY=value lines
       kitconfig.py --shell    print `export KEY=...` lines for `eval` in bash scripts"""
import os
import pathlib
import shlex
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / "config" / "environment.env"

# Single source of default engine versions and policy; re-verify versions before bumping.
DEFAULTS = {
    "WAZUH_VERSION": "4.14.9",
    "WAZUH_ALERT_LEVEL": "6",
    "WAZUH_LOCATION": "[001] (lab-sensor) any->/var/log/suricata/eve.json",
    "SURICATA_VERSION": "8.0.8",
    "RULE_ID_RANGE": "100200-100299",
    "SURICATA_RULES_CACHE": "",  # optional local copy of sensor rule lines, checked against intent metadata
}


# Multi-arch manifest digests of the default engine images: a tag can be moved, a digest cannot.
# Refresh after a version bump: docker buildx imagetools inspect <image:tag> --format '{{.Manifest.Digest}}'
PINNED_DIGESTS = {
    "wazuh/wazuh-manager:4.14.9": "sha256:9d07740f780024600101d759ddab9a4413bdcb3412ccb81dccc143b3cdc702a2",
    "jasonish/suricata:8.0.8": "sha256:d5a3a1785299ab40918d465e54fedf8e3afeeedba76bb64b0cc74dbc20bda2c3",
}


def images(cfg):
    """Image references for the engines; pinned by digest when the version is one we pinned."""
    refs = {"WAZUH_IMAGE": f"wazuh/wazuh-manager:{cfg['WAZUH_VERSION']}",
            "SURICATA_IMAGE": f"jasonish/suricata:{cfg['SURICATA_VERSION']}"}
    return {k: f"{v}@{PINNED_DIGESTS[v]}" if v in PINNED_DIGESTS else v for k, v in refs.items()}


def parse_env(text):
    out = {}
    for tok in shlex.split(text, comments=True):
        key, sep, value = tok.partition("=")
        if sep and key.isidentifier():
            out[key] = value
    return out


def load(env_file=ENV_FILE, environ=None):
    environ = os.environ if environ is None else environ
    cfg = dict(DEFAULTS)
    if pathlib.Path(env_file).is_file():
        cfg.update(parse_env(pathlib.Path(env_file).read_text()))
    cfg.update({k: environ[k] for k in DEFAULTS if environ.get(k)})
    return cfg


if __name__ == "__main__":
    cfg = load()
    cfg.update(images(cfg))
    fmt = "export {}={}" if "--shell" in sys.argv[1:] else "{}={}"
    for k in list(DEFAULTS) + ["WAZUH_IMAGE", "SURICATA_IMAGE"]:
        print(fmt.format(k, shlex.quote(cfg[k]) if "--shell" in sys.argv[1:] else cfg[k]))
