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
}


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
    fmt = "export {}={}" if "--shell" in sys.argv[1:] else "{}={}"
    for k in DEFAULTS:
        print(fmt.format(k, shlex.quote(cfg[k]) if "--shell" in sys.argv[1:] else cfg[k]))
