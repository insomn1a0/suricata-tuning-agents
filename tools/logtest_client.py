"""Runs INSIDE the wazuh-manager container (see logtest.sh). Feeds events to the logtest socket
in ONE session and prints one JSON result per input line.
Input line: '<event>' or '@loc=<location>\t<event>'. Lines starting with '#' and empty lines are skipped.
Usage: logtest_client.py <events-file> [default-location]"""
import json
import socket
import struct
import sys

SOCK = "/var/ossec/queue/sockets/logtest"


def call(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    data = json.dumps(payload).encode()
    s.sendall(struct.pack("<I", len(data)) + data)
    size = struct.unpack("<I", s.recv(4))[0]
    buf = b""
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    s.close()
    return json.loads(buf)


def main():
    default_loc = sys.argv[2] if len(sys.argv) > 2 else "[001] (lab-sensor) any->/var/log/suricata/eve.json"
    token = None
    for line in open(sys.argv[1]):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        loc = default_loc
        if line.startswith("@loc="):
            loc, line = line[5:].split("\t", 1)
        params = {"event": line, "log_format": "syslog", "location": loc}
        if token:
            params["token"] = token
        resp = call({"version": 1, "command": "log_processing", "parameters": params})
        d = resp.get("data", {})
        token = d.get("token", token)
        out = d.get("output", {})
        rule = out.get("rule", {})
        print(json.dumps({"id": rule.get("id"), "level": rule.get("level"), "alert": d.get("alert"),
                          "description": rule.get("description"), "messages": d.get("messages"),
                          "error": resp.get("error"), "decoder": out.get("decoder")}))


if __name__ == "__main__":
    main()
