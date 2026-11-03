#!/usr/bin/env bash
# Per-SID aggregates -> snapshots/<UTC time>-<days>d.json (snapshots/ is git-ignored: it holds IPs).
# Usage:
#   tools/snapshot.sh [days]                 remote: ssh to $SENSOR_SSH from config/environment.env
#   tools/snapshot.sh --local '<glob>' [days] [--now ISO]   local file(s), e.g. lab or demo data
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
mkdir -p "$root/snapshots"

if [[ "${1:-}" == "--local" ]]; then
  shift; glob="${1:?--local needs a glob}"; shift
  days=7
  if [[ $# -gt 0 && "$1" != --* ]]; then days="$1"; shift; fi
  out="$root/snapshots/local-$(date -u +%Y%m%dT%H%M%S)-${days}d.json"
  python3 "$here/sensor_snapshot.py" --eve-glob "$glob" --days "$days" "$@" > "$out"
else
  env_file="$root/config/environment.env"
  [[ -f "$env_file" ]] || { echo "missing $env_file - run the onboarding skill or copy environment.example.env" >&2; exit 2; }
  # shellcheck disable=SC1090
  source "$env_file"
  days="${1:-7}"
  out="$root/snapshots/$(date -u +%Y%m%dT%H%M)-${days}d.json"
  ssh -o BatchMode=yes "$SENSOR_SSH" \
    "${SENSOR_SUDO:-} python3 -I - --days $days --logdir '$SURICATA_LOG_DIR' --pattern '$SURICATA_ALERT_GLOB' --work-hours '$WORK_HOURS'" \
    < "$here/sensor_snapshot.py" > "$out"
fi

python3 - "$out" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"{sys.argv[1]}: alerts={d['alerts']} visible={d['visible']} sids={len(d['sids'])} "
      f"skipped={d['skipped_lines']} suricata={d['suricata']}")
PY
