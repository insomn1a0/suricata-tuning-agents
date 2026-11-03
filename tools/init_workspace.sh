#!/usr/bin/env bash
# Plugin install mode: copy the kit's working files (tools, rules, tests, templates, CLAUDE.md ground rules)
# from the plugin into a workspace directory. Never overwrites: existing files are reported and kept.
# Usage: tools/init_workspace.sh <target-dir>
# (A git clone of the repo already is a workspace - no need to run this there.)
set -euo pipefail
src="$(cd "$(dirname "$0")/.." && pwd)"
dst="${1:?usage: init_workspace.sh <target-dir>}"
mkdir -p "$dst"
dst="$(cd "$dst" && pwd)"
[[ "$src" == "$dst" ]] && { echo "target is the kit itself - nothing to do"; exit 0; }

items=(CLAUDE.md AGENTS.md Makefile .gitignore requirements.txt docs tools templates tuning wazuh suricata tests examples
       config/environment.example.env inventory/hosts.example.md)
copied=0 kept=0
while IFS= read -r -d '' f; do
  rel="${f#"$src"/}"
  case "$rel" in */__pycache__/*|examples/lab/data/*) continue ;; esac
  if [[ -e "$dst/$rel" ]]; then
    echo "kept existing: $rel"; kept=$((kept + 1))
  else
    mkdir -p "$dst/$(dirname "$rel")"; cp -p "$f" "$dst/$rel"; copied=$((copied + 1))
  fi
done < <(cd "$src" && for i in "${items[@]}"; do find "$src/$i" -type f -print0; done)
echo "workspace $dst: $copied files copied, $kept kept"
