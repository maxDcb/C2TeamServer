#!/usr/bin/env bash
# Bootstrap a validated Exploration release. Both components are installed by default.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "Exploration requires python3 to run the installer." >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [[ -n "$script_dir" && -f "$script_dir/packaging/exploration_install.py" ]]; then
  exec python3 "$script_dir/packaging/exploration_install.py" install "$@"
fi

version=""
previous=""
for argument in "$@"; do
  if [[ "$previous" == "--version" ]]; then
    version="$argument"
    break
  fi
  previous="$argument"
done
if [[ -z "$version" ]]; then
  version="$(python3 - <<'PY'
import json
import urllib.request
request = urllib.request.Request(
    "https://api.github.com/repos/maxDcb/C2TeamServer/releases/latest",
    headers={"User-Agent": "Exploration-installer"},
)
with urllib.request.urlopen(request, timeout=30) as response:
    print(json.load(response)["tag_name"])
PY
)"
fi
if [[ ! "$version" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid release version." >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT
curl -fsSL "https://raw.githubusercontent.com/maxDcb/C2TeamServer/$version/packaging/exploration_install.py" \
  -o "$temporary/exploration_install.py"
python3 "$temporary/exploration_install.py" install --version "$version" "$@"
