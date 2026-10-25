#!/usr/bin/env bash
set -euo pipefail

gate="$(cd "$(dirname "$0")" && pwd)/ci-gate.sh"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/bin" "$scratch/repo/docs"

cat > "$scratch/bin/gh" <<'EOF'
#!/usr/bin/env bash
if [ "${MOCK_GH_FAIL:-0}" = 1 ]; then
  exit 1
fi
printf '%s\n' "${MOCK_PR_COUNT:-0}"
EOF
chmod +x "$scratch/bin/gh"

git -C "$scratch/repo" init -q
git -C "$scratch/repo" config user.name CI-Test
git -C "$scratch/repo" config user.email ci@example.invalid
printf 'int main() {}\n' > "$scratch/repo/app.cpp"
git -C "$scratch/repo" add .
git -C "$scratch/repo" commit -qm initial
base=$(git -C "$scratch/repo" rev-parse HEAD)

printf 'documentation\n' > "$scratch/repo/docs/note.md"
git -C "$scratch/repo" add .
git -C "$scratch/repo" commit -qm docs
doc=$(git -C "$scratch/repo" rev-parse HEAD)

printf 'int other() {}\n' >> "$scratch/repo/app.cpp"
git -C "$scratch/repo" add .
git -C "$scratch/repo" commit -qm code
code=$(git -C "$scratch/repo" rev-parse HEAD)

cd "$scratch/repo"
run_case() {
  local label=$1 expected=$2 event=$3 before=$4 pr_count=$5 default=$6 failure=$7
  : > "$scratch/out"
  EVENT_NAME="$event" BEFORE_SHA="$before" GITHUB_OUTPUT="$scratch/out" \
    GITHUB_REPOSITORY=maxDcb/C2TeamServer GITHUB_REPOSITORY_OWNER=maxDcb \
    GITHUB_REF_NAME=feature DEFAULT_BRANCH="$default" \
    MOCK_PR_COUNT="$pr_count" MOCK_GH_FAIL="$failure" PATH="$scratch/bin:$PATH" \
    bash "$gate" > "$scratch/log" 2>&1

  if [ "$(cat "$scratch/out")" != "run_build=$expected" ]; then
    printf 'FAIL %s: %s\n' "$label" "$(cat "$scratch/out")"
    cat "$scratch/log"
    exit 1
  fi
  printf 'PASS %s\n' "$label"
}

git checkout -q "$doc"
run_case docs-only false push "$base" 0 master 0
run_case docs-pr false pull_request '' 0 master 0
run_case manual true workflow_dispatch '' 0 master 0
run_case no-base true push '' 0 master 0

git checkout -q "$code"
run_case code-change true push "$doc" 0 master 0
run_case open-pr false push "$doc" 1 master 0
run_case pr-lookup-failure true push "$doc" 0 master 1
run_case default-branch true push "$doc" 1 feature 0
run_case code-pr true pull_request '' 0 master 0
