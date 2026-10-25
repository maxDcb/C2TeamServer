#!/usr/bin/env bash
set -euo pipefail

run_build=true

if [ "$EVENT_NAME" = push ] && [ "$GITHUB_REF_NAME" != "$DEFAULT_BRANCH" ]; then
  # A pull_request run validates a branch that already has an open PR.
  if open_pr_count=$(gh api --method GET "repos/$GITHUB_REPOSITORY/pulls" \
    -f state=open -f head="$GITHUB_REPOSITORY_OWNER:$GITHUB_REF_NAME" \
    --jq 'length'); then
    if [ "$open_pr_count" -gt 0 ]; then
      run_build=false
      echo "Open PR found; its pull_request run owns the build."
    fi
  else
    echo "PR lookup failed; running the full build."
  fi
fi

if [ "$run_build" = true ] && [ "$EVENT_NAME" != workflow_dispatch ]; then
  if [ "$EVENT_NAME" = pull_request ]; then
    base=$(git rev-parse HEAD^1 2>/dev/null || true)
  else
    base=${BEFORE_SHA:-}
  fi

  # Missing commits and diff errors conservatively require the full build.
  if [ -n "$base" ] && git cat-file -e "$base^{commit}" 2>/dev/null && \
    git diff --quiet "$base" HEAD -- . \
      ':(exclude)docs/**' ':(exclude)README.md'; then
    run_build=false
    echo "Only documentation changed; skipping the build."
  fi
fi

echo "run_build=$run_build" >> "$GITHUB_OUTPUT"
