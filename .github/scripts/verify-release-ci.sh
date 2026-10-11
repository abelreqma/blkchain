#!/bin/sh
set -eu

commit=$(git rev-parse HEAD)
run=$(gh run list --repo "$GH_REPO" --workflow ci.yml --commit "$commit" \
    --branch main --event push --limit 1 \
    --json headSha,headBranch,status,conclusion \
    --jq '.[0] | "\(.headSha) \(.headBranch) \(.status) \(.conclusion)"')

if [ "$run" != "$commit main completed success" ]; then
    printf 'The tagged commit has no successful completed main push CI run.\n' >&2
    exit 1
fi
