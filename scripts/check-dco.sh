#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  printf 'usage: %s <git-revision-range>\n' "$0" >&2
  exit 2
fi

range=$1
missing=0

while IFS= read -r commit; do
  [[ -n "$commit" ]] || continue
  author=$(git show -s --format='%an <%ae>' "$commit")
  if ! git show -s --format=%B "$commit" | grep -Fqx "Signed-off-by: $author"; then
    printf '%s lacks an author DCO sign-off: Signed-off-by: %s\n' "$commit" "$author" >&2
    missing=1
  fi
done < <(git rev-list --reverse --no-merges "$range")

(( missing == 0 )) || exit 1
printf 'DCO sign-off checks passed\n'
