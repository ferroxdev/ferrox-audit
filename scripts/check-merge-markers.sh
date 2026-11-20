#!/usr/bin/env bash
# A conflict resolved by leaving the markers in is a paragraph that says two things at once, and every reader after it reads both. Nothing else in the tree sees the difference: the page renders, the counts match, the tests pass.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

markers='^(<{7,}|>{7,})( |$)|^\|{7,}( |$)'

selftest="$(mktemp -d)"
printf '%s\n' '<<<<<<< HEAD' 'the version main held' '=======' 'the version the branch wrote' '>>>>>>> 0123456 (one commit)' > "$selftest/conflicted.md"
printf '%s\n' '<<<<<<< HEAD' 'the version main held' '||||||| base' 'the version both started from' '=======' 'the version the branch wrote' '>>>>>>> 0123456 (one commit)' > "$selftest/diff3.md"
printf '%s\n' 'A setext heading' '=======' 'a rule: -------' 'less than seven: <<<< and >>>> and =======' 'not a marker: ======= after' > "$selftest/clean.md"
if ! grep -E -q "$markers" "$selftest/conflicted.md"; then
  echo "::error::self-test: the marker grep misses a real conflict"
  status=1
fi
if ! grep -E -q "$markers" "$selftest/diff3.md"; then
  echo "::error::self-test: the marker grep misses a diff3 base marker"
  status=1
fi
if grep -E -n -E "$markers" "$selftest/clean.md"; then
  echo "::error::self-test: the marker grep flags a setext heading, a rule or a shorter line"
  status=1
fi
rm -rf "$selftest"

set +e
hits="$(git grep -I -n -E "$markers" -- ':!scripts/check-merge-markers.sh')"
grep_rc=$?
set -e
if ((grep_rc >= 2)); then
  echo "::error::the merge-marker scan could not run (git grep exit $grep_rc)"
  status=1
elif ((grep_rc == 0)); then
  printf '%s\n' "$hits"
  echo "::error::an unresolved merge conflict landed: keep the one version that says the thing and delete the marker lines"
  status=1
fi

exit "$status"
