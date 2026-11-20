#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

scripts=(
  scripts/lib-engines.sh
  scripts/run-benchmark-matrix.sh
  scripts/run-parity.sh
  scripts/run-live-speedtest.sh
)

prose='^\s*#|"no executable|"[^"]*is not a file|\(\.exe\)'

for script in "${scripts[@]}"; do
  [[ -f "$script" ]] || continue
  while IFS=: read -r lineno text; do
    [[ -n "$lineno" ]] || continue
    if [[ "$text" =~ ^[[:space:]]*((local|export|readonly)[[:space:]]+)?(built[[:space:]]|[A-Za-z_][A-Za-z0-9_]*=\"?\$\(built[[:space:]]) ]]; then
      continue
    fi
    is_assignment=0
    if [[ "$text" =~ ^[[:space:]]*((local|export|readonly)[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)= ]]; then
      is_assignment=1
      assigned="${BASH_REMATCH[3]}"
    fi
    if ((is_assignment)) && [[ "$text" =~ [[:space:]]-[xf][[:space:]] ]]; then
      printf '::error file=%s,line=%s::a bare -x/-f probe passes on MSYS for a \
name that does not exist; resolve the path with `built` first: %s\n' \
        "$script" "$lineno" "$text" >&2
      status=1
      continue
    fi
    if ((is_assignment)); then
      if grep -qE "built[[:space:]]+\"?\\\$\{?$assigned\b" "$script"; then
        continue
      fi
      printf '::error file=%s,line=%s::`%s` is assigned a bare target/release path \
and never passed through `built`; on windows-latest the name that reaches the \
native process is one MSYS can resolve and nothing else can: %s\n' \
        "$script" "$lineno" "$assigned" "$text" >&2
      status=1
      continue
    fi
    if [[ "$text" =~ $prose ]]; then continue; fi
    printf '::error file=%s,line=%s::binary path is not resolved through `built`; \
on windows-latest MSYS answers a stat of the bare name with the .exe, so this \
passes here and fails there: %s\n' \
      "$script" "$lineno" "$text" >&2
    status=1
  done < <(grep -nE 'target/release/[A-Za-z0-9_-]+' "$script" 2>/dev/null || true)
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/target/release"
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-app.exe"
chmod +x "$tmp/target/release/ferrox-app.exe"
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-bench.exe"
chmod +x "$tmp/target/release/ferrox-bench.exe"

# shellcheck source=scripts/lib-engines.sh
source scripts/lib-engines.sh

cd "$tmp"
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-app"
chmod +x "$tmp/target/release/ferrox-app"
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-bench"
chmod +x "$tmp/target/release/ferrox-bench"

for os in Windows_NT Linux; do
  for crate in ferrox-app ferrox-bench; do
    got="$(OS=$os built "target/release/$crate")" || {
      printf '::error::built could not resolve target/release/%s under OS=%s\n' \
        "$crate" "$os" >&2
      status=1
      continue
    }
    want_suffix=''
    [[ "$os" == Windows_NT ]] && want_suffix='.exe'
    if [[ "$got" != "target/release/$crate$want_suffix" ]]; then
      printf '::error::under OS=%s, built answered %s for target/release/%s; \
expected the %s spelling\n' "$os" "$got" "$crate" "${want_suffix:-bare}" >&2
      status=1
    fi
  done
done

printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-mode"
chmod 0644 "$tmp/target/release/ferrox-mode"
got="$(OS=Linux built target/release/ferrox-mode)" || {
  printf '::error::built refused a 0644 artifact instead of restoring its mode\n' >&2
  status=1
}
if [[ -n "${got:-}" && ! -x "$got" ]]; then
  printf '::error::built returned %s without making it executable\n' "$got" >&2
  status=1
fi

if ((status)); then
  echo "windows binary-path check failed" >&2
  exit 1
fi
echo "windows binary paths: resolved through built on both platforms"