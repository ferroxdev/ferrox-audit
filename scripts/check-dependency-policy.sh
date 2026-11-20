#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

note() { printf '::error::%s\n' "$1"; status=1; }

allow_list="$(sed -n '/^\[licenses\]/,/^\[/p' deny.toml | sed -n 's/^  "\(.*\)",\{0,1\}$/\1/p')"

if [[ -z "$allow_list" ]]; then
  note "deny.toml's [licenses].allow is empty or unreadable, so this check would pass on nothing"
fi

metadata=""
if metadata="$(cargo metadata --offline --format-version 1 --all-features 2>/dev/null)"; then
  :
elif metadata="$(cargo metadata --format-version 1 --all-features 2>/dev/null)"; then
  :
else
  note "cargo metadata could not read the graph, so no licence was checked; run \`cargo fetch\` and try again"
  metadata=""
fi

policy_check="$(mktemp "${TMPDIR:-/tmp}/ferrox-licences.XXXXXX")"
trap 'rm -f "$policy_check"' EXIT
cat >"$policy_check" <<'PY'
import json, re, sys

selftest = sys.argv[1:2] == ["--selftest"]
allow = {line.strip().lower() for line in sys.argv[2 if selftest else 1].splitlines() if line.strip()}

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.at = 0

    def peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def take(self, want=None):
        token = self.peek()
        if token is None or (want is not None and token.upper() != want):
            raise ValueError(f"expected {want or 'a licence id'}, found {token or 'end'}")
        self.at += 1
        return token

    def atom(self):
        token = self.take()
        if token == "(":
            value = self.disjunction()
            self.take(")")
            return value
        if token.upper() in ("WITH", "AND", "OR", ")"):
            raise ValueError(f"expected a licence id, found {token}")
        if self.peek() is not None and self.peek().upper() == "WITH":
            self.take("WITH")
            exception = self.take()
            if exception.upper() in ("WITH", "AND", "OR", "(", ")"):
                raise ValueError(f"expected an exception id, found {exception}")
            token = f"{token} WITH {exception}"
        return token.lower() in allow

    def conjunction(self):
        value = self.atom()
        while self.peek() is not None and self.peek().upper() == "AND":
            self.take("AND")
            value = self.atom() and value
        return value

    def disjunction(self):
        value = self.conjunction()
        while self.peek() is not None and self.peek().upper() == "OR":
            self.take("OR")
            value = self.conjunction() or value
        return value

def allowed(expression):
    source = expression.replace("/", " OR ")
    tokens = re.findall(r"\(|\)|[A-Za-z0-9.+-]+", source)
    leftover = re.sub(r"\(|\)|[A-Za-z0-9.+-]+", " ", source)
    if leftover.strip():
        raise ValueError(f"unsupported token `{leftover.strip()}`")
    parser = Parser(tokens)
    value = parser.disjunction()
    if parser.peek() is not None:
        raise ValueError(f"trailing token {parser.peek()}")
    return value

if selftest:
    cases = [
        ("MIT", True),
        ("LGPL-2.1-or-later", False),
        ("MIT OR LGPL-2.1-or-later", True),
        ("MIT AND LGPL-2.1-or-later", False),
        ("(MIT OR Apache-2.0) AND BSD-3-Clause", True),
        ("Apache-2.0 WITH LLVM-exception", True),
        ("GPL-3.0-no! OR MIT", "error"),
        ("MIT OR )", "error"),
        ("MIT OR AND", "error"),
        ("MIT WITH OR", "error"),
        ("MIT$", "error"),
    ]
    failed = False
    for expression, want in cases:
        try:
            passed = allowed(expression)
        except ValueError:
            passed = "error"
        if passed != want:
            print(f"::error::selftest: `{expression}` returned {passed}, wanted {want}")
            failed = True
    if failed:
        sys.exit(1)
    print("check-dependency-policy: selftest ok")
    sys.exit(0)

graph = json.load(sys.stdin)
expressions = sorted({p["license"] for p in graph["packages"] if p.get("license")})
failed = False
for package in graph["packages"]:
    if package.get("license"):
        continue
    name = package.get("name", "?")
    if package.get("license_file"):
        print(f"::error::{name} names only a license_file, so its licence cannot be validated")
    else:
        print(f"::error::{name} has no license or license_file")
    failed = True
for expression in expressions:
    try:
        passed = allowed(expression)
    except ValueError as error:
        print(f"::error::could not read licence expression `{expression}`: {error}")
        failed = True
        continue
    if not passed:
        print(f"::error::the graph carries `{expression}`, which names no licence `deny.toml` allows")
        failed = True

sys.exit(1 if failed else 0)
PY
python3 "$policy_check" --selftest "$allow_list" || status=1
if [[ "${1:-}" != "--selftest" && -n "$metadata" ]]; then
  if ! printf '%s' "$metadata" | python3 "$policy_check" "$allow_list"; then
    status=1
  fi
fi

if grep -E '^source = "git\+' Cargo.lock >/dev/null; then
  grep -E '^source = "git\+' Cargo.lock | sort -u | while read -r _ line; do
    note "$line is not crates.io; deny.toml's [sources] allows no git source"
  done || true
  status=1
fi

allowed_registry="$(sed -n '/^\[sources\]/,/^\[/p' deny.toml \
  | sed -n 's/^allow-registry[[:space:]]*=[[:space:]]*\[\(.*\)\][[:space:]]*$/\1/p' \
  | tr ',' '\n' \
  | sed -n 's/^[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p')"
if [[ -z "$allowed_registry" ]]; then
  note "deny.toml's [sources].allow-registry is empty or unreadable, so every registry source is rejected"
fi
bad_registry="$(awk -v allowed="$allowed_registry" '
  function norm(value) { sub(/\/$/, "", value); return value }
  BEGIN {
    count = split(allowed, line, "\n")
    for (i = 1; i <= count; i++) if (line[i] != "") ok[norm(line[i])] = 1
  }
  /^source = "(registry|sparse)\+/ {
    source = $0
    sub(/^source = "(registry|sparse)\+/, "", source)
    sub(/"$/, "", source)
    if (!(norm(source) in ok)) print $0
  }
' Cargo.lock)"
if [[ -n "$bad_registry" ]]; then
  printf '%s\n' "$bad_registry" | sort -u | while read -r line; do
    note "$line is not the crates.io registry; deny.toml's [sources] allows no other"
  done
  status=1
fi

for banned in sing-box v2ray-rust; do
  hits="$(grep -rnE "^[[:space:]]*['\"]?(${banned})['\"]?[[:space:]]*=|\[[^]]*dependencies\.['\"]?${banned}['\"]?\]|package[[:space:]]*=[[:space:]]*['\"]${banned}['\"]" --include='Cargo.toml' crates Cargo.toml 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    note "\`${banned}\` is a comparator, read at its pin under upstream/ and never a dependency"
    printf '%s\n' "$hits"
  fi
done

exit "$status"
