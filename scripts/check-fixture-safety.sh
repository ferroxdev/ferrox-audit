#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export LC_ALL=C

status=0
selftest=0
if [[ "${1:-}" == "--selftest" ]]; then
  selftest=1
fi

if ((selftest == 0)); then
python3 - <<'EOF'
import os, re, subprocess, sys
result = subprocess.run(
    ["git", "grep", "-I", "-z", "--name-only", "-E",
     r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "--", "."],
    capture_output=True)
if result.returncode not in (0, 1):
    sys.exit(result.returncode)
raw = result.stdout
files = [os.fsdecode(f) for f in raw.split(b"\0") if f]
ip = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})")
WARP = {
    ".github/workflows/warp-parity.yml",
    "crates/ferrox-app/src/warp.rs",
    "crates/ferrox-app/src/warp_scan.rs",
    "scripts/run-warp-parity.py",
}
SCAN = {"crates/ferrox-app/src/warp_scan.rs"}
PSIPHON = {"crates/ferrox-app/src/psiphon.rs"}
def allowed(a, b, c, d, f):
    if (a, b, c, d) == (0, 0, 0, 0) or (a, b, c, d) == (0, 0, 0, 1) or (a, b, c, d) == (255, 255, 255, 255):
        # 0.0.0.0 is "this network" and 0.0.0.1 is the SOCKS4a marker a client
        # puts in the address field to say a name follows; neither is routable.
        return True
    if a == 127 or a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 169 and b == 254:
        # Link-local, the VPN lane's bypass default; not routable.
        return True
    if a == 192 and b == 168:
        return True
    if a == 198 and b in (18, 19):
        # RFC 2544 benchmarking space, the reference FakeDNS pool's default.
        return True
    if (a, b, c, d) == (1, 1, 1, 1) or (a, b) == (162, 159):
        # Cloudflare's WARP plane: resolvers and the edge the WARP lane dials
        # are runtime data in warp.rs and warp_scan.rs, not test material.
        return f in WARP
    if (a == 188 and b == 114) or (a, b, c) == (172, 65, 251):
        # Cloudflare's other WARP edge ranges, also runtime scan data in warp_scan.rs.
        return f in SCAN
    if (a, b, c, d) in (
        (23, 215, 0, 206), (23, 215, 0, 203), (23, 212, 250, 91),
        (23, 212, 250, 78), (23, 12, 147, 13), (23, 12, 147, 29),
        (23, 73, 207, 8), (23, 73, 207, 15), (92, 123, 102, 43),
    ):
        # The Android client's CDN edge scan data in psiphon.rs, not test material.
        return f in PSIPHON
    if (a, b) in ((192, 0), (198, 51), (203, 0)) and (
        (c == 2 and a == 192) or (c == 100 and a == 198) or (c == 113 and a == 203)):
        return True
    return False
bad = 0
for f in files:
    try:
        text = open(f, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    for n, line in enumerate(text.splitlines(), 1):
        for m in ip.finditer(line):
            a, b, c, d = (int(m.group(i)) for i in range(1, 5))
            if not all(x <= 255 for x in (a, b, c, d)):
                continue
            if not allowed(a, b, c, d, f):
                print(f"::error::{f}:{n}: routable IPv4 literal {m.group(0)} — use TEST-NET (192.0.2.0/24)")
                bad += 1
sys.exit(1 if bad else 0)
EOF
fi

python3 - "${1:-}" <<'EOF'
import base64, json, re, subprocess, sys
selftest = len(sys.argv) > 1 and sys.argv[1] == "--selftest"
link = re.compile(r"(?:vless|vmess|trojan|ss)://[^@#? ]+@([^/?# ]+)")
vmess = re.compile(r"vmess://([A-Za-z0-9+/=_-]+)")
ss = re.compile(r"ss://([A-Za-z0-9+/=_-]+)(?:@([^/\s#?]+))?")
allowed = re.compile(
    r"^(\[::1\]|::1|\[2001:db8:[0-9A-Fa-f:]*\]|2001:db8:[0-9A-Fa-f:]*|(127|10)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}"
    r"|(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}"
    r"|localhost|example\.(com|net|org)"
    r"|[A-Za-z0-9.-]+\.(test|invalid|localhost|example)"
    r"|uuid|host|\{host\})([:/?#]|$)"
)

def ss_host(match):
    token = match.group(1) + "=" * (-len(match.group(1)) % 4)
    try:
        decoded = base64.b64decode(
            token, altchars=b"-_", validate=False
        ).decode("utf-8", "replace")
    except ValueError:
        return ""
    authority = decoded.rsplit("@", 1)[1] if "@" in decoded else (match.group(2) or "")
    authority = authority.strip()
    if authority.startswith("["):
        end = authority.find("]")
        if end != -1:
            return authority[1:end]
    if authority.count(":") > 1:
        return authority
    return authority.rsplit(":", 1)[0] if ":" in authority else authority

if selftest:
    def encoded(value):
        return base64.b64encode(value.encode()).decode()

    public = ".".join(("8", "8", "8", "8"))
    scheme = "ss" + "://"
    cases = [
        (f"{scheme}{encoded(f'aes-256-gcm:p@{public}:8388')}", public),
        (f'"{scheme}{encoded(f"aes-256-gcm:p@{public}:8388")}"', public),
        (f"`{scheme}{encoded(f'aes-256-gcm:p@{public}:8388')}`", public),
        (f"{scheme}{encoded(f'aes-256-gcm:p@{public}:8388')}?plugin=obfs-local", public),
        (f"{scheme}{encoded(f'aes-256-gcm:p@[::ffff:{public}]:8388')}", f"::ffff:{public}"),
        (f"{scheme}{encoded('aes-256-gcm:p')}@[::ffff:{public}]:8388", f"::ffff:{public}"),
        (f"{scheme}{encoded('aes-256-gcm:p@192.0.2.1:8388')}", "192.0.2.1"),
        (f"{scheme}{encoded('aes-256-gcm:p@[2001:db8::1]:8388')}", "2001:db8::1"),
    ]
    for line, want in cases:
        match = ss.search(line)
        got = ss_host(match) if match else ""
        if got != want:
            print(f"::error::selftest: {line!r} yielded {got!r}, want {want!r}", file=sys.stderr)
            sys.exit(1)
    if allowed.match(public + ":"):
        print("::error::selftest: a public IPv4 address passed the allowlist", file=sys.stderr)
        sys.exit(1)
    match = link.search(f"{scheme}{encoded('aes-256-gcm:p')}@[2001:db8::1]:8388")
    if not match or not allowed.match(match.group(1)):
        print("::error::selftest: a bracketed documentation IPv6 authority was rejected", file=sys.stderr)
        sys.exit(1)
    print("check-fixture-safety: selftest ok")
    sys.exit(0)
result = subprocess.run(
    ["git", "grep", "-I", "-n", "-E",
     r"(vless|vmess|trojan|ss)://[^@#? ]+@[^/:?# ]+", "--", "."],
    capture_output=True, text=True, encoding="utf-8", errors="replace")
if result.returncode not in (0, 1):
    sys.exit(result.returncode)
bad = 0
for line in result.stdout.splitlines():
    for match in link.finditer(line):
        if allowed.match(match.group(1)):
            continue
        where = re.match(r"^(.*?):(\d+):", line)
        prefix = f"{where.group(1)}:{where.group(2)}" if where else "?"
        print(f"::error::{prefix}: share-link with a non-documentation host — working configs arrive as masked CI input only")
        bad += 1
vmess_result = subprocess.run(
    ["git", "grep", "-I", "-n", "-E", r"vmess://[A-Za-z0-9+/=_-]+", "--", "."],
    capture_output=True, text=True, encoding="utf-8", errors="replace")
if vmess_result.returncode not in (0, 1):
    sys.exit(vmess_result.returncode)
for line in vmess_result.stdout.splitlines():
    for match in vmess.finditer(line):
        token = match.group(1) + "=" * (-len(match.group(1)) % 4)
        try:
            document = json.loads(base64.b64decode(token, altchars=b"-_", validate=False))
        except (ValueError, json.JSONDecodeError):
            continue
        host = document.get("add") or document.get("host") if isinstance(document, dict) else ""
        if not isinstance(host, str) or not host or allowed.match(host + ":"):
            continue
        where = re.match(r"^(.*?):(\d+):", line)
        prefix = f"{where.group(1)}:{where.group(2)}" if where else "?"
        print(f"::error::{prefix}: vmess link with a non-documentation host — working configs arrive as masked CI input only")
        bad += 1
ss_result = subprocess.run(
    ["git", "grep", "-I", "-n", "-E", r"ss://[A-Za-z0-9+/=_-]+", "--", "."],
    capture_output=True, text=True, encoding="utf-8", errors="replace")
if ss_result.returncode not in (0, 1):
    sys.exit(ss_result.returncode)
for line in ss_result.stdout.splitlines():
    for match in ss.finditer(line):
        host = ss_host(match)
        if not host or allowed.match(host + ":"):
            continue
        where = re.match(r"^(.*?):(\d+):", line)
        prefix = f"{where.group(1)}:{where.group(2)}" if where else "?"
        print(f"::error::{prefix}: ss link with a non-documentation host — working configs arrive as masked CI input only")
        bad += 1
sys.exit(1 if bad else 0)
EOF

if ((selftest == 0)); then
  if git grep -I -n -E -e '-----BEGIN .*PRIVATE KEY( BLOCK)?-----' -- . ':!scripts/check-fixture-safety.sh'; then
    echo "::error::private key block in the tree — test material is generated at runtime"
    status=1
  fi
fi

exit "$status"
