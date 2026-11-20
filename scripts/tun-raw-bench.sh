#!/bin/sh
# Raw TUN device benchmark: a forwarder between two TUN devices, with iperf3
# crossing it. This isolates the device layer (open/read/write, offload,
# multi-queue) from any tun2socks stack. Run as root in CI; it creates two
# throw-away namespaces and removes them.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT_DIR=${OUT_DIR:-"$ROOT/tun-raw-results"}
mkdir -p "$OUT_DIR"
OUT_DIR=$(CDPATH= cd -- "$OUT_DIR" && pwd)
RESULTS="$OUT_DIR/results.jsonl"
: > "$RESULTS"

FERROX_RAW=${FERROX_RAW:-"$ROOT/scripts/tun-raw/target/release/ferrox-tun-raw"}
TUN_RS_DIR=${TUN_RS_DIR:-}
DURATION=${DURATION:-5}
CLIENT_TIMEOUT=${CLIENT_TIMEOUT:-$((DURATION + 20))}
REPEAT=${REPEAT:-2}
STATUS=0
GAPS="$OUT_DIR/gaps.md"
FAILED_SCENARIO=""
: > "$GAPS"
QUEUES=${QUEUES:-4}
VARIANTS=${VARIANTS:-"ferrox-raw-plain ferrox-raw-gso ferrox-raw-mq ferrox-raw-gso-mq tun-rs-sync-normal tun-rs-sync-gso tun-rs-sync-gso-concurrent"}

SERVER_PID=""
FORWARDER_PID=""
IPERF_PID=""
SAMPLER_PID=""
CPU_START=0
WALL_START=0

cleanup() {
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2> /dev/null || true
    [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2> /dev/null || true
    [ -n "$FORWARDER_PID" ] && kill -9 "$FORWARDER_PID" 2> /dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2> /dev/null || true
    ip link del tun11 2> /dev/null || true
    ip link del tun22 2> /dev/null || true
    wait 2> /dev/null || true
}
trap cleanup EXIT INT TERM

wait_dev() {
    for _ in $(seq 1 200); do
        if ip -o link show "$1" > /dev/null 2>&1; then return 0; fi
        sleep 0.05
    done
    return 1
}

wait_ns() {
    for _ in $(seq 1 100); do
        if [ "$(readlink "/proc/$SERVER_PID/ns/net" 2> /dev/null)" != "$(readlink /proc/self/ns/net)" ]; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

wait_port() {
    for _ in $(seq 1 200); do
        if nsenter --target "$SERVER_PID" --net -- ss -Hltn "sport = :5201" 2> /dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.05
    done
    return 1
}

command_for() {
    case "$1" in
        ferrox-raw-plain) printf '%s --iface1 tun11 --iface2 tun22' "$FERROX_RAW" ;;
        ferrox-raw-gso) printf '%s --iface1 tun11 --iface2 tun22 --gso' "$FERROX_RAW" ;;
        ferrox-raw-mq) printf '%s --iface1 tun11 --iface2 tun22 --queues %s' "$FERROX_RAW" "$QUEUES" ;;
        ferrox-raw-gso-mq) printf '%s --iface1 tun11 --iface2 tun22 --gso --queues %s' "$FERROX_RAW" "$QUEUES" ;;
        tun-rs-sync-normal)
            [ -n "$TUN_RS_DIR" ] || return 1
            printf '%s --iface1 tun11 --ip1 10.0.1.1 --iface2 tun22 --ip2 10.0.2.1' "$TUN_RS_DIR/target/release/tun-rs-sync-normal"
            ;;
        tun-rs-sync-gso)
            [ -n "$TUN_RS_DIR" ] || return 1
            printf '%s --iface1 tun11 --ip1 10.0.1.1 --iface2 tun22 --ip2 10.0.2.1' "$TUN_RS_DIR/target/release/tun-rs-sync-gso"
            ;;
        tun-rs-sync-gso-concurrent)
            [ -n "$TUN_RS_DIR" ] || return 1
            printf '%s --iface1 tun11 --ip1 10.0.1.1 --iface2 tun22 --ip2 10.0.2.1' "$TUN_RS_DIR/target/release/tun-rs-sync-gso-concurrent"
            ;;
        *) return 1 ;;
    esac
}

start_variant() {
    variant=$1
    command=$(command_for "$variant") || {
        echo "  $variant: no command (TUN_RS_DIR unset or unknown variant)" >&2
        return 2
    }
    # shellcheck disable=SC2086
    $command > "$OUT_DIR/$variant.log" 2>&1 &
    FORWARDER_PID=$!
    wait_dev tun11 || { echo "  $variant: tun11 did not appear" >&2; cat "$OUT_DIR/$variant.log" >&2; return 1; }
    wait_dev tun22 || { echo "  $variant: tun22 did not appear" >&2; cat "$OUT_DIR/$variant.log" >&2; return 1; }

    unshare --net -- sleep 1000000 &
    SERVER_PID=$!
    wait_ns || return 1
    ip link set tun22 netns "$SERVER_PID"

    ip addr replace 10.0.1.1/24 dev tun11
    ip link set tun11 up
    ip route replace 10.0.2.1/32 dev tun11

    nsenter --target "$SERVER_PID" --net -- ip link set lo up
    nsenter --target "$SERVER_PID" --net -- ip addr replace 10.0.2.1/24 dev tun22
    nsenter --target "$SERVER_PID" --net -- ip link set tun22 up
    nsenter --target "$SERVER_PID" --net -- ip route replace 10.0.0.0/16 dev tun22

    nsenter --target "$SERVER_PID" --net -- iperf3 -s -B 10.0.2.1 -p 5201 > "$OUT_DIR/$variant-iperf.log" 2>&1 &
    IPERF_PID=$!
    wait_port || { echo "  $variant: iperf3 never listened" >&2; return 1; }
    sleep 0.5

    ip -s link show tun11 > "$OUT_DIR/$variant-links.log" 2>&1 || true
    ip -s link show tun22 >> "$OUT_DIR/$variant-links.log" 2>&1 || true
    ip route get 10.0.2.1 >> "$OUT_DIR/$variant-links.log" 2>&1 || true
    if ! ping -c 3 -i 0.2 -W 1 -q 10.0.2.1 > "$OUT_DIR/$variant-ping-before.log" 2>&1; then
        echo "  $variant: the path probe failed" >&2
        cat "$OUT_DIR/$variant-links.log" >&2
        cat "$OUT_DIR/$variant-ping-before.log" >&2
        cat "$OUT_DIR/$variant.log" >&2
        return 1
    fi
}

stop_variant() {
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2> /dev/null || true
    [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2> /dev/null || true
    [ -n "$FORWARDER_PID" ] && kill -9 "$FORWARDER_PID" 2> /dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2> /dev/null || true
    SAMPLER_PID=""
    IPERF_PID=""
    FORWARDER_PID=""
    SERVER_PID=""
    ip link del tun11 2> /dev/null || true
    ip link del tun22 2> /dev/null || true
    sleep 0.5
}

cpu_ticks() {
    python3 -c 'import sys; fields = open(sys.argv[1]).read().rsplit(")", 1)[1].split(); print(int(fields[11]) + int(fields[12]))' "/proc/$FORWARDER_PID/stat" 2> /dev/null || echo 0
}

sample_start() {
    file=$1
    CPU_START=$(cpu_ticks)
    WALL_START=$(date +%s%N)
    : > "$file"
    (
        while [ -n "$FORWARDER_PID" ] && kill -0 "$FORWARDER_PID" 2> /dev/null; do
            ps -p "$FORWARDER_PID" -o %cpu=,rss= --no-headers >> "$file" 2> /dev/null || true
            sleep 0.5
        done
    ) &
    SAMPLER_PID=$!
}

sample_stop() {
    file=$1
    cpu_end=$(cpu_ticks)
    wall_end=$(date +%s%N)
    [ -n "$SAMPLER_PID" ] && kill "$SAMPLER_PID" 2> /dev/null || true
    SAMPLER_PID=""
    python3 - "$file" "$CPU_START" "$cpu_end" "$WALL_START" "$wall_end" "$(getconf CLK_TCK 2> /dev/null || echo 100)" << 'PY'
import sys
file, start, end, wall_start, wall_end, hz = sys.argv[1:7]
rss = 0.0
for line in open(file):
    parts = line.split()
    if len(parts) == 2:
        rss = max(rss, float(parts[1]))
seconds = (int(wall_end) - int(wall_start)) / 1e9
cpu = 100.0 * (int(end) - int(start)) / (float(hz) * seconds) if seconds > 0 else 0.0
print(f"{cpu:.1f} {rss:.0f}")
PY
}

emit() {
    variant=$1
    scenario=$2
    value=$3
    unit=$4
    cpu=$5
    rss=$6
    slot=$7
    loss=${8:-}
    loss_field=""
    [ -n "$loss" ] && loss_field=",\"loss_pct\":$loss"
    printf '{"engine":"%s","scenario":"%s","slot":%s,"value":%s,"unit":"%s","cpu_pct":%s,"rss_kb":%s,"mtu":1500,"queues":%s%s}\n' \
        "$variant" "$scenario" "$slot" "$value" "$unit" "$cpu" "$rss" "$QUEUES" "$loss_field" >> "$RESULTS"
    printf '  %-28s %-6s %s %s cpu %s%% rss %s KB\n' "$variant" "$scenario" "$value" "$unit" "$cpu" "$rss"
}

run_variant() {
    variant=$1
    rep=$2
    slot=$3
    echo "round $rep variant $variant"
    FAILED_SCENARIO="start"
    rc=0
    start_variant "$variant" || rc=$?
    if [ "$rc" -eq 2 ]; then
        stop_variant
        # A comparator with no command is unmeasured, not green: past a missing TUN_RS_DIR the cell is named, while a ferrox variant that lost its command still fails the gate.
        case "$variant" in
            ferrox-raw*) return 1 ;;
        esac
        printf -- '- `%s` had no command to run\n' "$variant" >> "$GAPS"
        return 0
    fi
    if [ "$rc" -ne 0 ]; then
        stop_variant
        return 1
    fi

    sample_start "$OUT_DIR/$variant-$rep.samples"
    if ! timeout "$CLIENT_TIMEOUT" iperf3 -c 10.0.2.1 -p 5201 -t "$DURATION" -J > "$OUT_DIR/$variant-$rep-tcp.json" 2> /dev/null; then
        FAILED_SCENARIO="tcp"
        echo "  $variant: tcp iperf3 failed" >&2
        stop_variant
        return 1
    fi
    set -- $(sample_stop "$OUT_DIR/$variant-$rep.samples")
    tcp=$(python3 - "$OUT_DIR/$variant-$rep-tcp.json" << 'PY'
import json, math, sys
try:
    d = json.load(open(sys.argv[1]))
    received = d.get("end", {}).get("sum_received") or d.get("end", {}).get("sum") or {}
    bits = float(received["bits_per_second"])
except Exception as error:
    print(f"tcp measurement: {error}", file=sys.stderr)
    raise SystemExit(1)
if not math.isfinite(bits) or bits <= 0:
    print(f"tcp measurement: invalid bits_per_second {bits}", file=sys.stderr)
    raise SystemExit(1)
print("%.3f" % (bits / 1e9))
PY
) || { FAILED_SCENARIO="tcp measurement"; echo "  $variant: tcp measurement failed" >&2; stop_variant; return 1; }
    emit "$variant" "tcp-${rep}" "$tcp" "Gbit/s" "$1" "$2" "$slot"

    sample_start "$OUT_DIR/$variant-$rep-udp.samples"
    if ! timeout "$CLIENT_TIMEOUT" iperf3 -c 10.0.2.1 -p 5201 -u -b 1G -t "$DURATION" -J > "$OUT_DIR/$variant-$rep-udp.json" 2> /dev/null; then
        FAILED_SCENARIO="udp"
        echo "  $variant: udp iperf3 failed" >&2
        stop_variant
        return 1
    fi
    set -- $(sample_stop "$OUT_DIR/$variant-$rep-udp.samples")
    udp_cpu=$1
    udp_rss=$2
    udp=$(python3 - "$OUT_DIR/$variant-$rep-udp.json" << 'PY'
import json, math, sys
try:
    d = json.load(open(sys.argv[1]))
    total = d.get("end", {}).get("sum") or {}
    bits = float(total["bits_per_second"])
    lost = total.get("lost_percent")
except Exception as error:
    print(f"udp measurement: {error}", file=sys.stderr)
    raise SystemExit(1)
if not math.isfinite(bits) or bits <= 0:
    print(f"udp measurement: invalid bits_per_second {bits}", file=sys.stderr)
    raise SystemExit(1)
if isinstance(lost, (int, float)):
    lost = float(lost)
    if not math.isfinite(lost):
        print(f"udp measurement: invalid lost_percent {lost}", file=sys.stderr)
        raise SystemExit(1)
    print("%.3f %.2f" % (bits / 1e9, lost))
else:
    print("%.3f" % (bits / 1e9))
PY
) || { FAILED_SCENARIO="udp measurement"; echo "  $variant: udp measurement failed" >&2; stop_variant; return 1; }
    set -- $udp
    emit "$variant" "udp-${rep}" "$1" "Gbit/s" "$udp_cpu" "$udp_rss" "$slot" "${2:-}"

    if ! timeout 10 ping -c 100 -i 0.01 -W 1 -q 10.0.2.1 > "$OUT_DIR/$variant-$rep-ping.log" 2>&1; then
        FAILED_SCENARIO="ping"
        echo "  $variant: ping failed" >&2
        stop_variant
        return 1
    fi
    rtt=$(python3 - "$OUT_DIR/$variant-$rep-ping.log" << 'PY'
import math, re, sys
text = open(sys.argv[1]).read()
m = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', text)
if not m:
    print("ping measurement: no rtt", file=sys.stderr)
    raise SystemExit(1)
rtt = float(m.group(2))
if not math.isfinite(rtt) or rtt <= 0:
    print(f"ping measurement: invalid rtt {rtt}", file=sys.stderr)
    raise SystemExit(1)
print("%.3f" % rtt)
PY
) || { FAILED_SCENARIO="ping measurement"; echo "  $variant: ping measurement failed" >&2; stop_variant; return 1; }
    emit "$variant" "ping-${rep}" "$rtt" "ms" "0" "0" "$slot"

    stop_variant
}

runner_spec() {
    {
        printf '| property | value |\n|---|---|\n'
        printf '| runner image | %s %s |\n' "${ImageOS:-unknown}" "${ImageVersion:-}"
        printf '| cpu | %s |\n' "$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)"
        printf '| cpu cores | %s |\n' "$(nproc)"
        printf '| memory | %s |\n' "$(awk '/MemTotal/ {printf "%.1f GB", $2/1048576}' /proc/meminfo)"
        printf '| kernel | %s |\n' "$(uname -sr)"
        printf '| duration | %ss x %s rounds |\n' "$DURATION" "$REPEAT"
        printf '| queues | %s |\n' "$QUEUES"
    } > "$OUT_DIR/runner.md"
    cat "$OUT_DIR/runner.md" >&2
}

runner_spec
for knob in "net.ipv4.tcp_tw_reuse=1" "net.ipv4.ip_local_port_range=1024 65000"; do
    sysctl -qw "$knob" 2> /dev/null || true
done

order_for_round() {
    round=$1
    count=0
    for _ in $VARIANTS; do count=$((count + 1)); done
    [ "$count" -gt 0 ] || return 0
    cut=$(((round - 1) % count))
    index=0
    head=""
    tail=""
    for variant in $VARIANTS; do
        if [ "$index" -ge "$cut" ]; then
            tail="$tail $variant"
        else
            head="$head $variant"
        fi
        index=$((index + 1))
    done
    printf '%s%s\n' "$tail" "$head"
}

rep=1
while [ "$rep" -le "$REPEAT" ]; do
    slot=0
    for variant in $(order_for_round "$rep"); do
        slot=$((slot + 1))
        # A baseline variant that cannot hold its two devices is a hole in the comparison, not this tree's regression: the cell is named and the gate still fails on our own variants.
        if ! run_variant "$variant" "$rep" "$slot"; then
            case "$variant" in
                ferrox-raw*) STATUS=1 ;;
                *) printf -- '- `%s` failed round %s (%s)\n' "$variant" "$rep" "$FAILED_SCENARIO" >> "$GAPS" ;;
            esac
        fi
    done
    rep=$((rep + 1))
done

if [ ! -s "$RESULTS" ]; then
    printf 'no measurements: no variant produced a result\n' >&2
    STATUS=1
fi

python3 - "$RESULTS" "$OUT_DIR/summary.md" << 'PY'
import json, statistics, sys
rows = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
groups = {}
for row in rows:
    groups.setdefault((row["engine"], row["scenario"].rsplit("-", 1)[0]), []).append(row)
def median(values):
    values = sorted(values)
    if not values:
        return 0
    middle = len(values) // 2
    if len(values) % 2:
        return values[middle]
    return (values[middle - 1] + values[middle]) / 2
lines = ["| engine | scenario | median | cpu % | max rss MB | loss % |", "|---|---|---:|---:|---:|---:|"]
for (engine, scenario), group in groups.items():
    value = median([row["value"] for row in group])
    cpu = median([row["cpu_pct"] for row in group])
    rss = max(row["rss_kb"] for row in group) / 1024
    losses = [row["loss_pct"] for row in group if "loss_pct" in row]
    loss = f"{statistics.median(losses):.2f}" if losses else ""
    lines.append(f"| {engine} | {scenario} | {value:.3f} {group[0]['unit']} | {cpu:.0f} | {rss:.1f} | {loss} |")
open(sys.argv[2], "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
PY
if [ -s "$GAPS" ]; then
    { printf '\nNot measured:\n\n'; cat "$GAPS"; } >> "$OUT_DIR/summary.md"
fi
exit "$STATUS"
