#!/usr/bin/env python3
"""Measure ferrox and Aether with one WARP identity against a local MASQUE server and Cloudflare's edge."""

import argparse
import base64
import copy
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
from urllib.parse import urlsplit

CONNECT_HOST = "cloudflareaccess.com"
CONNECT_SNI = "consumer-masque.cloudflareclient.com"
DEFAULT_EDGE = "162.159.198.2:443"
DEFAULT_TARGET = "https://speed.cloudflare.com/__down?bytes=67108864"
LOCAL_V4 = "10.13.0.2"
LOCAL_V6 = "fd13::2"
try:
    CPU_TICK_MS = 1000.0 / os.sysconf("SC_CLK_TCK")
except (AttributeError, ValueError, OSError):
    CPU_TICK_MS = 10.0


def fail(message):
    """Report a setup error and exit 2."""
    print(f"warp-parity: {message}", file=sys.stderr)
    raise SystemExit(2)


def note(message):
    """Write progress to stderr so stdout stays a report."""
    print(f"warp-parity: {message}", file=sys.stderr)


def have(tool):
    """Return whether a command resolves on PATH."""
    return shutil.which(tool) is not None


def run(cmd, *, env=None, timeout=180, cwd=None):
    """Run a command and return its result, raising on a non-zero exit."""
    return subprocess.run(
        cmd,
        env=env,
        cwd=cwd,
        timeout=timeout,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


def precreate_owner_only(path):
    """Create an empty owner-only file so a tool writing it cannot widen the mode."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    os.close(descriptor)


def openssl_der(pem_path, der_path):
    """Convert a PEM private key to PKCS #8 DER, the envelope ferrox reads."""
    precreate_owner_only(der_path)
    run(["openssl", "pkey", "-in", str(pem_path), "-outform", "DER", "-out", str(der_path)])


def openssl_pem(der_path, pem_path):
    """Convert a PKCS #8 DER private key to PEM."""
    precreate_owner_only(pem_path)
    run(["openssl", "pkey", "-inform", "DER", "-in", str(der_path), "-out", str(pem_path)])


def openssl_self_signed(pem_key, pem_cert):
    """Mint a self-signed client certificate for an enrolled key."""
    run([
        "openssl", "req", "-new", "-x509", "-key", str(pem_key), "-days", "7",
        "-subj", "/CN=warp-parity", "-out", str(pem_cert),
    ])


def cert_spki(cert_path):
    """Return a certificate's SubjectPublicKeyInfo as base64."""
    return run([sys.executable, "scripts/cert_spki.py", str(cert_path)]).stdout.strip()


def edge_spki(edge, sni):
    """Read the edge's leaf certificate and return its SubjectPublicKeyInfo as base64."""
    host, _, port = edge.rpartition(":")
    if not host:
        host, port = edge, "443"
    try:
        result = run(
            [
                "openssl", "s_client", "-connect", f"{host}:{port}", "-servername", sni,
                "-showcerts",
            ],
            timeout=60,
            cwd=".",
        )
    except subprocess.CalledProcessError as error:
        fail(f"the Cloudflare edge at {edge} presented no certificate: {error.stderr.strip()[:400]}")
    blocks = []
    inside = False
    for line in result.stdout.splitlines():
        if line == "-----BEGIN CERTIFICATE-----":
            inside = True
        if inside:
            blocks.append(line)
        if line == "-----END CERTIFICATE-----":
            inside = False
            break
    if not blocks:
        fail("the Cloudflare edge presented no certificate")
    path = pathlib.Path("target/warp-parity/edge.pem")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(blocks) + "\n")
    return cert_spki(path)


def read_json(path):
    """Read a JSON document."""
    return json.loads(pathlib.Path(path).read_text())


def write_secret(path, data):
    """Write a private key with owner-only permissions, replacing any existing file."""
    path = pathlib.Path(path)
    descriptor, temp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb" if isinstance(data, bytes) else "w") as handle:
            handle.write(data)
        os.replace(temp, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def write_json(path, value):
    """Write a JSON document with a trailing newline, owner-only because configs carry keys."""
    write_secret(path, json.dumps(value, indent=2) + "\n")


def pem_text(path):
    """Read PEM text and normalize its trailing newline."""
    return pathlib.Path(path).read_text().strip() + "\n"


def identity_addresses(value):
    """Return the first IPv4 and IPv6 address from a WARP identity's mask block."""
    values = value if isinstance(value, list) else [value]
    v4 = next((str(item).split("/", 1)[0] for item in values if ":" not in str(item)), "")
    v6 = next((str(item).split("/", 1)[0] for item in values if ":" in str(item)), "")
    if not v4 or not v6:
        fail("the WARP identity needs one address per family")
    return v4, v6


def identity_blocks(identity):
    """Return the WireGuard and MASQUE blocks of a ferrox identity."""
    wireguard = identity.get("wireguard") or {}
    masque = identity.get("masque") or {}
    if not masque:
        fail("the WARP identity has no MASQUE block")
    return wireguard, masque


def ferrox_identity_from_aether(path, pin):
    """Turn an Aether TOML identity into the JSON identity both engines read."""
    with pathlib.Path(path).open("rb") as handle:
        doc = tomllib.load(handle)
    key_pem = doc.get("key_pem") or ""
    if "BEGIN PRIVATE KEY" not in key_pem:
        fail(f"{path} carries no MASQUE private key")
    key_path = pathlib.Path(path).with_name("aether-key.pem")
    write_secret(key_path, key_pem)
    key_der = key_path.with_name("aether-key.der")
    openssl_der(key_path, key_der)
    key_der.chmod(0o600)
    v4 = doc.get("ipv4") or ""
    v6 = doc.get("ipv6") or ""
    if not v4 or not v6:
        fail("the Aether identity names no IPv4 and IPv6 address")
    endpoint = doc.get("assigned_endpoint") or DEFAULT_EDGE
    if not endpoint.rsplit(":", 1)[-1].isdigit():
        endpoint = f"{endpoint}:443"
    return {
        "deviceId": doc.get("device_id") or "warp-parity",
        "token": doc.get("access_token") or "",
        "wireguard": {
            "privateKey": doc.get("wg_private_key") or "",
            "publicKey": doc.get("wg_peer_public_key") or "",
            "endpoint": endpoint,
            "address": [f"{v4}/32", f"{v6}/128"],
            "reserved": [0, 0, 0],
        },
        "masque": {
            "privateKey": base64.b64encode(key_der.read_bytes()).decode(),
            "publicKey": pin,
            "address": [f"{v4}/32", f"{v6}/128"],
        },
    }, v4, v6


def aether_identity_from_ferrox(identity, out_dir):
    """Derive the Aether certificate and key from a ferrox identity's enrolled key."""
    _, masque = identity_blocks(identity)
    der = out_dir / "ferrox-key.der"
    write_secret(der, base64.b64decode(masque["privateKey"]))
    key = out_dir / "ferrox-key.pem"
    cert = out_dir / "ferrox-cert.pem"
    openssl_pem(der, key)
    key.chmod(0o600)
    openssl_self_signed(key, cert)
    return cert, key


def measured_command(cmd, env, log_dir, name, timeout):
    """Run a command while sampling its wall time, CPU and peak RSS."""
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout = (log_dir / f"{name}.stdout.log").open("w")
    stderr = (log_dir / f"{name}.stderr.log").open("w")
    start = time.monotonic()
    proc = subprocess.Popen(cmd, env=env, stdout=stdout, stderr=stderr)
    status_file = pathlib.Path(f"/proc/{proc.pid}/status")
    stat_file = pathlib.Path(f"/proc/{proc.pid}/stat")
    peak_rss = 0
    cpu_start = None
    cpu_last = None
    while proc.poll() is None:
        try:
            peak_rss = max(peak_rss, int(next(
                line.split()[1] for line in status_file.read_text().splitlines()
                if line.startswith("VmHWM:")
            )))
        except (OSError, StopIteration, IndexError, ValueError):
            pass
        try:
            fields = stat_file.read_text().split()
            ticks = int(fields[13]) + int(fields[14])
            if cpu_start is None:
                cpu_start = ticks
            cpu_last = ticks
        except (OSError, IndexError, ValueError):
            pass
        if time.monotonic() - start > timeout:
            proc.kill()
            proc.wait()
            stdout.close()
            stderr.close()
            fail(f"{name} did not finish inside {timeout}s")
        time.sleep(0.02)
    stdout.close()
    stderr.close()
    return {
        "seconds": round(time.monotonic() - start, 3),
        "cpu_millis": round((cpu_last - cpu_start) * CPU_TICK_MS) if cpu_start is not None and cpu_last is not None else None,
        "rss_mib": round(peak_rss / 1024.0, 2) if peak_rss else None,
        "exit": proc.returncode,
    }


def wait_socks(port, proc, timeout=45):
    """Wait until a local SOCKS listener accepts a connection."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            return None
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return time.monotonic() - start
        except OSError:
            time.sleep(0.05)
    return None


def recv_exact(sock, size):
    """Read exactly `size` bytes or fail, so a split read is not a refusal."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("the SOCKS front closed mid-reply")
        data += chunk
    return data


def socks_connect(port, host, target_port):
    """Time one SOCKS5 CONNECT through the engine's front."""
    start = time.monotonic()
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("the SOCKS front refused no-auth")
        try:
            ip = socket.inet_pton(socket.AF_INET, host)
        except OSError:
            try:
                ip = socket.inet_pton(socket.AF_INET6, host)
                request = b"\x05\x01\x00\x04" + ip + target_port.to_bytes(2, "big")
            except OSError:
                name = host.encode()
                request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target_port.to_bytes(2, "big")
        else:
            request = b"\x05\x01\x00\x01" + ip + target_port.to_bytes(2, "big")
        sock.sendall(request)
        head = recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError(f"the SOCKS CONNECT answered {head[:2].hex()}")
        if head[3] == 1:
            recv_exact(sock, 6)
        elif head[3] == 4:
            recv_exact(sock, 18)
        elif head[3] == 3:
            length = recv_exact(sock, 1)[0]
            recv_exact(sock, length + 2)
        else:
            raise OSError(f"the SOCKS CONNECT answered address type {head[3]}")
    finally:
        sock.close()
    return (time.monotonic() - start) * 1000.0


def curl_download(port, url, out_path, timeout):
    """Download through the engine's SOCKS front and return its transfer record."""
    result = run([
        "curl", "-sS", "--noproxy", "", "--socks5-hostname", f"127.0.0.1:{port}",
        "--max-time", str(timeout), "--fail", "-o", str(out_path),
        "-w", '{"http_code":%{http_code},"size":%{size_download},'
              '"total":%{time_total},"starttransfer":%{time_starttransfer}}',
        url,
    ], timeout=timeout + 10)
    record = json.loads(result.stdout)
    size = int(record["size"])
    total = float(record["total"])
    start = float(record["starttransfer"])
    window = max(total - start, 0.001)
    record["mib_s"] = round(size / 1048576.0 / window, 2)
    record["ok"] = int(record["http_code"]) in (200, 206) and size > 0
    return record


def engine_config(identity, cert, key, pin, edge, sni, host, socks_port, v4, v6, local):
    """Build the one Xray-dialect client config both engines read."""
    _, masque = identity_blocks(identity)
    stream_tls = {
        "serverName": "carrier.test" if local else sni,
        "allowInsecure": True,
        "certificates": [{
            "certificateFile": str(cert),
            "keyFile": str(key),
            "usage": "verify",
        }],
    }
    stream = {
        "network": "masque",
        "security": "tls",
        "tlsSettings": stream_tls,
        "masqueSettings": {},
    }
    masque_settings = {
        "address": edge[0],
        "port": edge[1],
        "serverName": "carrier.test" if local else sni,
        "host": "carrier.test" if local else host,
        "path": "/",
    }
    inline = {
        "deviceId": identity.get("deviceId") or "warp-parity",
        "token": identity.get("token") or "",
        "wireguard": identity["wireguard"],
        "masque": {
            "privateKey": masque["privateKey"],
            "publicKey": pin,
            "address": [f"{v4}/32", f"{v6}/128"],
        },
    }
    return {
        "inbounds": [{
            "tag": "socks",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "tag": "proxy",
            "protocol": "warp",
            "settings": {
                "mode": "masque",
                "identity": inline,
                "masque": masque_settings,
                "mtu": 1280,
            },
            "streamSettings": stream,
        }],
        "routing": {"rules": [{
            "type": "field",
            "inboundTag": ["socks"],
            "outboundTag": "proxy",
        }]},
    }


def local_server_config(port, cert, key):
    """Build a ferrox MASQUE/WARP server config."""
    return {
        "inbounds": [{
            "tag": "warp",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "masque",
            "settings": {
                "warp": True,
                "users": [{"email": "warp-parity@carrier.test", "pass": "warp-parity"}],
                "address": ["10.13.0.1/24", "fd13::1/64"],
            },
            "streamSettings": {
                "network": "masque",
                "security": "tls",
                "tlsSettings": {
                    "alpn": ["h3"],
                    "certificates": [{
                        "certificateFile": str(cert),
                        "keyFile": str(key),
                    }],
                },
            },
        }],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {}}],
    }


def free_port():
    """Return one loopback TCP port the kernel says is free."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_process(cmd, env, log_path):
    """Start a background process with its output in one log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("w")
    proc = subprocess.Popen(cmd, env=env, stdout=handle, stderr=subprocess.STDOUT, start_new_session=True)
    return proc, handle


def stop_process(proc, handle):
    """Stop a background process and its children."""
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, 15)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, 9)
            except ProcessLookupError:
                pass
            proc.wait()
    handle.close()


def make_local_target(root, size):
    """Write a local target and serve it over loopback HTTP."""
    root.mkdir(parents=True, exist_ok=True)
    target = root / "target.bin"
    block = os.urandom(1024 * 1024)
    with target.open("wb") as handle:
        left = size
        while left > 0:
            chunk = block[: min(left, len(block))]
            handle.write(chunk)
            left -= len(chunk)
    port = free_port()
    proc, log = start_process(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1", "--directory", str(root)],
        os.environ.copy(),
        root / "http.log",
    )
    time.sleep(0.3)
    if proc.poll() is not None:
        log.close()
        fail("the local HTTP target did not start")
    return proc, log, port


def measure_engine(name, binary, adapter, config, socks_port, url, out_dir, repeat, env_base):
    """Start one engine, measure its front, and download the target through it."""
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir = out_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    cfg = out_dir / f"{name}-{repeat}.json"
    write_json(cfg, config)
    env = env_base.copy()
    env["AETHER_BIN"] = str(binary)
    if name == "aether":
        cmd = [sys.executable, str(adapter), "run", "-config", str(cfg)]
    else:
        cmd = [str(binary), "run", "-config", str(cfg)]
    stdout = (log_dir / f"{name}-{repeat}.stdout.log").open("w")
    stderr = (log_dir / f"{name}-{repeat}.stderr.log").open("w")
    start = time.monotonic()
    proc = subprocess.Popen(cmd, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
    started = wait_socks(socks_port, proc)
    if started is None:
        stop_process(proc, stdout)
        stderr.close()
        tail = (log_dir / f"{name}-{repeat}.stderr.log").read_text()[-400:]
        return {"ok": False, "note": f"the SOCKS front never listened: {tail.strip()}"}
    status_file = pathlib.Path(f"/proc/{proc.pid}/status")
    stat_file = pathlib.Path(f"/proc/{proc.pid}/stat")
    startup_rss = None
    startup_cpu = None
    try:
        startup_rss = int(next(
            line.split()[1] for line in status_file.read_text().splitlines()
            if line.startswith("VmHWM:")
        )) / 1024.0
        fields = stat_file.read_text().split()
        startup_cpu = int(fields[13]) + int(fields[14])
    except (OSError, StopIteration, IndexError, ValueError):
        pass
    setup_ms = None
    setup_error = ""
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            setup_ms = socks_connect(socks_port, url[0], url[1])
            break
        except OSError as error:
            setup_error = str(error)
            time.sleep(0.25)
    record = {
        "ok": False,
        "startup_ms": round(started * 1000.0, 1),
        "startup_rss_mib": round(startup_rss, 2) if startup_rss else None,
        "setup_ms": round(setup_ms, 1) if setup_ms is not None else None,
        "note": setup_error,
    }
    if setup_ms is not None:
        try:
            download = curl_download(socks_port, url[2], out_dir / f"{name}-{repeat}.bin", 300)
            record.update(download)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            record["note"] = f"download: {error}"
    peak_rss = startup_rss
    cpu_end = startup_cpu
    try:
        peak_rss = max(peak_rss or 0, int(next(
            line.split()[1] for line in status_file.read_text().splitlines()
            if line.startswith("VmHWM:")
        )) / 1024.0)
        fields = stat_file.read_text().split()
        cpu_end = int(fields[13]) + int(fields[14])
    except (OSError, StopIteration, IndexError, ValueError):
        pass
    record["rss_mib"] = round(peak_rss, 2) if peak_rss else record.get("startup_rss_mib")
    if startup_cpu is not None and cpu_end is not None:
        record["cpu_millis"] = round((cpu_end - startup_cpu) * CPU_TICK_MS)
    stop_process(proc, stdout)
    stderr.close()
    return record


def main():
    """Run both provenance directions against both servers and write the report."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--ferrox-app", default="target/release/ferrox-app")
    parser.add_argument("--ferrox-bench", default="target/release/ferrox-bench")
    parser.add_argument("--aether", default=os.environ.get("AETHER_BIN", ""))
    parser.add_argument("--adapter", default="scripts/run-aether.py")
    parser.add_argument("--out", default="target/warp-parity")
    parser.add_argument("--edge", default=os.environ.get("WARP_MASQUE_EDGE") or DEFAULT_EDGE)
    parser.add_argument("--sni", default=CONNECT_SNI)
    parser.add_argument("--host", default=CONNECT_HOST)
    parser.add_argument("--target-url", default=os.environ.get("WARP_PARITY_URL") or DEFAULT_TARGET)
    parser.add_argument("--bytes", type=int, default=134217728)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        fail("--repeats must be positive")
    for tool in ("openssl", "curl"):
        if not have(tool):
            fail(f"{tool} is not on PATH")
    ferrox = pathlib.Path(args.ferrox_app)
    bench = pathlib.Path(args.ferrox_bench)
    aether = pathlib.Path(args.aether)
    adapter = pathlib.Path(args.adapter)
    if not ferrox.is_file():
        fail(f"no ferrox-app at {ferrox}")
    if not bench.is_file():
        fail(f"no ferrox-bench at {bench}")
    if not aether.is_file():
        fail(f"no Aether binary at {aether}")
    if not adapter.is_file():
        fail(f"no Aether adapter at {adapter}")
    out = pathlib.Path(args.out)
    created = not out.exists()
    out.mkdir(parents=True, exist_ok=True)
    if created:
        out.chmod(0o700)
    env = os.environ.copy()
    env.update({
        "AETHER_LOG_LEVEL": "warn",
        "AETHER_TLS_VERIFY": "0",
        "AETHER_QUIC_V2": "0",
        "AETHER_MASQUE_NO_DATA_CHECK": "1",
        "AETHER_WG_NO_DATA_CHECK": "1",
        "AETHER_NOIZE": "off",
    })
    edge_host, edge_sep, edge_port = args.edge.rpartition(":")
    if not edge_sep:
        edge_host, edge_port = args.edge, "443"
    edge = (edge_host, int(edge_port))
    target_url = args.target_url
    target_host = "speed.cloudflare.com"
    scheme = target_url.split("://", 1)[0].lower() if "://" in target_url else "https"
    target_port = 80 if scheme == "http" else 443
    if "://" in target_url:
        parts = urlsplit(target_url)
        target_host = parts.hostname or target_host
        target_port = parts.port or target_port
    rows = []
    registrations = []
    local_server = None
    server_log = None
    local_http = None
    local_log = None
    try:
        tls_dir = out / "tls"
        run([str(bench), "make-tls", str(tls_dir)])
        local_cert = tls_dir / "cert.pem"
        local_key = tls_dir / "key.pem"
        local_pin = cert_spki(local_cert)
        local_port = free_port()
        write_json(out / "local-server.json", local_server_config(local_port, local_cert, local_key))
        local_server, server_log = start_process(
            [str(ferrox), "run", "-config", str(out / "local-server.json")],
            env,
            out / "logs" / "local-server.log",
        )
        time.sleep(0.7)
        if local_server.poll() is not None:
            server_log.close()
            fail("the local MASQUE server exited at startup")
        local_http, local_log, http_port = make_local_target(out / "http", args.bytes)
        local_url = ("127.0.0.1", http_port, f"http://127.0.0.1:{http_port}/target.bin")
        def measure_pair(provenance, identity, cert, key, cloud_v4, cloud_v6):
            for local in (True, False):
                v4, v6 = (LOCAL_V4, LOCAL_V6) if local else (cloud_v4, cloud_v6)
                server = "local" if local else "cloudflare"
                pin = local_pin if local else ((identity.get("masque") or {}).get("publicKey") or edge_spki(args.edge, args.sni))
                if not pin:
                    fail("the provenance carries no MASQUE edge pin")
                run_identity = copy.deepcopy(identity)
                run_identity.setdefault("wireguard", {})["address"] = [f"{v4}/32", f"{v6}/128"]
                run_identity.setdefault("masque", {})["address"] = [f"{v4}/32", f"{v6}/128"]
                server_edge = ("127.0.0.1", local_port) if local else edge
                url = local_url if local else (target_host, target_port, target_url)
                for repeat in range(1, args.repeats + 1):
                    port = free_port()
                    config = engine_config(run_identity, cert, key, pin, server_edge, args.sni, args.host, port, v4, v6, local)
                    row = measure_engine("ferrox", ferrox, adapter, config, port, url, out / "runs" / server / provenance, repeat, env)
                    rows.append({"provenance": provenance, "server": server, "engine": "ferrox", "repeat": repeat, **row})
                    port = free_port()
                    config = engine_config(run_identity, cert, key, pin, server_edge, args.sni, args.host, port, v4, v6, local)
                    row = measure_engine("aether", aether, adapter, config, port, url, out / "runs" / server / provenance, repeat, env)
                    rows.append({"provenance": provenance, "server": server, "engine": "aether", "repeat": repeat, **row})

        for provenance in ("ferrox", "aether"):
            identities = out / provenance
            identities.mkdir(parents=True, exist_ok=True)
            identities.chmod(0o700)
            if provenance == "ferrox":
                identity_path = identities / "identity.json"
                cmd = [
                    str(ferrox), "warp-register", "--register", "masque",
                    "-o", str(identity_path),
                ]
                registers = measured_command(cmd, env, out / "logs", "register-ferrox", 180)
                registrations.append({"provenance": provenance, **registers})
                if registers["exit"] != 0:
                    registrations[-1]["note"] = (out / "logs" / "register-ferrox.stderr.log").read_text()[-800:]
                    continue
                identity = read_json(identities / "identity-masque.json")
                cert, key = aether_identity_from_ferrox(identity, identities)
            else:
                identity_path = identities / "identity.toml"
                cmd = [
                    str(aether), "--register", "masque", "--masque-config", str(identity_path),
                ]
                registers = measured_command(cmd, env, out / "logs", "register-aether", 180)
                registrations.append({"provenance": provenance, **registers})
                if registers["exit"] != 0:
                    registrations[-1]["note"] = (out / "logs" / "register-aether.stderr.log").read_text()[-800:]
                    continue
                with identity_path.open("rb") as handle:
                    toml_identity = tomllib.load(handle)
                cert = identities / "cert.pem"
                key = identities / "key.pem"
                cert.write_text(toml_identity["cert_pem"])
                write_secret(key, toml_identity["key_pem"])
                identity, _, _ = ferrox_identity_from_aether(identity_path, "")
            cloud_v4, cloud_v6 = identity_addresses((identity.get("masque") or {}).get("address") or [])
            measure_pair(provenance, identity, cert, key, cloud_v4, cloud_v6)
        write_json(out / "results.json", {"registrations": registrations, "rows": rows})
        def display(value):
            return "" if value is None else value
        lines = ["# WARP parity", "", "## Registration", "",
                 "| provenance | engine | seconds | cpu ms | rss MiB | exit | note |",
                 "| --- | --- | --- | --- | --- | --- | --- |"]
        for item in registrations:
            lines.append(
                f"| {item['provenance']} | `ferrox-app`/Aether | {item['seconds']} | "
                f"{display(item.get('cpu_millis'))} | {display(item.get('rss_mib'))} | "
                f"{item['exit']} | {(item.get('note') or '').replace('|', '/')[:160]} |"
            )
        lines += ["", "## Client runs", "",
                  "| provenance | server | engine | repeat | startup ms | setup ms | MiB/s | peak RSS MiB | cpu ms | ok | note |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
        for item in rows:
            lines.append(
                f"| {item['provenance']} | {item['server']} | {item['engine']} | {item['repeat']} | "
                f"{display(item.get('startup_ms'))} | {display(item.get('setup_ms'))} | "
                f"{display(item.get('mib_s'))} | {display(item.get('rss_mib'))} | "
                f"{display(item.get('cpu_millis'))} | {item.get('ok')} | "
                f"{(item.get('note') or '').replace('|', '/')[:160]} |"
            )
        if not any(row.get("ok") for row in rows if row.get("server") == "cloudflare"):
            lines += ["", "Cloudflare moved no bytes."]
        report = "\n".join(lines) + "\n"
        (out / "report.md").write_text(report)
        print(report)
    finally:
        if local_http is not None:
            stop_process(local_http, local_log)
        if local_server is not None and server_log is not None:
            stop_process(local_server, server_log)
    for server in ("local", "cloudflare"):
        for provenance in ("ferrox", "aether"):
            for engine in ("ferrox", "aether"):
                if not any(
                    row.get("ok")
                    for row in rows
                    if row["provenance"] == provenance
                    and row["server"] == server
                    and row["engine"] == engine
                ):
                    fail(f"no {server} {engine} row for the {provenance} identity")


if __name__ == "__main__":
    main()
