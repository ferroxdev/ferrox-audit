#!/usr/bin/env python3
"""Translate the matrix's Xray-dialect client config into Aether's environment: a MASQUE, WARP or nested MASQUE dial to its masque identity, or a WireGuard dial to its wg one."""

import base64
import json
import os
import pathlib
import subprocess
import sys
import time


def fail(message):
    """Report an adapter error and exit 2."""
    print(f"aether adapter: {message}", file=sys.stderr)
    raise SystemExit(2)


def text(value):
    """Render a config value as text."""
    return str(value)


def endpoint(settings):
    """Return the peer address and port the outbound settings name."""
    address = settings.get("address")
    port = settings.get("port")
    if address and port:
        return f"{address}:{port}"
    for peer in settings.get("peers") or []:
        address = peer.get("endpoint") or peer.get("address")
        port = peer.get("port")
        if address and port:
            return f"{address}:{port}"
        if address and ":" in address:
            return address
    for server in settings.get("servers") or []:
        address = server.get("address")
        port = server.get("port")
        if address and port:
            return f"{address}:{port}"
    server = settings.get("server") or {}
    address = server.get("address")
    port = server.get("port")
    if address and port:
        return f"{address}:{port}"
    fail("the client config has no address and port")


def local_addresses(settings):
    """Return one local IPv4 and one local IPv6 address from the settings."""
    values = []
    for item in settings.get("address") or []:
        values.append(text(item).split("/", 1)[0])
    if not values:
        fail("the client config has no local address")
    v4 = next((item for item in values if ":" not in item), None)
    v6 = next((item for item in values if ":" in item), None)
    if v4 is None or v6 is None:
        fail("the client config needs one address per family")
    return v4, v6


def pem(value):
    """Wrap PEM text in a TOML multiline string."""
    return '"""' + value + '"""'


def base64_key(value):
    """Normalize a WireGuard key to padded standard base64."""
    key = str(value).strip().replace("-", "+").replace("_", "/")
    return key + "=" * (-len(key) % 4)


def identity(path, fields):
    """Write a TOML identity file, owner-only because it carries private keys."""
    lines = []
    for key, value in fields:
        lines.append(f"{key} = {value}")
    path = pathlib.Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    path.chmod(0o600)
    return path


def masque_identity(cfg_path, stream, name="aether-identity.toml", v4="10.13.0.2", v6="fd13::2", inline=None):
    """Build the MASQUE identity TOML from the client TLS settings or an inline identity."""
    if inline is not None:
        private = ((inline or {}).get("masque") or {}).get("privateKey")
        if not private:
            fail("the inner MASQUE identity has no private key")
        stem = pathlib.Path(name).stem
        cert_path = cfg_path.with_name(f"{stem}-cert.pem")
        key_path = cfg_path.with_name(f"{stem}-key.pem")
        der_path = cfg_path.with_name(f"{stem}-key.der")
        try:
            payload = base64.b64decode(private)
        except ValueError as error:
            fail(f"the inner MASQUE private key is not base64: {error}")
        descriptor = os.open(der_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        der_path.chmod(0o600)
        try:
            key_descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.fchmod(key_descriptor, 0o600)
            os.close(key_descriptor)
            subprocess.run(
                ["openssl", "pkey", "-inform", "DER", "-in", str(der_path), "-out", str(key_path)],
                check=True, stdin=subprocess.DEVNULL, capture_output=True,
            )
            key_path.chmod(0o600)
            subprocess.run(
                ["openssl", "req", "-new", "-x509", "-key", str(key_path), "-days", "7",
                 "-subj", "/CN=aether-inner", "-out", str(cert_path)],
                check=True, stdin=subprocess.DEVNULL, capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            fail(f"cannot derive the inner MASQUE certificate: {error}")
    else:
        tls = stream.get("tlsSettings") or {}
        certificates = tls.get("certificates") or []
        certificate = certificates[0].get("certificateFile") if certificates else None
        if not certificate:
            certificate = tls.get("caCertFile")
        if not certificate:
            fail("the MASQUE client config names no certificate")
        cert_path = pathlib.Path(certificate)
        key_file = certificates[0].get("keyFile") if certificates else None
        key_path = pathlib.Path(key_file) if key_file else cert_path.with_name("key.pem")
    if not cert_path.exists() or not key_path.exists():
        fail(f"the MASQUE client identity is missing at {cert_path}")
    identity_path = cfg_path.with_name(name)
    zeros = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    return identity(identity_path, [
        ("device_id", '"matrix"'),
        ("access_token", '"matrix"'),
        ("cert_pem", pem(cert_path.read_text())),
        ("key_pem", pem(key_path.read_text())),
        ("cert_issued_at", str(int(time.time()))),
        ("ipv4", f'"{v4}"'),
        ("ipv6", f'"{v6}"'),
        ("wg_private_key", f'"{zeros}"'),
        ("wg_peer_public_key", f'"{zeros}"'),
        ("client_id", '""'),
    ])


def wireguard_identity(cfg_path, settings, suffix=""):
    """Build the WireGuard identity TOML from the client settings."""
    secret = settings.get("secretKey")
    peers = settings.get("peers") or []
    if not secret or not peers:
        fail("the WireGuard client config has no key or peer")
    public = peers[0].get("publicKey")
    if not public:
        fail("the WireGuard client config has no peer public key")
    local_v4, local_v6 = local_addresses(settings)
    name = "aether-identity" + (f"-{suffix}" if suffix else "") + ".toml"
    identity_path = cfg_path.with_name(name)
    return identity(identity_path, [
        ("device_id", '"matrix"'),
        ("access_token", '"matrix"'),
        ("cert_pem", '""'),
        ("key_pem", '""'),
        ("cert_issued_at", "0"),
        ("ipv4", f'"{local_v4}"'),
        ("ipv6", f'"{local_v6}"'),
        ("wg_private_key", f'"{base64_key(secret)}"'),
        ("wg_peer_public_key", f'"{base64_key(public)}"'),
        ("client_id", '""'),
    ])


def inline_wireguard(identity):
    """Shape an inline warp identity's WireGuard half like client settings."""
    block = (identity or {}).get("wireguard") or {}
    return {
        "secretKey": block.get("privateKey"),
        "address": block.get("address"),
        "peers": [{"publicKey": block.get("publicKey"), "endpoint": block.get("endpoint")}],
    }


def inline_masque_addresses(identity):
    """Return the inner identity's IPv4 and IPv6 MASQUE addresses."""
    block = (identity or {}).get("masque") or {}
    values = [text(value).split("/", 1)[0] for value in block.get("address") or []]
    v4 = next((value for value in values if ":" not in value), None)
    v6 = next((value for value in values if ":" in value), None)
    if v4 is None or v6 is None:
        fail("the inner MASQUE identity needs one address per family")
    return v4, v6


def main():
    """Read the matrix client config and exec the pinned Aether."""
    args = sys.argv[1:]
    if len(args) != 3 or args[0] != "run" or args[1] not in ("-config", "--config"):
        fail("expected `run -config <path>`")
    cfg_path = pathlib.Path(args[2])
    try:
        doc = json.loads(cfg_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read {cfg_path}: {error}")
    inbound = next(
        (item for item in doc.get("inbounds") or [] if item.get("protocol") == "socks"),
        None,
    )
    if inbound is None:
        fail("the config has no SOCKS inbound")
    inbound_port = inbound.get("port")
    if not isinstance(inbound_port, int) or isinstance(inbound_port, bool):
        fail("the SOCKS inbound has no port")
    bind = f"{inbound.get('listen', '127.0.0.1')}:{inbound_port}"
    outbound = next(
        (item for item in doc.get("outbounds") or []
         if item.get("protocol") in ("masque", "wireguard", "warp")),
        None,
    )
    if outbound is None:
        fail("the config has no MASQUE, WireGuard or WARP outbound")
    settings = outbound.get("settings") or {}
    stream = outbound.get("streamSettings") or {}
    real = pathlib.Path(
        os.environ.get("AETHER_BIN")
        or pathlib.Path(__file__).resolve().with_name("aether-bin")
    )
    if not real.exists():
        fail(f"the pinned Aether binary is missing at {real}")
    env = os.environ.copy()
    env.update({
        "AETHER_LOG_LEVEL": "warn",
        "AETHER_TLS_VERIFY": "0",
        "AETHER_QUIC_V2": "0",
        "AETHER_MASQUE_NO_DATA_CHECK": "1",
        "AETHER_WG_NO_DATA_CHECK": "1",
        "AETHER_NOIZE": "off",
    })
    protocol = outbound.get("protocol")
    mode = settings.get("mode") if protocol == "warp" else None
    if protocol == "warp" and mode == "gool":
        block = settings.get("masque") or {}
        masque_peer = (
            f"{block['address']}:{block['port']}"
            if block.get("address") and block.get("port") else None
        )
        if not masque_peer:
            fail("the WARP outbound names no MASQUE address and port")
        inner = settings.get("goolIdentity") or {}
        inner_peer = settings.get("goolPeer") or endpoint(inline_wireguard(inner))
        tls = stream.get("tlsSettings") or {}
        sni = block.get("serverName") or tls.get("serverName") or "carrier.test"
        outer_config = masque_identity(cfg_path, stream)
        wireguard_identity(cfg_path, inline_wireguard(inner), "gool")
        command = [
            str(real), "--protocol", "gool", "--peer", masque_peer,
            "--gool-peer", inner_peer, "--masque-sni", sni, "--bind", bind,
            "--masque-config", str(outer_config), "--no-data-check",
            "--no-quic-v2", "--log-level", "warn",
        ]
    elif protocol == "warp" and mode == "gool-classic":
        outer = settings.get("identity") or {}
        inner = settings.get("goolIdentity") or {}
        outer_peer = settings.get("wiwOuter") or endpoint(inline_wireguard(outer))
        inner_peer = settings.get("wiwInner") or endpoint(inline_wireguard(inner))
        primary = wireguard_identity(cfg_path, inline_wireguard(outer))
        wireguard_identity(cfg_path, inline_wireguard(inner), "secondary")
        command = [
            str(real), "--gool-classic", "--wiw-outer", outer_peer,
            "--wiw-inner", inner_peer, "--bind", bind,
            "--wg-config", str(primary), "--no-data-check", "--log-level", "warn",
        ]
    elif protocol == "warp" and mode == "mim":
        block = settings.get("masque") or {}
        outer_peer = settings.get("mimOuter")
        if not outer_peer and block.get("address") and block.get("port"):
            outer_peer = f"{block['address']}:{block['port']}"
        inner_peer = settings.get("mimInner")
        if not outer_peer or not inner_peer:
            fail("the mim outbound names no outer or inner address and port")
        tls = stream.get("tlsSettings") or {}
        sni = block.get("serverName") or tls.get("serverName") or "carrier.test"
        inner_identity = settings.get("mimIdentity")
        if not inner_identity and settings.get("mimIdentityFile"):
            try:
                inner_identity = json.loads(
                    pathlib.Path(settings["mimIdentityFile"]).read_text()
                )
            except (OSError, ValueError) as error:
                fail(f"the inner MASQUE identity is unreadable: {error}")
        inner_v4, inner_v6 = inline_masque_addresses(inner_identity)
        outer_config = masque_identity(cfg_path, stream)
        masque_identity(
            cfg_path, stream, "aether-identity-secondary.toml", inner_v4, inner_v6,
            inline=inner_identity,
        )
        command = [
            str(real), "--protocol", "mim", "--mim-outer", outer_peer,
            "--mim-inner", inner_peer, "--masque-sni", sni, "--bind", bind,
            "--masque-config", str(outer_config), "--no-data-check",
            "--no-quic-v2", "--log-level", "warn",
        ]
    elif protocol == "warp":
        block = settings.get("masque") or {}
        masque_peer = (
            f"{block['address']}:{block['port']}"
            if block.get("address") and block.get("port") else None
        )
        if not masque_peer:
            fail("the WARP outbound names no MASQUE address and port")
        tls = stream.get("tlsSettings") or {}
        sni = block.get("serverName") or tls.get("serverName") or "carrier.test"
        inline = settings.get("identity") or {}
        v4, v6 = (
            inline_masque_addresses(inline)
            if (inline.get("masque") or {}).get("address")
            else ("10.13.0.2", "fd13::2")
        )
        config = masque_identity(cfg_path, stream, v4=v4, v6=v6)
        command = [
            str(real), "--protocol", "masque", "--peer", masque_peer,
            "--masque-sni", sni, "--bind", bind,
            "--masque-config", str(config), "--no-data-check",
            "--no-quic-v2", "--log-level", "warn",
        ]
    elif protocol == "masque":
        tls = stream.get("tlsSettings") or {}
        sni = tls.get("serverName") or "carrier.test"
        peer = endpoint(settings)
        config = masque_identity(cfg_path, stream)
        command = [
            str(real), "--protocol", "masque", "--peer", peer,
            "--masque-sni", sni, "--bind", bind,
            "--masque-config", str(config), "--no-data-check",
            "--no-quic-v2", "--log-level", "warn",
        ]
    elif protocol == "wireguard":
        peer = endpoint(settings)
        config = wireguard_identity(cfg_path, settings)
        command = [
            str(real), "--protocol", "wg", "--wg-peer", peer,
            "--bind", bind, "--wg-config", str(config),
            "--no-data-check", "--log-level", "warn",
        ]
    else:
        fail(f"the config has no known outbound protocol: {protocol}")
    env["AETHER_SOCKS"] = bind
    os.execve(str(real), command, env)


if __name__ == "__main__":
    main()
