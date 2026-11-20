"""Translate one Xray-dialect document to a sing-box client or server config.

The matrix scenarios are written as Xray JSON because xray-core is the reference
and its dialect is the one every server reads. sing-box reads the same protocols
but names them with `type`, `server`/`server_port`, `tls` and `transport`; this
converter carries only the fields the matrix emits and refuses a carrier sing-box
at the pin does not have.
"""

import argparse
import base64
import binascii
import ipaddress
import json
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_WIREGUARD_ADDRESSES = ("10.0.0.1", "fd59:7153:2388:b5fd::1")
DEFAULT_WIREGUARD_ALLOWED = ("0.0.0.0/0", "::/0")


def _first(items, what):
    if not isinstance(items, list) or not items:
        raise ValueError(f"{what} must be a non-empty array")
    return items[0]


def _prefix(value):
    if not isinstance(value, str):
        raise ValueError(f"`{value}` is not an IP address or prefix")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as error:
        raise ValueError(f"`{value}` is not an IP address or prefix") from error


def _interface(value):
    if not isinstance(value, str):
        raise ValueError(f"`{value}` is not an IP address or prefix")
    try:
        return str(ipaddress.ip_interface(value))
    except ValueError as error:
        raise ValueError(f"`{value}` is not an IP address or prefix") from error


def _wireguard_key(value, what):
    if not isinstance(value, str) or not value:
        raise ValueError(f"the WireGuard {what} is missing")
    if len(value) == 64:
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            pass
        else:
            return base64.b64encode(raw).decode()
    text = value.strip()
    try:
        raw = base64.b64decode(text + "=" * (-len(text) % 4),
                               altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError(f"the WireGuard {what} does not decode") from error
    if len(raw) != 32:
        raise ValueError(f"the WireGuard {what} is not 32 bytes")
    return base64.b64encode(raw).decode()


def _wireguard_addresses(settings):
    raw = settings.get("address")
    if not raw:
        raw = list(DEFAULT_WIREGUARD_ADDRESSES)
    if not isinstance(raw, list):
        raise ValueError("`address` must be an array")
    return [_interface(value) for value in raw]


def _wireguard_mtu(settings):
    value = settings.get("mtu") or 1420
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"`mtu` is not a number: {value!r}") from error


def _wireguard_reserved(settings):
    reserved = settings.get("reserved")
    if not reserved:
        return None
    if isinstance(reserved, str):
        try:
            reserved = base64.b64decode(
                reserved + "=" * (-len(reserved) % 4), validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("`reserved` is not base64") from error
        reserved = list(reserved)
    if (not isinstance(reserved, list) or len(reserved) != 3
            or any(not isinstance(byte, int) or not 0 <= byte <= 255
                   for byte in reserved)):
        raise ValueError("`reserved` must be three bytes")
    return reserved


def _wireguard_endpoint(value):
    if not isinstance(value, str):
        raise ValueError("the WireGuard peer has no `endpoint`")
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise ValueError(f"`{value}` is not a host and port")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        port = int(port)
    except ValueError as error:
        raise ValueError(f"`{value}` has no numeric port") from error
    if not 0 < port < 65536:
        raise ValueError(f"`{value}` has a port outside 1...65535")
    return host, port


def _wireguard_peers(settings, client):
    peers = settings.get("peers")
    if not isinstance(peers, list) or not peers:
        raise ValueError("the WireGuard endpoint needs at least one peer")
    reserved = _wireguard_reserved(settings)
    converted = []
    for peer in peers:
        if not isinstance(peer, dict):
            raise ValueError("a WireGuard peer is not an object")
        allowed = peer.get("allowedIPs") or list(DEFAULT_WIREGUARD_ALLOWED)
        if not isinstance(allowed, list):
            raise ValueError("`allowedIPs` must be an array")
        item = {
            "public_key": _wireguard_key(peer.get("publicKey"), "public key"),
            "allowed_ips": [_prefix(value) for value in allowed],
        }
        if peer.get("preSharedKey"):
            item["pre_shared_key"] = _wireguard_key(
                peer["preSharedKey"], "pre-shared key")
        if peer.get("keepAlive"):
            try:
                item["persistent_keepalive_interval"] = int(peer["keepAlive"])
            except (TypeError, ValueError) as error:
                raise ValueError("`keepAlive` is not a number") from error
        if reserved is not None:
            item["reserved"] = reserved
        if client:
            host, port = _wireguard_endpoint(peer.get("endpoint"))
            item["address"] = host
            item["port"] = port
        converted.append(item)
    return converted


def _wireguard_client(settings, tag):
    if not isinstance(settings, dict):
        raise ValueError("the WireGuard outbound has no settings object")
    return {
        "type": "wireguard",
        "tag": tag,
        "address": _wireguard_addresses(settings),
        "private_key": _wireguard_key(settings.get("secretKey"), "secret key"),
        "mtu": _wireguard_mtu(settings),
        "peers": _wireguard_peers(settings, True),
    }


def _wireguard_server(inbound):
    settings = inbound.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("the WireGuard inbound has no settings object")
    return {
        "type": "wireguard",
        "tag": inbound.get("tag", "wireguard-in"),
        "address": _wireguard_addresses(settings),
        "private_key": _wireguard_key(settings.get("secretKey"), "secret key"),
        "listen_port": int(inbound["port"]),
        "mtu": _wireguard_mtu(settings),
        "peers": _wireguard_peers(settings, False),
    }


def _tls(stream):
    security = stream.get("security", "none")
    if security not in ("tls", "reality"):
        return None
    settings = stream.get("tlsSettings" if security == "tls" else "realitySettings") or {}
    tls = {"enabled": True}
    if "serverName" in settings:
        tls["server_name"] = settings["serverName"]
    if security == "reality":
        tls["utls"] = {
            "enabled": True,
            "fingerprint": settings.get("fingerprint", "chrome"),
        }
        tls["reality"] = {
            "enabled": True,
            "public_key": settings.get("publicKey", ""),
            "short_id": settings.get("shortId", ""),
        }
    else:
        if "caCertFile" in settings:
            tls["certificate_path"] = settings["caCertFile"]
        if "alpn" in settings:
            tls["alpn"] = settings["alpn"]
        if settings.get("allowInsecure"):
            tls["insecure"] = True
    return tls


def _early_data(path):
    """Split Xray's `?ed=N` WebSocket marker from the path sing-box speaks."""
    if not isinstance(path, str):
        raise ValueError("`wsSettings.path` must be a string")
    parsed = urlsplit(path)
    kept = []
    early = None
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key == "ed":
            if early is None:
                try:
                    early = int(value)
                except ValueError as error:
                    raise ValueError(
                        "`wsSettings.path` has a non-numeric `ed`"
                    ) from error
                if early < 0:
                    raise ValueError("`wsSettings.path` has a negative `ed`")
            continue
        kept.append((key, value))
    return urlunsplit(parsed._replace(query=urlencode(kept))), early


def _transport(stream):
    network = stream.get("network", "tcp")
    if network in ("tcp", ""):
        return None
    if network == "ws":
        settings = stream.get("wsSettings") or {}
        transport = {"type": "ws"}
        if "path" in settings:
            path, early = _early_data(settings["path"])
            transport["path"] = path
            if early is not None:
                transport["max_early_data"] = early
                transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return transport
    if network == "grpc":
        settings = stream.get("grpcSettings") or {}
        transport = {"type": "grpc"}
        if "serviceName" in settings:
            transport["service_name"] = settings["serviceName"]
        return transport
    if network == "httpupgrade":
        settings = stream.get("httpupgradeSettings") or {}
        transport = {"type": "httpupgrade"}
        for source, target in (("path", "path"), ("host", "host")):
            if source in settings:
                transport[target] = settings[source]
        return transport
    if network == "quic":
        return {"type": "quic"}
    raise ValueError(f"sing-box at this pin has no `{network}` transport")


def convert(document):
    outbounds = document.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        raise ValueError("`outbounds` must be a non-empty array")
    source = outbounds[0]
    protocol = source.get("protocol")
    if not protocol:
        raise ValueError("the client outbound has no `protocol`")
    settings = source.get("settings") or {}
    stream = source.get("streamSettings") or {}
    tag = source.get("tag", "proxy")
    if protocol == "wireguard":
        endpoint = _wireguard_client(settings, tag)
        return {
            "endpoints": [endpoint],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": tag},
        }
    outbound = {"type": protocol, "tag": tag}

    if protocol == "vless":
        server = _first(settings.get("vnext"), "`vnext`")
        user = _first(server.get("users"), "`vnext[0].users`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["uuid"] = user["id"]
        if user.get("flow"):
            outbound["flow"] = user["flow"]
    elif protocol == "vmess":
        server = _first(settings.get("vnext"), "`vnext`")
        user = _first(server.get("users"), "`vnext[0].users`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["uuid"] = user["id"]
        outbound["security"] = user.get("security", "auto")
        if user.get("alterId"):
            outbound["alter_id"] = user["alterId"]
    elif protocol == "trojan":
        server = _first(settings.get("servers"), "`servers`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["password"] = server["password"]
    elif protocol == "shadowsocks":
        server = _first(settings.get("servers"), "`servers`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["method"] = server["method"]
        outbound["password"] = server["password"]
    elif protocol in ("socks", "http"):
        server = _first(settings.get("servers"), "`servers`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        if protocol == "socks":
            outbound["version"] = "5"
        users = server.get("users")
        if users:
            user = _first(users, "`servers[0].users`")
            outbound["username"] = user.get("user", "")
            outbound["password"] = user.get("pass", "")
    elif protocol == "anytls":
        server = _first(settings.get("servers"), "`servers`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["password"] = server["password"]
    elif protocol == "tuic":
        server = _first(settings.get("servers"), "`servers`")
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["uuid"] = server["uuid"]
        outbound["password"] = server["password"]
        if "congestion_control" in server:
            outbound["congestion_control"] = server["congestion_control"]
    elif protocol == "hysteria":
        if settings.get("version") != 1:
            raise ValueError("sing-box at this pin carries only Hysteria v1 here")
        server = settings
        if settings.get("servers"):
            server = _first(settings["servers"], "`servers`")
        outbound["type"] = "hysteria"
        outbound["server"] = server["address"]
        outbound["server_port"] = server["port"]
        outbound["auth_str"] = server.get("auth", settings.get("auth", ""))
        outbound["up_mbps"] = 100
        outbound["down_mbps"] = 100
        obfs = (stream.get("tlsSettings") or {}).get("obfs")
        if obfs:
            outbound["obfs"] = obfs
    else:
        raise ValueError(f"sing-box at this pin has no `{protocol}` client here")

    tls = _tls(stream)
    if tls is not None:
        outbound["tls"] = tls
        if protocol == "vmess" and outbound.get("security") == "auto":
            outbound["security"] = "aes-128-gcm"
    if protocol != "hysteria":
        transport = _transport(stream)
        if transport is not None:
            outbound["transport"] = transport
    return {"outbounds": [outbound], "route": {"final": outbound["tag"]}}


def _certificate(settings):
    certificate = _first(settings.get("certificates"), "`tlsSettings.certificates`")
    if "certificateFile" not in certificate or "keyFile" not in certificate:
        raise ValueError("`tlsSettings.certificates[0]` needs a file and a key")
    return certificate["certificateFile"], certificate["keyFile"]


def _server_tls(stream):
    security = stream.get("security")
    if security == "reality":
        settings = stream.get("realitySettings") or {}
        short_ids = settings.get("shortIds") or []
        if not isinstance(short_ids, list):
            raise ValueError("`realitySettings.shortIds` must be an array")
        reality = {
            "enabled": True,
            "private_key": settings.get("privateKey", ""),
            "short_id": short_ids,
        }
        tls = {"enabled": True, "reality": reality}
        names = settings.get("serverNames")
        if isinstance(names, list) and names:
            tls["server_name"] = names[0]
        dest = settings.get("dest")
        if dest:
            host, separator, port = str(dest).rpartition(":")
            if not separator or not host:
                raise ValueError("`realitySettings.dest` is not a host and port")
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            try:
                port = int(port)
            except ValueError as error:
                raise ValueError("`realitySettings.dest` has no numeric port") from error
            if not 0 < port < 65536:
                raise ValueError("`realitySettings.dest` has a port outside 1...65535")
            reality["handshake"] = {"server": host, "server_port": port}
        return tls
    if security != "tls":
        return None
    settings = stream.get("tlsSettings") or {}
    certificate, key = _certificate(settings)
    tls = {
        "enabled": True,
        "certificate_path": certificate,
        "key_path": key,
    }
    if "alpn" in settings:
        tls["alpn"] = settings["alpn"]
    return tls


def _server_inbound(inbound):
    protocol = inbound.get("protocol")
    if protocol == "socks":
        return {
            "type": "socks",
            "tag": inbound.get("tag", "socks-in"),
            "listen": inbound.get("listen", "127.0.0.1"),
            "listen_port": inbound["port"],
        }
    if protocol == "tuic":
        settings = inbound.get("settings") or {}
        users = settings.get("users") or settings.get("clients")
        if not isinstance(users, list) or not users:
            if not settings.get("uuid") or not settings.get("password"):
                raise ValueError("the TUIC server needs at least one user")
            users = [settings]
        converted = {
            "type": "tuic",
            "tag": inbound.get("tag", "tuic-in"),
            "listen": inbound.get("listen", "127.0.0.1"),
            "listen_port": inbound["port"],
            "users": [
                {
                    "name": user.get("name", f"user-{index}"),
                    "uuid": user["uuid"],
                    "password": user["password"],
                }
                for index, user in enumerate(users)
            ],
        }
        tls = _server_tls(inbound.get("streamSettings") or {})
        if tls is not None:
            converted["tls"] = tls
        return converted
    if protocol == "anytls":
        settings = inbound.get("settings") or {}
        users = settings.get("users") or settings.get("clients")
        if not isinstance(users, list) or not users:
            raise ValueError("the AnyTLS server needs at least one user")
        converted = {
            "type": "anytls",
            "tag": inbound.get("tag", "anytls-in"),
            "listen": inbound.get("listen", "127.0.0.1"),
            "listen_port": inbound["port"],
            "users": [
                {
                    "name": user.get("name", f"user-{index}"),
                    "password": user["password"],
                }
                for index, user in enumerate(users)
            ],
        }
        tls = _server_tls(inbound.get("streamSettings") or {})
        if tls is not None:
            converted["tls"] = tls
        return converted
    if protocol == "vless":
        settings = inbound.get("settings") or {}
        stream = inbound.get("streamSettings") or {}
        users = settings.get("clients")
        if not isinstance(users, list) or not users:
            raise ValueError("the VLESS server needs at least one client")
        converted = {
            "type": "vless",
            "tag": inbound.get("tag", "vless-in"),
            "listen": inbound.get("listen", "127.0.0.1"),
            "listen_port": inbound["port"],
            "users": [
                {
                    "name": user.get("name", f"user-{index}"),
                    "uuid": user["id"],
                    "flow": user.get("flow", ""),
                }
                for index, user in enumerate(users)
            ],
        }
        tls = _server_tls(stream)
        if tls is not None:
            converted["tls"] = tls
        transport = _transport(stream)
        if transport is not None:
            converted["transport"] = transport
        return converted
    if protocol != "hysteria":
        raise ValueError(f"sing-box at this pin has no `{protocol}` server here")
    settings = inbound.get("settings") or {}
    if settings.get("version") != 1:
        raise ValueError("sing-box at this pin carries only Hysteria v1 here")
    stream = inbound.get("streamSettings") or {}
    tls_settings = stream.get("tlsSettings") or {}
    certificate, key = _certificate(tls_settings)
    users = settings.get("users") or settings.get("clients")
    if not isinstance(users, list) or not users:
        raise ValueError("the Hysteria v1 server needs at least one user")
    converted = {
        "type": "hysteria",
        "tag": inbound.get("tag", "hysteria-in"),
        "listen": inbound.get("listen", "127.0.0.1"),
        "listen_port": inbound["port"],
        "up_mbps": 100,
        "down_mbps": 100,
        "users": [
            {"auth_str": user.get("auth", user.get("auth_str", ""))}
            for user in users
        ],
        "tls": {
            "enabled": True,
            "alpn": tls_settings.get("alpn", ["hysteria"]),
            "certificate_path": certificate,
            "key_path": key,
        },
    }
    if tls_settings.get("obfs"):
        converted["obfs"] = tls_settings["obfs"]
    return converted


def convert_server(document):
    inbounds = document.get("inbounds")
    if not isinstance(inbounds, list) or not inbounds:
        raise ValueError("`inbounds` must be a non-empty array")
    converted = {
        "inbounds": [],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
    }
    for inbound in inbounds:
        if inbound.get("protocol") == "wireguard":
            converted.setdefault("endpoints", []).append(_wireguard_server(inbound))
        else:
            converted["inbounds"].append(_server_inbound(inbound))
    return converted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--server", action="store_true")
    args = parser.parse_args()
    try:
        document = json.loads(args.input.read_text())
        converted = convert_server(document) if args.server else convert(document)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"xray-to-singbox: {error}", file=sys.stderr)
        return 2
    args.output.write_text(json.dumps(converted, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
