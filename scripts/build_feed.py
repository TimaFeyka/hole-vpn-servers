#!/usr/bin/env python3
"""Build the HoleNet server feed from the two configured upstream sources."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


VPNGATE_URL = "https://www.vpngate.net/api/iphone/"
XRAY_RAW_ROOT = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main"
XRAY_FILES = (
    "BLACK_VLESS_RUS_mobile.txt",
    "BLACK_SS+All_RUS.txt",
    "Vless-Reality-White-Lists-Rus-Mobile.txt",
    "WHITE-CIDR-RU-checked.txt",
    "WHITE-SNI-RU-all.txt",
)
SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}
OUTPUT_DIR = Path(os.environ.get("FEED_OUTPUT_DIR", Path(__file__).parents[1] / "data"))
USER_AGENT = "HoleNetFeedBuilder/1.0 (+https://github.com/TimaFeyka/hole-vpn-servers)"


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        import certifi  # type: ignore[import-not-found]
        context = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=45, context=context) as response:
        return response.read().decode("utf-8-sig")


def flag_for(code: str) -> str:
    code = code.strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        return "🌍"
    return "".join(chr(127397 + ord(char)) for char in code)


def country_from_name(name: str) -> tuple[str, str]:
    for first, second in zip(name, name[1:]):
        if 0x1F1E6 <= ord(first) <= 0x1F1FF and 0x1F1E6 <= ord(second) <= 0x1F1FF:
            code = chr(ord(first) - 127397) + chr(ord(second) - 127397)
            return code, first + second
    return "", "🌍"


def protocol_for(link: str) -> str:
    scheme = link.split("://", 1)[0].lower()
    return "hysteria2" if scheme == "hy2" else scheme


def parse_ovpn(raw: str) -> list[dict]:
    lines = [line for line in raw.splitlines() if line and not line.startswith("*")]
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    servers: list[dict] = []
    seen: set[str] = set()
    for row in reader:
        encoded = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        try:
            config = base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if "client" not in config or "remote " not in config:
            continue
        digest = hashlib.sha256(config.encode()).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        code = (row.get("CountryShort") or "").strip().upper()
        country = (row.get("CountryLong") or "VPN Gate").strip()
        host = (row.get("HostName") or row.get("IP") or "Server").strip()
        try:
            ping = max(0, int(row.get("Ping") or 0))
        except ValueError:
            ping = 0
        try:
            score = int(row.get("Score") or 0)
        except ValueError:
            score = 0
        servers.append({
            "name": f"{country} · {host}",
            "flag": flag_for(code),
            "countryCode": code,
            "isOptimal": False,
            "ping": ping,
            "configUrl": f"feed://ovpn/{digest[:16]}",
            "configContent": config,
            "protocol": "openvpn",
            "isPremium": False,
            "xtlsVision": False,
            "xtlsVisionFlow": None,
            "_score": score,
        })
    servers.sort(key=lambda item: (-item.pop("_score"), item["ping"] or 999999))
    return servers


def parse_xray(documents: list[tuple[str, str]]) -> list[dict]:
    servers: list[dict] = []
    seen: set[str] = set()
    for source_name, raw in documents:
        for line in raw.splitlines():
            link = line.strip().strip('"\'')
            if "://" not in link:
                continue
            scheme = link.split("://", 1)[0].lower()
            if scheme not in SUPPORTED_SCHEMES or link in seen:
                continue
            seen.add(link)
            fragment = urllib.parse.urlsplit(link).fragment
            name = urllib.parse.unquote(fragment).strip() or f"Xray · {source_name}"
            country_code, flag = country_from_name(name)
            flow = "xtls-rprx-vision" if "flow=xtls-rprx-vision" in link else None
            servers.append({
                "name": name,
                "flag": flag,
                "countryCode": country_code,
                "isOptimal": False,
                "ping": 0,
                "configUrl": link,
                "configContent": None,
                "protocol": protocol_for(link),
                "isPremium": False,
                "xtlsVision": flow is not None,
                "xtlsVisionFlow": flow,
            })
    return servers


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    ovpn = parse_ovpn(fetch(VPNGATE_URL))
    xray_docs = [(name, fetch(f"{XRAY_RAW_ROOT}/{urllib.parse.quote(name)}")) for name in XRAY_FILES]
    xray = parse_xray(xray_docs)
    if not ovpn:
        raise RuntimeError("VPN Gate returned no valid OpenVPN profiles")
    if not xray:
        raise RuntimeError("Xray upstream returned no supported share links")

    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    servers = ovpn + xray
    payload = {
        "schemaVersion": 1,
        "generatedAt": generated_at,
        "counts": {"openvpn": len(ovpn), "xray": len(xray), "total": len(servers)},
        "sources": {"openvpn": VPNGATE_URL, "xray": "https://github.com/igareck/vpn-configs-for-russia"},
        "servers": servers,
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_json(OUTPUT_DIR / "servers.json", payload)
    write_json(OUTPUT_DIR / "ovpn.json", {**payload, "servers": ovpn})
    write_json(OUTPUT_DIR / "xray.json", {**payload, "servers": xray})
    print(f"openvpn: {len(ovpn)}")
    print(f"xray: {len(xray)}")
    print(f"total: {len(servers)}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(f"feed build failed: {error}", file=sys.stderr)
        sys.exit(1)
