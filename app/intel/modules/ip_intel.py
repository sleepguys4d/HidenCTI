"""
Módulo: IP / Infrastructure Intelligence
Enriquecimento de endereços IP: rDNS, geolocalização, ASN e reputação.

Fontes gratuitas (sem chave): ip-api.com.
Fontes com chave: AbuseIPDB (reputação), Shodan (exposição de serviços).
"""

from __future__ import annotations
import socket
from typing import Optional

from .. import console as c
from ..config import config
from ..utils import http


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def geo_asn(ip: str) -> dict:
    """Geolocalização + ASN via ip-api.com (gratuito, sem chave)."""
    try:
        data = http.get_json(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,isp,org,as,query"},
            min_interval=1.5,
        )
        if data.get("status") == "success":
            return data
    except Exception as e:
        c.warn(f"ip-api indisponível: {e}")
    return {}


def abuseipdb(ip: str) -> dict:
    key = config.get_key("abuseipdb")
    if not key:
        c.warn("Sem chave AbuseIPDB — a saltar reputação.")
        return {}
    try:
        data = http.get_json(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            min_interval=1.0,
        )
        d = data.get("data", {})
        return {
            "abuseConfidenceScore": d.get("abuseConfidenceScore"),
            "totalReports": d.get("totalReports"),
            "isWhitelisted": d.get("isWhitelisted"),
            "usageType": d.get("usageType"),
        }
    except Exception as e:
        c.warn(f"AbuseIPDB falhou: {e}")
        return {}


def shodan_host(ip: str) -> dict:
    key = config.get_key("shodan")
    if not key:
        c.warn("Sem chave Shodan — a saltar exposição de serviços.")
        return {}
    try:
        data = http.get_json(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
            min_interval=1.0,
        )
        return {
            "ports": data.get("ports"),
            "hostnames": data.get("hostnames"),
            "os": data.get("os"),
            "vulns": list(data.get("vulns", [])) if data.get("vulns") else [],
            "tags": data.get("tags"),
        }
    except Exception as e:
        c.warn(f"Shodan falhou: {e}")
        return {}


def run(ip: str) -> None:
    c.rule(f"IP / Infrastructure Intelligence · {ip}")

    rdns = reverse_dns(ip)
    c.kv("Reverse DNS", rdns or "[nenhum]")

    geo = geo_asn(ip)
    if geo:
        c.kv("País", geo.get("country"))
        c.kv("Região/Cidade", f"{geo.get('regionName')} / {geo.get('city')}")
        c.kv("ISP", geo.get("isp"))
        c.kv("Organização", geo.get("org"))
        c.kv("ASN", geo.get("as"))

    rep = abuseipdb(ip)
    if rep:
        c.rule("Reputação (AbuseIPDB)")
        for k, v in rep.items():
            c.kv(k, v)

    sh = shodan_host(ip)
    if sh:
        c.rule("Exposição de Serviços (Shodan)")
        for k, v in sh.items():
            c.kv(k, v)
