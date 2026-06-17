"""
Módulo: Correlation Engine
Liga um domínio à sua infraestrutura e devolve um grafo + pontos geográficos
para o mapa da plataforma.

Geolocaliza INFRAESTRUTURA (IPs, servidores, domínios de phishing) — não pessoas.
Cobre: domínio -> IPs (A) -> geo/ASN/rDNS -> subdomínios (passivo) -> lookalikes ativos.
"""

from __future__ import annotations
import socket
from typing import Any

from .. import console as c
from ..utils import http
from . import domain_intel, brand_protect

try:
    import dns.resolver
    _DNS = True
except Exception:
    _DNS = False


def _resolve_a(host: str) -> list[str]:
    if not _DNS:
        try:
            return [socket.gethostbyname(host)]
        except Exception:
            return []
    try:
        return [a.to_text() for a in dns.resolver.resolve(host, "A")]
    except Exception:
        return []


def _geo(ip: str) -> dict:
    """Geolocalização de IP com lat/lon para o mapa (ip-api, gratuito)."""
    try:
        data = http.get_json(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,isp,org,as,reverse,query"},
            min_interval=1.5,
        )
        if data.get("status") == "success":
            return data
    except Exception:
        pass
    return {}


def correlate(domain: str, max_subdomains: int = 25) -> dict[str, Any]:
    nodes: list[dict] = []
    edges: list[dict] = []
    geo_points: list[dict] = []
    seen_ips: set[str] = set()

    nodes.append({"id": domain, "type": "domain", "label": domain, "root": True})

    def add_ip(ip: str, via: str) -> None:
        edges.append({"source": via, "target": ip})
        if ip in seen_ips:
            return
        seen_ips.add(ip)
        g = _geo(ip)
        node = {
            "id": ip, "type": "ip", "label": ip,
            "country": g.get("country"), "city": g.get("city"),
            "isp": g.get("isp"), "asn": g.get("as"), "rdns": g.get("reverse"),
        }
        nodes.append(node)
        if g.get("lat") is not None and g.get("lon") is not None:
            geo_points.append({
                "ip": ip, "lat": g["lat"], "lon": g["lon"],
                "label": ip, "country": g.get("country"), "city": g.get("city"),
                "isp": g.get("isp"), "asn": g.get("as"), "kind": "host",
            })

    # 1) IPs do domínio raiz
    for ip in _resolve_a(domain):
        add_ip(ip, domain)

    # 2) Subdomínios (passivo via crt.sh) + os seus IPs
    subs = domain_intel.subdomains_crtsh(domain, limit=max_subdomains)
    for sub in subs:
        if sub == domain:
            continue
        nodes.append({"id": sub, "type": "subdomain", "label": sub})
        edges.append({"source": domain, "target": sub})
        for ip in _resolve_a(sub):
            add_ip(ip, sub)

    # 3) Lookalikes ATIVOS (potencial phishing) + geo da sua infraestrutura
    lookalikes = brand_protect.generate(domain, with_tlds=True)
    live_lookalikes: list[str] = []
    for la in lookalikes[:120]:
        if brand_protect.resolves(la):
            live_lookalikes.append(la)
            nodes.append({"id": la, "type": "lookalike", "label": la, "threat": True})
            edges.append({"source": domain, "target": la, "threat": True})
            for ip in _resolve_a(la):
                edges.append({"source": la, "target": ip, "threat": True})
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    g = _geo(ip)
                    nodes.append({"id": ip, "type": "ip", "label": ip,
                                  "country": g.get("country"), "isp": g.get("isp")})
                    if g.get("lat") is not None:
                        geo_points.append({
                            "ip": ip, "lat": g["lat"], "lon": g["lon"],
                            "label": f"{la} → {ip}", "country": g.get("country"),
                            "city": g.get("city"), "isp": g.get("isp"),
                            "asn": g.get("as"), "kind": "threat",
                        })

    return {
        "domain": domain,
        "nodes": nodes,
        "edges": edges,
        "geo_points": geo_points,
        "subdomains": subs,
        "live_lookalikes": live_lookalikes,
        "summary": {
            "ips": len(seen_ips),
            "subdomains": len(subs),
            "threats": len(live_lookalikes),
            "geo_points": len(geo_points),
        },
    }


def run(domain: str) -> None:
    c.rule(f"Correlation Engine · {domain}")
    result = correlate(domain)
    s = result["summary"]
    c.kv("IPs", s["ips"])
    c.kv("Subdomínios", s["subdomains"])
    c.kv("Lookalikes ativos (ameaça)", s["threats"])
    c.kv("Pontos no mapa", s["geo_points"])
    for gp in result["geo_points"]:
        c.kv(gp["kind"], f"{gp['label']} · {gp.get('city')}/{gp.get('country')} · {gp.get('isp')}")
