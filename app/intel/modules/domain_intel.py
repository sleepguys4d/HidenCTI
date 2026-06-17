"""
Módulo: Domain Intelligence
Reconhecimento passivo de infraestrutura sobre DOMÍNIOS.

Cobre: registos DNS, WHOIS, postura de segurança de email (SPF/DMARC/DKIM),
enumeração passiva de subdomínios via Certificate Transparency (crt.sh) e
verificação de cabeçalhos de segurança HTTP.

Uso destinado a ativos próprios ou a alvos com autorização explícita
(engagements de cliente, threat intelligence defensiva, brand protection).
"""

from __future__ import annotations
from typing import Optional

from .. import console as c
from ..utils import http

try:
    import dns.resolver
    _DNS = True
except Exception:
    _DNS = False

try:
    import whois as _whois_lib
    _WHOIS = True
except Exception:
    _WHOIS = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def dns_records(domain: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not _DNS:
        c.warn("dnspython não instalado — a saltar registos DNS (pip install dnspython).")
        return out
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 8.0
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            out[rtype] = [a.to_text() for a in answers]
        except Exception:
            continue
    return out


def email_posture(txt_records: list[str]) -> dict[str, Optional[str]]:
    """Avalia presença de SPF e DMARC a partir de registos TXT."""
    spf = next((t for t in txt_records if "v=spf1" in t.lower()), None)
    dmarc = None  # DMARC vive em _dmarc.<domain>; consultado à parte
    return {"spf": spf, "dmarc": dmarc}


def dmarc_record(domain: str) -> Optional[str]:
    if not _DNS:
        return None
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for a in answers:
            txt = a.to_text().strip('"')
            if "v=dmarc1" in txt.lower():
                return txt
    except Exception:
        return None
    return None


def whois_info(domain: str) -> dict:
    if not _WHOIS:
        c.warn("python-whois não instalado — a saltar WHOIS (pip install python-whois).")
        return {}
    try:
        w = _whois_lib.whois(domain)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "org": getattr(w, "org", None),
            "country": getattr(w, "country", None),
        }
    except Exception as e:
        c.warn(f"WHOIS falhou: {e}")
        return {}


def subdomains_crtsh(domain: str, limit: int = 200) -> list[str]:
    """Enumeração PASSIVA de subdomínios via Certificate Transparency (crt.sh)."""
    try:
        data = http.get_json(
            f"https://crt.sh/?q=%25.{domain}&output=json", min_interval=2.0
        )
    except Exception as e:
        c.warn(f"crt.sh indisponível: {e}")
        return []
    found: set[str] = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain):
                found.add(name)
    return sorted(found)[:limit]


def security_headers(domain: str) -> dict[str, Optional[str]]:
    """Verifica cabeçalhos de segurança HTTP relevantes."""
    wanted = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
    ]
    try:
        import requests
        r = requests.get(f"https://{domain}", timeout=15,
                         headers={"User-Agent": http.USER_AGENT})
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {h: headers.get(h) for h in wanted}
    except Exception as e:
        c.warn(f"Não foi possível obter cabeçalhos HTTP: {e}")
        return {h: None for h in wanted}


def run(domain: str, deep: bool = False) -> None:
    c.rule(f"Domain Intelligence · {domain}")

    recs = dns_records(domain)
    for rtype, values in recs.items():
        for v in values:
            c.kv(rtype, v)

    dmarc = dmarc_record(domain)
    posture = email_posture(recs.get("TXT", []))
    c.rule("Postura de Email")
    c.kv("SPF", posture["spf"] or "[em falta]")
    c.kv("DMARC", dmarc or "[em falta]")

    w = whois_info(domain)
    if w:
        c.rule("WHOIS")
        for k, v in w.items():
            c.kv(k, v)

    c.rule("Cabeçalhos de Segurança HTTP")
    for h, v in security_headers(domain).items():
        c.kv(h, v or "[em falta]")

    if deep:
        c.rule("Subdomínios (Certificate Transparency)")
        subs = subdomains_crtsh(domain)
        c.info(f"{len(subs)} subdomínios encontrados (passivo).")
        for s in subs:
            c.kv("subdomínio", s)
