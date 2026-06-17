"""
Collectors: run the intelligence modules and materialize results as
entities / relations / events / geo points inside an Investigation.

Geolocates INFRASTRUCTURE. No lookup of people or third-party breach data.
"""

from __future__ import annotations
import socket
from typing import Any

from ..core.models import Entity, EntityType, Investigation, Severity
from ..intel.modules import (
    domain_intel, ip_intel, cti, brand_protect, profile_analyzer, breach_monitor,
)
from ..intel.utils import http

try:
    import dns.resolver
    _DNS = True
except Exception:
    _DNS = False


def _resolve_a(host: str) -> list[str]:
    try:
        if _DNS:
            return [a.to_text() for a in dns.resolver.resolve(host, "A")]
        return [socket.gethostbyname(host)]
    except Exception:
        return []


def _geo(ip: str) -> dict:
    try:
        d = http.get_json(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,lat,lon,isp,org,as,reverse,query"},
            min_interval=1.4,
        )
        return d if d.get("status") == "success" else {}
    except Exception:
        return {}


def _add_ip(inv: Investigation, ip: str, via: Entity, kind: str, threat: bool = False) -> Entity:
    g = _geo(ip)
    ent = Entity(
        type=EntityType.ip, label=ip,
        severity=Severity.high if threat else Severity.info,
        lat=g.get("lat"), lon=g.get("lon"),
        attrs={"country": g.get("country"), "city": g.get("city"),
               "isp": g.get("isp"), "asn": g.get("as"), "rdns": g.get("reverse")},
    )
    ent = inv.upsert_entity(ent)
    inv.link(via, ent, kind, threat=threat)
    return ent


# ---------------------------------------------------------------- domain
def collect_domain(inv: Investigation, domain: str, deep: bool = True) -> dict[str, Any]:
    root = inv.upsert_entity(Entity(type=EntityType.domain, label=domain))
    recs = domain_intel.dns_records(domain)
    dmarc = domain_intel.dmarc_record(domain)
    posture = domain_intel.email_posture(recs.get("TXT", []))
    whois = domain_intel.whois_info(domain)
    headers = domain_intel.security_headers(domain)

    root.attrs.update({
        "spf": bool(posture.get("spf")), "dmarc": bool(dmarc),
        "registrar": whois.get("registrar"), "org": whois.get("org"),
    })
    if not posture.get("spf") or not dmarc:
        root.severity = Severity.medium

    for ip in recs.get("A", []):
        _add_ip(inv, ip, root, "resolves_to")

    subs = domain_intel.subdomains_crtsh(domain) if deep else []
    for sub in subs:
        if sub == domain:
            continue
        se = inv.upsert_entity(Entity(type=EntityType.subdomain, label=sub))
        inv.link(root, se, "has_subdomain")
        for ip in _resolve_a(sub):
            _add_ip(inv, ip, se, "resolves_to")

    inv.log("domain", "collect", f"Domain {domain}: {len(recs.get('A', []))} IPs, "
            f"{len(subs)} subdomains. SPF={bool(posture.get('spf'))} DMARC={bool(dmarc)}.",
            severity=root.severity, entity_ids=[root.id])
    return {"dns": recs, "dmarc": dmarc, "email_posture": posture,
            "whois": whois, "security_headers": headers, "subdomains": subs}


# ---------------------------------------------------------------- ip
def collect_ip(inv: Investigation, ip: str) -> dict[str, Any]:
    g = ip_intel.geo_asn(ip)
    rep = ip_intel.abuseipdb(ip)
    sh = ip_intel.shodan_host(ip)
    sev = Severity.info
    if rep.get("abuseConfidenceScore", 0) and rep["abuseConfidenceScore"] >= 50:
        sev = Severity.high
    ent = inv.upsert_entity(Entity(
        type=EntityType.ip, label=ip, severity=sev,
        lat=g.get("lat"), lon=g.get("lon"),
        attrs={"country": g.get("country"), "city": g.get("city"),
               "isp": g.get("isp"), "asn": g.get("as"),
               "rdns": ip_intel.reverse_dns(ip),
               "abuse_score": rep.get("abuseConfidenceScore"),
               "ports": sh.get("ports")},
    ))
    inv.log("ip", "collect", f"IP {ip} enriched (abuse={rep.get('abuseConfidenceScore')}).",
            severity=sev, entity_ids=[ent.id])
    return {"geo": g, "reputation": rep, "shodan": sh,
            "rdns": ent.attrs.get("rdns")}


# ---------------------------------------------------------------- brand / phishing
def collect_brand(inv: Investigation, domain: str, check_live: bool = True) -> dict[str, Any]:
    root = inv.upsert_entity(Entity(type=EntityType.domain, label=domain))
    variants = brand_protect.generate(domain)
    live: list[str] = []
    if check_live:
        for v in variants:
            if brand_protect.resolves(v):
                live.append(v)
                le = inv.upsert_entity(Entity(
                    type=EntityType.lookalike, label=v, severity=Severity.high,
                    attrs={"status": "active"}))
                inv.link(root, le, "impersonated_by", threat=True)
                for ip in _resolve_a(v):
                    _add_ip(inv, ip, le, "resolves_to", threat=True)
    inv.log("brand", "collect",
            f"{len(variants)} variants generated, {len(live)} live (threat).",
            severity=Severity.high if live else Severity.info,
            entity_ids=[root.id])
    return {"variants": variants, "count": len(variants), "live": live}


# ---------------------------------------------------------------- profile
def collect_profile(inv: Investigation, payload: dict) -> dict[str, Any]:
    sig = profile_analyzer.ProfileSignals(
        handle=payload.get("handle", "@profile"),
        account_age_days=payload.get("age_days"),
        followers=payload.get("followers"), following=payload.get("following"),
        post_count=payload.get("posts"),
        has_profile_photo=payload.get("has_photo"),
        photo_is_reused=payload.get("photo_reused"),
        handle_resembles_brand=payload.get("resembles_brand"),
        name_matches_known_person=payload.get("impersonates_person"),
        verified=payload.get("verified"),
        posts_only_promotional=payload.get("promo_only"),
        default_username_pattern=payload.get("auto_username"),
    )
    score, verdict, findings = profile_analyzer.analyze(sig)
    sev = Severity.critical if score >= 65 else Severity.medium if score >= 35 else Severity.low
    ent = inv.upsert_entity(Entity(
        type=EntityType.source, label=sig.handle, severity=sev,
        attrs={"impersonation_score": score, "verdict": verdict, "kind": "suspect_profile"}))
    inv.log("profile", "analyze", f"Profile {sig.handle}: risk {score}/100 — {verdict}.",
            severity=sev, entity_ids=[ent.id])
    return {"handle": sig.handle, "score": score, "verdict": verdict,
            "findings": [{"weight": f.weight, "reason": f.reason} for f in findings]}


# ---------------------------------------------------------------- breach (org)
def collect_breach(inv: Investigation, domain: str) -> dict[str, Any]:
    catalog = breach_monitor.list_known_breaches(domain)
    exposure = breach_monitor.domain_exposure(domain)
    root = inv.upsert_entity(Entity(type=EntityType.domain, label=domain))
    sev = Severity.high if exposure else (Severity.medium if catalog else Severity.info)
    if sev != Severity.info and root.severity.value != "critical":
        root.severity = sev
    inv.log("breach", "collect",
            f"Organization exposure: {len(catalog)} catalogued breaches, "
            f"{len(exposure)} exposed aliases.", severity=sev, entity_ids=[root.id])
    return {"catalog": catalog, "exposure": exposure,
            "note": ("Direct exposure requires verified domain ownership on HIBP. "
                     "No lookup of arbitrary individuals' breach data.")}


# ---------------------------------------------------------------- cti
def collect_cti(inv: Investigation, ioc: str | None, cve: str | None) -> dict[str, Any]:
    if cve:
        res = cti.cve_lookup(cve)
        if res:
            sev_map = {"CRITICAL": Severity.critical, "HIGH": Severity.high,
                       "MEDIUM": Severity.medium, "LOW": Severity.low}
            sev = sev_map.get(str(res.get("severity", "")).upper(), Severity.info)
            ent = inv.upsert_entity(Entity(type=EntityType.cve, label=cve, severity=sev,
                                           attrs={"cvss": res.get("cvss"),
                                                  "severity": res.get("severity")}))
            inv.log("cti", "cve", f"{cve} · CVSS {res.get('cvss')} · {res.get('severidade')}.",
                    severity=sev, entity_ids=[ent.id])
        return {"type": "cve", "result": res}
    res = cti.virustotal(ioc) if ioc else {}
    if res:
        mal = res.get("malicious") or 0
        sev = Severity.high if mal and mal > 0 else Severity.info
        ent = inv.upsert_entity(Entity(type=EntityType.ioc, label=ioc, severity=sev,
                                       attrs=res))
        inv.log("cti", "ioc", f"IOC {ioc}: {mal} malicious detections.",
                severity=sev, entity_ids=[ent.id])
    return {"type": "ioc", "result": res}
