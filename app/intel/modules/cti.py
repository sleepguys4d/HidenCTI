"""
Módulo: Cyber Threat Intelligence (CTI)
Enriquecimento de IOCs (hash/domínio/IP) e consulta de vulnerabilidades (CVE).

Fontes:
  - VirusTotal v3 (chave): reputação de ficheiros, domínios e IPs.
  - NVD (NIST, sem chave obrigatória): detalhes e severidade de CVEs.
"""

from __future__ import annotations
from typing import Optional

from .. import console as c
from ..config import config
from ..utils import http, validators


def virustotal(ioc: str) -> dict:
    key = config.get_key("virustotal")
    if not key:
        c.warn("No VirusTotal key — skipping VT enrichment.")
        return {}
    kind = validators.detect_ioc(ioc)
    endpoint = {
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
    }.get(kind)
    if not endpoint:
        c.err(f"IOC type not supported by VT: {kind}")
        return {}
    try:
        data = http.get_json(endpoint, headers={"x-apikey": key}, min_interval=16.0)
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "type": kind,
            "malicious": stats.get("malicious"),
            "suspicious": stats.get("suspicious"),
            "harmless": stats.get("harmless"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags"),
        }
    except Exception as e:
        c.warn(f"VirusTotal failed: {e}")
        return {}


def cve_lookup(cve_id: str) -> dict:
    """Look up CVE details on NVD (NIST)."""
    cve_id = cve_id.strip().upper()
    try:
        data = http.get_json(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            min_interval=6.0,
        )
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        cve = vulns[0]["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        metrics = cve.get("metrics", {})
        score = None
        severity = None
        for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if ver in metrics and metrics[ver]:
                m = metrics[ver][0]["cvssData"]
                score = m.get("baseScore")
                severity = m.get("baseSeverity") or metrics[ver][0].get("baseSeverity")
                break
        return {
            "id": cve_id,
            "description": desc,
            "cvss": score,
            "severity": severity,
            "published": cve.get("published"),
        }
    except Exception as e:
        c.warn(f"NVD failed: {e}")
        return {}


def run_ioc(ioc: str) -> None:
    kind = validators.detect_ioc(ioc)
    c.rule(f"CTI · Enriquecimento de IOC ({kind}) · {ioc}")
    vt = virustotal(ioc)
    if vt:
        for k, v in vt.items():
            c.kv(k, v)
    else:
        c.info("Sem dados de enriquecimento (verifica a chave VT ou o tipo de IOC).")


def run_cve(cve_id: str) -> None:
    c.rule(f"CTI · Vulnerabilidade · {cve_id}")
    cve = cve_lookup(cve_id)
    if not cve:
        c.err("CVE não encontrada.")
        return
    c.kv("CVE", cve["id"])
    c.kv("CVSS", cve["cvss"])
    c.kv("Severity", cve["severity"])
    c.kv("Published", cve["published"])
    c.kv("Description", (cve["description"][:240] + "…") if len(cve["description"]) > 240 else cve["description"])
