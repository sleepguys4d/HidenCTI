"""
Módulo: Breach Monitoring (apenas domínios próprios/autorizados)
Monitoriza exposição da TUA organização em fugas de dados conhecidas.

IMPORTANTE — âmbito de utilização:
  - A pesquisa por domínio na HaveIBeenPwned EXIGE que tenhas verificado a posse
    do domínio na própria HIBP. A API só devolve resultados de domínios teus.
  - Esta ferramenta NÃO faz lookup de indivíduos arbitrários nem expõe
    credenciais. Serve para a equipa de segurança saber QUE contas da própria
    organização foram afetadas e acionar reset de passwords / resposta a incidentes.
  - O catálogo de brechas (que fugas existem) é informação pública e pode ser
    consultado livremente para contexto de threat intelligence.
"""

from __future__ import annotations

from .. import console as c
from ..config import config
from ..utils import http

HIBP_BASE = "https://haveibeenpwned.com/api/v3"


def list_known_breaches(domain_filter: str | None = None) -> list[dict]:
    """Catálogo público de brechas conhecidas (contexto de CTI)."""
    try:
        url = f"{HIBP_BASE}/breaches"
        if domain_filter:
            url += f"?domain={domain_filter}"
        return http.get_json(url, min_interval=2.0)
    except Exception as e:
        c.warn(f"Catálogo HIBP indisponível: {e}")
        return []


def domain_exposure(your_domain: str) -> dict:
    """
    Contas DO TEU DOMÍNIO afetadas por brechas.
    Requer chave HIBP + posse do domínio verificada na HIBP.
    """
    key = config.get_key("hibp")
    if not key:
        c.warn("Sem chave HIBP — define HIBP_API_KEY para monitorizar o teu domínio.")
        return {}
    try:
        data = http.get_json(
            f"{HIBP_BASE}/breacheddomain/{your_domain}",
            headers={"hibp-api-key": key},
            min_interval=2.0,
        )
        return data or {}
    except Exception as e:
        c.warn(
            f"HIBP domain falhou ({e}). Confirma que verificaste a posse de "
            f"'{your_domain}' na tua conta HIBP."
        )
        return {}


def run(your_domain: str) -> None:
    c.rule(f"Breach Monitoring · {your_domain} (ativo próprio)")

    catalog = list_known_breaches(your_domain)
    if catalog:
        c.rule("Brechas conhecidas associadas ao domínio (catálogo público)")
        c.table(
            "Brechas",
            ["Nome", "Data", "Contas afetadas"],
            [[b.get("Name"), b.get("BreachDate"), b.get("PwnCount")] for b in catalog],
        )

    exposure = domain_exposure(your_domain)
    if exposure:
        c.rule("Contas do teu domínio expostas (requer posse verificada)")
        for alias, breaches in exposure.items():
            c.kv(alias + "@", ", ".join(breaches))
        c.warn("Aciona reset de credenciais para as contas listadas.")
    else:
        c.info(
            "Sem dados de exposição direta. Verifica a posse do domínio na HIBP "
            "para ativar esta funcionalidade."
        )
