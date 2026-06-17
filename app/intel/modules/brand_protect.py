"""
Módulo: Brand Protection / Anti-Phishing
Gera variações de typosquatting/lookalike de um domínio da TUA marca e verifica
quais estão registadas/ativas — para deteção PROATIVA de infraestrutura de
phishing e abuso de marca dirigida à organização.

Técnicas de geração: omissão, inserção, transposição, substituição de carácter,
duplicação, troca de TLD e homóglifos (ataques visuais).

Destinado a proteger marcas próprias ou de clientes (brand protection).
"""

from __future__ import annotations
from typing import Iterable

from .. import console as c
from ..utils import http

try:
    import dns.resolver
    _DNS = True
except Exception:
    _DNS = False

KEYBOARD_NEIGHBORS = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wrsdf",
    "f": "rtgdvc", "g": "tyhfvb", "h": "yujgbn", "i": "ujko", "j": "uikhnm",
    "k": "ioljm", "l": "opk", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "etdf", "s": "awedxz", "t": "ryfg",
    "u": "yihj", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tugh",
    "z": "asx",
}
HOMOGLYPHS = {
    "o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"],
    "a": ["4", "@"], "s": ["5", "$"], "g": ["9"], "b": ["8"],
    "m": ["rn"], "w": ["vv"],
}
COMMON_TLDS = ["com", "net", "org", "co", "io", "info", "online", "site",
               "ao", "co.ao", "com.ao", "africa", "biz", "app", "xyz"]


def _split(domain: str) -> tuple[str, str]:
    parts = domain.lower().split(".", 1)
    return parts[0], (parts[1] if len(parts) > 1 else "com")


def omission(name: str) -> set[str]:
    return {name[:i] + name[i + 1:] for i in range(len(name)) if len(name) > 2}


def transposition(name: str) -> set[str]:
    out = set()
    for i in range(len(name) - 1):
        out.add(name[:i] + name[i + 1] + name[i] + name[i + 2:])
    return out


def repetition(name: str) -> set[str]:
    return {name[:i] + name[i] + name[i:] for i in range(len(name))}


def replacement(name: str) -> set[str]:
    out = set()
    for i, ch in enumerate(name):
        for nb in KEYBOARD_NEIGHBORS.get(ch, ""):
            out.add(name[:i] + nb + name[i + 1:])
    return out


def insertion(name: str) -> set[str]:
    out = set()
    for i in range(len(name)):
        for nb in KEYBOARD_NEIGHBORS.get(name[i], ""):
            out.add(name[:i] + nb + name[i:])
    return out


def homoglyph(name: str) -> set[str]:
    out = set()
    for i, ch in enumerate(name):
        for h in HOMOGLYPHS.get(ch, []):
            out.add(name[:i] + h + name[i + 1:])
    return out


def generate(domain: str, with_tlds: bool = True) -> list[str]:
    name, tld = _split(domain)
    variants: set[str] = set()
    for fn in (omission, transposition, repetition, replacement, insertion, homoglyph):
        variants |= fn(name)
    variants.discard(name)
    results: set[str] = {f"{v}.{tld}" for v in variants}
    if with_tlds:
        for t in COMMON_TLDS:
            if t != tld:
                results.add(f"{name}.{t}")
    return sorted(results)


def resolves(domain: str) -> bool:
    if not _DNS:
        return False
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


def crtsh_lookalikes(keyword: str, limit: int = 100) -> list[str]:
    """Procura certificados emitidos para domínios que contêm a tua marca."""
    try:
        data = http.get_json(f"https://crt.sh/?q=%25{keyword}%25&output=json", min_interval=2.0)
    except Exception as e:
        c.warn(f"crt.sh indisponível: {e}")
        return []
    names: set[str] = set()
    for entry in data:
        for n in str(entry.get("name_value", "")).splitlines():
            names.add(n.strip().lstrip("*.").lower())
    return sorted(names)[:limit]


def run(domain: str, check_live: bool = False, scan_certs: bool = False) -> None:
    c.rule(f"Brand Protection · {domain}")
    variants = generate(domain)
    c.info(f"{len(variants)} variações de typosquatting/lookalike geradas.")

    if check_live:
        c.info("A verificar quais resolvem (potencial infraestrutura ativa)...")
        live = [v for v in variants if resolves(v)]
        if live:
            c.warn(f"{len(live)} variações ATIVAS — investigar como possível phishing:")
            c.table("Domínios lookalike ativos", ["Domínio"], [[v] for v in live])
        else:
            c.ok("Nenhuma das variações geradas resolve atualmente.")
    else:
        c.table("Amostra de variações geradas", ["Domínio"],
                [[v] for v in variants[:40]])
        c.info("Usa --check-live para testar quais estão registadas/ativas.")

    if scan_certs:
        name, _ = _split(domain)
        c.rule("Certificados que contêm a marca (Certificate Transparency)")
        hits = crtsh_lookalikes(name)
        c.table("Domínios em certificados", ["Domínio (verificar legitimidade)"],
                [[h] for h in hits[:60]])
