"""
Módulo: Operational Security (OPSEC)
Duas funções:
  1. Autoavaliação OPSEC da organização/analista (checklist com score).
  2. Orientação de ATRIBUIÇÃO GERIDA para investigação OSINT legítima — como uma
     equipa SOC/CTI conduz pesquisa sem expor a identidade real do analista nem a
     infraestrutura corporativa.

Nota: este módulo fornece BOAS PRÁTICAS de OPSEC e atribuição gerida. Não gera
identidades falsas, biografias, fotografias nem automatiza criação de contas —
essas capacidades servem deceção/fraude e estão fora do âmbito desta ferramenta.
"""

from __future__ import annotations

from .. import console as c

CHECKLIST = [
    ("MFA em todas as contas críticas (email, redes, cloud, repositórios)?", 10),
    ("Gestor de passwords com passwords únicas por serviço?", 10),
    ("Separação clara entre contas pessoais e contas de trabalho/investigação?", 12),
    ("VPN/rede dedicada para atividade de investigação OSINT?", 10),
    ("Navegador/VM isolada e descartável para pesquisa (sem cookies pessoais)?", 12),
    ("Metadados removidos de ficheiros antes de partilhar (EXIF, autor)?", 6),
    ("DMARC/SPF/DKIM configurados nos domínios da organização?", 8),
    ("Monitorização de marca/typosquatting ativa?", 8),
    ("Plano de resposta a incidentes documentado e testado?", 10),
    ("Backups offline testados e cifrados?", 8),
    ("Formação de phishing/engenharia social para a equipa nos últimos 12 meses?", 6),
]

MANAGED_ATTRIBUTION = [
    "Objetivo e enquadramento legal: define o âmbito da investigação e a base "
    "legal/autorização antes de começar. Documenta tudo (cadeia de custódia).",
    "Infraestrutura separada: usa uma máquina/VM dedicada, isolada da rede "
    "corporativa, sem sessões nem cookies pessoais.",
    "Rede dedicada: encaminha o tráfego por uma ligação que não revele a "
    "infraestrutura da organização (VPN/rede de investigação).",
    "Higiene de browser: containers/perfis isolados, bloqueio de fingerprinting, "
    "limpeza de sessão entre alvos.",
    "Minimização de pegada: não interajas (likes, follows, comentários) com os "
    "alvos — observa apenas conteúdo público. Interação ativa pode contaminar a "
    "prova e alertar o alvo.",
    "Registo e prova: captura com timestamp e hash; preserva originais para "
    "valor probatório.",
    "Conformidade com ToS e lei: respeita os termos das plataformas e a "
    "legislação aplicável (em Angola, Lei 22/11 de proteção de dados e demais "
    "diploma aplicável). Quando o caso for sensível, envolve jurídico.",
    "Sem deceção ativa de terceiros: a atribuição gerida protege o analista; não "
    "serve para criar identidades fictícias que enganem pessoas ou plataformas.",
]


def self_assessment(answers: list[bool]) -> tuple[int, int]:
    earned = sum(w for (_, w), a in zip(CHECKLIST, answers) if a)
    total = sum(w for _, w in CHECKLIST)
    return earned, total


def run_checklist(interactive: bool = True) -> None:
    c.rule("OPSEC · Autoavaliação")
    answers: list[bool] = []
    if interactive:
        for question, _ in CHECKLIST:
            try:
                resp = input(f"  {question} [s/N] ").strip().lower()
            except EOFError:
                resp = "n"
            answers.append(resp in ("s", "sim", "y", "yes"))
    else:
        c.info("Modo não interativo — a listar apenas o checklist:")
        for question, weight in CHECKLIST:
            c.kv(f"[{weight}pts]", question)
        return

    earned, total = self_assessment(answers)
    pct = round(100 * earned / total)
    c.rule("Resultado")
    c.kv("Pontuação", f"{earned}/{total} ({pct}%)")
    if pct >= 80:
        c.ok("Postura OPSEC forte.")
    elif pct >= 50:
        c.warn("Postura OPSEC razoável — fecha as lacunas marcadas com 'não'.")
    else:
        c.err("Postura OPSEC frágil — prioriza MFA, isolamento e resposta a incidentes.")


def run_attribution_guide() -> None:
    c.rule("OPSEC · Atribuição Gerida para Investigação OSINT")
    for i, item in enumerate(MANAGED_ATTRIBUTION, 1):
        c.kv(f"{i:>2}.", item)
