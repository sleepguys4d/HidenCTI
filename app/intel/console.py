"""
SEC4INTEL — Camada de apresentação na consola.

Usa 'rich' se disponível (recomendado) e degrada graciosamente para ANSI puro.
Estética: espaço-preto + ciano elétrico (#00E5FF), alinhada com a identidade SEC4DATA.
"""

from __future__ import annotations
from typing import Iterable, Sequence

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    _RICH = True
    _console = Console()
except Exception:  # pragma: no cover
    _RICH = False
    _console = None

CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

BANNER = r"""
   ███████ ███████  ██████ ██   ██ ██ ███    ██ ████████ ███████ ██
   ██      ██      ██      ██   ██ ██ ████   ██    ██    ██      ██
   ███████ █████   ██      ███████ ██ ██ ██  ██    ██    █████   ██
        ██ ██      ██           ██ ██ ██  ██ ██    ██    ██      ██
   ███████ ███████  ██████      ██ ██ ██   ████    ██    ███████ ███████
"""


def banner(version: str) -> None:
    if _RICH:
        _console.print(Text(BANNER, style="bold cyan"))
        _console.print(
            Panel.fit(
                "[bold cyan]SEC4INTEL[/]  ·  CTI & OSINT Toolkit\n"
                f"[dim]SEC4DATA · Luanda · Angola  ·  v{version}[/]",
                border_style="cyan",
            )
        )
    else:
        print(CYAN + BANNER + RESET)
        print(f"{BOLD}{CYAN}SEC4INTEL{RESET}  ·  CTI & OSINT Toolkit  ·  v{version}\n")


def rule(title: str) -> None:
    if _RICH:
        _console.rule(f"[bold cyan]{title}")
    else:
        print(f"\n{CYAN}{'─' * 8} {title} {'─' * 8}{RESET}")


def info(msg: str) -> None:
    _print(f"[cyan][*][/] {msg}", f"{CYAN}[*]{RESET} {msg}")


def ok(msg: str) -> None:
    _print(f"[green][+][/] {msg}", f"{GREEN}[+]{RESET} {msg}")


def warn(msg: str) -> None:
    _print(f"[yellow][!][/] {msg}", f"{YELLOW}[!]{RESET} {msg}")


def err(msg: str) -> None:
    _print(f"[red][x][/] {msg}", f"{RED}[x]{RESET} {msg}")


def kv(key: str, value: object) -> None:
    _print(f"  [dim]{key:<22}[/] {value}", f"  {DIM}{key:<22}{RESET} {value}")


def table(title: str, columns: Sequence[str], rows: Iterable[Sequence[object]]) -> None:
    rows = list(rows)
    if _RICH:
        t = Table(title=title, title_style="bold cyan", border_style="cyan", header_style="bold cyan")
        for c in columns:
            t.add_column(str(c))
        for r in rows:
            t.add_row(*[str(x) for x in r])
        _console.print(t)
    else:
        print(f"\n{BOLD}{CYAN}{title}{RESET}")
        print("  " + " | ".join(str(c) for c in columns))
        print("  " + "-" * 60)
        for r in rows:
            print("  " + " | ".join(str(x) for x in r))


def _print(rich_markup: str, plain: str) -> None:
    if _RICH:
        _console.print(rich_markup)
    else:
        print(plain)
