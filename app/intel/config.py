"""
SEC4INTEL — Configuração e gestão de credenciais.

As chaves de API são lidas (por ordem de prioridade) de:
  1. Variáveis de ambiente
  2. Ficheiro ~/.sec4intel/config.json
  3. Ficheiro ./sec4intel.json no diretório atual

NUNCA escrevas chaves diretamente no código nem as comites para git.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional

# Mapeamento: nome lógico -> variável de ambiente
ENV_KEYS = {
    "virustotal": "VT_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "hibp": "HIBP_API_KEY",          # usado APENAS para domínios cuja posse foi verificada na HIBP
    "ipinfo": "IPINFO_TOKEN",
}

DEFAULT_PATHS = [
    Path.home() / ".sec4intel" / "config.json",
    Path.cwd() / "sec4intel.json",
]


class Config:
    def __init__(self) -> None:
        self._file_cfg: dict = {}
        for p in DEFAULT_PATHS:
            if p.is_file():
                try:
                    self._file_cfg.update(json.loads(p.read_text(encoding="utf-8")))
                except Exception:
                    pass

    def get_key(self, name: str) -> Optional[str]:
        """Devolve a chave de API para um serviço, ou None se não estiver definida."""
        env_var = ENV_KEYS.get(name)
        if env_var and os.environ.get(env_var):
            return os.environ[env_var].strip()
        val = self._file_cfg.get(name)
        return val.strip() if isinstance(val, str) and val.strip() else None

    def require(self, name: str) -> str:
        key = self.get_key(name)
        if not key:
            env = ENV_KEYS.get(name, name.upper() + "_API_KEY")
            raise RuntimeError(
                f"Falta a chave de API '{name}'. "
                f"Define a variável de ambiente {env} ou adiciona-a ao config.json."
            )
        return key


config = Config()
