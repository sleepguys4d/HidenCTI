"""Wrapper HTTP fino com rate limiting cooperativo e tratamento de erros."""

from __future__ import annotations
import time
from typing import Any, Optional

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

USER_AGENT = "SEC4INTEL/1.0 (+https://sec4data.example) CTI-OSINT-Toolkit"
_last_call: dict[str, float] = {}


def _throttle(host: str, min_interval: float) -> None:
    now = time.monotonic()
    last = _last_call.get(host, 0.0)
    wait = min_interval - (now - last)
    if wait > 0:
        time.sleep(wait)
    _last_call[host] = time.monotonic()


def get_json(
    url: str,
    *,
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    min_interval: float = 1.0,
    timeout: int = 20,
) -> Any:
    if requests is None:
        raise RuntimeError("O pacote 'requests' não está instalado (pip install requests).")
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        h.update(headers)
    host = url.split("/")[2] if "://" in url else url
    _throttle(host, min_interval)
    resp = requests.get(url, headers=h, params=params, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def get_text(
    url: str,
    *,
    headers: Optional[dict] = None,
    min_interval: float = 1.0,
    timeout: int = 20,
) -> str:
    if requests is None:
        raise RuntimeError("O pacote 'requests' não está instalado (pip install requests).")
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    host = url.split("/")[2] if "://" in url else url
    _throttle(host, min_interval)
    resp = requests.get(url, headers=h, timeout=timeout)
    resp.raise_for_status()
    return resp.text
