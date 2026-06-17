"""Persistence layer — one JSON document per investigation, process-locked."""

from __future__ import annotations
import json
import threading
from pathlib import Path
from typing import Optional

from .models import Investigation

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()


def _path(inv_id: str) -> Path:
    return DATA_DIR / f"{inv_id}.json"


def save(inv: Investigation) -> None:
    with _lock:
        _path(inv.id).write_text(inv.model_dump_json(indent=2), encoding="utf-8")


def load(inv_id: str) -> Optional[Investigation]:
    p = _path(inv_id)
    if not p.is_file():
        return None
    return Investigation.model_validate_json(p.read_text(encoding="utf-8"))


def delete(inv_id: str) -> bool:
    p = _path(inv_id)
    if p.is_file():
        p.unlink()
        return True
    return False


def list_all() -> list[dict]:
    out = []
    for p in sorted(DATA_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append({
                "id": d["id"], "name": d["name"], "analyst": d.get("analyst"),
                "authorized": d.get("authorized", False),
                "updated": d.get("updated"), "created": d.get("created"),
                "entities": len(d.get("entities", [])),
                "relations": len(d.get("relations", [])),
                "events": len(d.get("events", [])),
            })
        except Exception:
            continue
    return out
