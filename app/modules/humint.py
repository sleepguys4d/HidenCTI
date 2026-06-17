"""
Module: HUMINT — Case & Source Management.

Framing: HUMINT here is CASE MANAGEMENT — structured, auditable recording of
information obtained from people WITH CONSENT/AUTHORIZATION (interviews, field
notes, documentary evidence), with chain of custody.

It is NOT operational social engineering, target approach profiling, or person
location. Every source requires explicit consent confirmation.
"""

from __future__ import annotations
from typing import Any

from ..core.models import Entity, EntityType, Investigation


def add_source(inv: Investigation, *, codename: str, reliability: str = "C",
               consent: bool, context: str = "") -> dict[str, Any]:
    """
    Register a human source.
      reliability: NATO-style A-F scale (A=reliable ... F=cannot be judged).
      consent: MUST be True — without consent/authorization nothing is recorded.
    """
    if not consent:
        return {"error": "Blocked: source consent/authorization is mandatory."}
    ent = inv.upsert_entity(Entity(
        type=EntityType.source, label=codename,
        attrs={"reliability": reliability, "consent": True,
               "context": context, "kind": "humint_source"}))
    inv.log("humint", "add_source",
            f"Source '{codename}' registered (reliability {reliability}, consent confirmed).",
            entity_ids=[ent.id])
    return {"id": ent.id, "codename": codename, "reliability": reliability}


def add_note(inv: Investigation, *, source_codename: str, title: str, content: str,
             credibility: str = "3") -> dict[str, Any]:
    """
    Field/interview note linked to a source.
      credibility: 1 (confirmed) ... 6 (cannot be judged).
    """
    src = next((e for e in inv.entities
                if e.type == EntityType.source and e.label == source_codename), None)
    note = inv.upsert_entity(Entity(
        type=EntityType.case_note, label=title,
        attrs={"content": content, "credibility": credibility,
               "source": source_codename}))
    if src:
        inv.link(src, note, "reported")
    inv.log("humint", "add_note", f"Note '{title}' (credibility {credibility}) from '{source_codename}'.",
            entity_ids=[note.id])
    return {"id": note.id, "title": title}


def add_document(inv: Investigation, *, title: str, sha256: str = "",
                 origin: str = "", classification: str = "internal") -> dict[str, Any]:
    """Documentary evidence with hash for chain of custody."""
    doc = inv.upsert_entity(Entity(
        type=EntityType.document, label=title,
        attrs={"sha256": sha256, "origin": origin, "classification": classification}))
    inv.log("humint", "add_document",
            f"Document '{title}' registered (hash {sha256[:12] or 'n/a'}…).",
            entity_ids=[doc.id])
    return {"id": doc.id, "title": title, "sha256": sha256}


def assess_summary(inv: Investigation) -> dict[str, Any]:
    sources = [e for e in inv.entities if e.type == EntityType.source
               and e.attrs.get("kind") == "humint_source"]
    notes = [e for e in inv.entities if e.type == EntityType.case_note]
    docs = [e for e in inv.entities if e.type == EntityType.document]
    return {
        "sources": len(sources), "notes": len(notes), "documents": len(docs),
        "reliability_breakdown": _count(sources, "reliability"),
    }


def _count(items, key: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        v = str(it.attrs.get(key, "?"))
        out[v] = out.get(v, 0) + 1
    return out
