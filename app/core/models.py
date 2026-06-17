"""
HIDEN by SEC4DATA — domain models.

An INVESTIGATION aggregates:
  - entities (graph nodes): domain, subdomain, IP, certificate, lookalike,
    ASN/org, and — for HUMINT — sources and case assets;
  - relations (graph edges) between entities;
  - events (timeline) with timestamps;
  - geo points (map) — geolocation of INFRASTRUCTURE, not people.
"""

from __future__ import annotations
import time
import uuid
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> float:
    return time.time()


class EntityType(str, Enum):
    domain = "domain"
    subdomain = "subdomain"
    ip = "ip"
    certificate = "certificate"
    lookalike = "lookalike"
    asn = "asn"
    org = "org"
    email_domain = "email_domain"
    cve = "cve"
    ioc = "ioc"
    # HUMINT (case management, with consent/authorization)
    source = "source"          # registered human source
    case_note = "case_note"    # field note / interview
    document = "document"      # documentary evidence


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Entity(BaseModel):
    id: str = Field(default_factory=_id)
    type: EntityType
    label: str
    attrs: dict[str, Any] = Field(default_factory=dict)
    severity: Severity = Severity.info
    lat: Optional[float] = None
    lon: Optional[float] = None
    created: float = Field(default_factory=_now)


class Relation(BaseModel):
    id: str = Field(default_factory=_id)
    source: str            # Entity.id
    target: str            # Entity.id
    kind: str = "linked"   # resolves_to, hosts, issued_for, impersonates, reports_to...
    threat: bool = False
    attrs: dict[str, Any] = Field(default_factory=dict)


class Event(BaseModel):
    id: str = Field(default_factory=_id)
    ts: float = Field(default_factory=_now)
    module: str
    action: str
    summary: str
    severity: Severity = Severity.info
    entity_ids: list[str] = Field(default_factory=list)


class Investigation(BaseModel):
    id: str = Field(default_factory=_id)
    name: str
    analyst: str = "SEC4DATA"
    authorized: bool = False           # authorized-use confirmation
    authorization_note: str = ""       # legal basis / engagement scope
    created: float = Field(default_factory=_now)
    updated: float = Field(default_factory=_now)
    entities: list[Entity] = Field(default_factory=list)
    relations: list[Relation] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)

    # ---- helpers ----
    def upsert_entity(self, ent: Entity) -> Entity:
        for e in self.entities:
            if e.type == ent.type and e.label == ent.label:
                e.attrs.update(ent.attrs)
                if ent.lat is not None:
                    e.lat, e.lon = ent.lat, ent.lon
                if _sev_rank(ent.severity) > _sev_rank(e.severity):
                    e.severity = ent.severity
                return e
        self.entities.append(ent)
        return ent

    def link(self, src: Entity, tgt: Entity, kind: str, threat: bool = False) -> None:
        for r in self.relations:
            if r.source == src.id and r.target == tgt.id and r.kind == kind:
                return
        self.relations.append(Relation(source=src.id, target=tgt.id, kind=kind, threat=threat))

    def log(self, module: str, action: str, summary: str,
            severity: Severity = Severity.info, entity_ids: list[str] | None = None) -> None:
        self.events.append(Event(module=module, action=action, summary=summary,
                                 severity=severity, entity_ids=entity_ids or []))
        self.updated = _now()

    def geo_points(self) -> list[dict]:
        pts = []
        for e in self.entities:
            if e.lat is not None and e.lon is not None:
                pts.append({
                    "id": e.id, "lat": e.lat, "lon": e.lon, "label": e.label,
                    "type": e.type.value, "severity": e.severity.value,
                    "city": e.attrs.get("city"), "country": e.attrs.get("country"),
                    "isp": e.attrs.get("isp"), "asn": e.attrs.get("asn"),
                })
        return pts


def _sev_rank(s: Severity) -> int:
    return ["info", "low", "medium", "high", "critical"].index(s.value)
