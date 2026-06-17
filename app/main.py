#!/usr/bin/env python3
"""
HIDEN by SEC4DATA — Threat Hunting, OSINT & CTI platform.
FastAPI backend. Orchestrates investigations (graph + map + timeline),
intelligence collectors, HUMINT (case management), and forensic PDF export.

Scope: DEFENSIVE operations on owned assets or with explicit authorization.
No lookup of people or arbitrary individuals' breach data.
"""

from __future__ import annotations
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .core import store
from .core.config import signature
from .core.models import Investigation
from .core.report import generate as generate_pdf
from .modules import collectors, humint

WEB = Path(__file__).resolve().parent / "web"
SIG = signature()

app = FastAPI(title=f"{SIG['platform']} · {SIG['by']}", version=SIG["version"],
              description="Threat Hunting, OSINT & CTI — defensive operations.")
app.mount("/static", StaticFiles(directory=str(WEB / "static")), name="static")


def _get(inv_id: str) -> Investigation:
    inv = store.load(inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found.")
    return inv


def _authz(inv: Investigation):
    if not inv.authorized:
        raise HTTPException(403, "Investigation has no authorized-use confirmation.")


# -------------------------------------------------- pages & meta
@app.get("/", response_class=HTMLResponse)
def index():
    return (WEB / "index.html").read_text(encoding="utf-8")


@app.get("/health")
def health():
    return JSONResponse({"status": "ok", "platform": SIG["platform"], "version": SIG["version"]})


@app.get("/api/meta")
def meta():
    return SIG


# -------------------------------------------------- investigations
class NewInv(BaseModel):
    name: str
    analyst: str = "SEC4DATA"
    authorized: bool = False
    authorization_note: str = ""


@app.get("/api/investigations")
def list_inv():
    return store.list_all()


@app.post("/api/investigations")
def create_inv(body: NewInv):
    inv = Investigation(name=body.name, analyst=body.analyst,
                        authorized=body.authorized,
                        authorization_note=body.authorization_note)
    inv.log("system", "create", f"Investigation '{inv.name}' created.")
    store.save(inv)
    return inv.model_dump()


@app.get("/api/investigations/{inv_id}")
def get_inv(inv_id: str):
    return _get(inv_id).model_dump()


@app.delete("/api/investigations/{inv_id}")
def del_inv(inv_id: str):
    if not store.delete(inv_id):
        raise HTTPException(404, "Not found.")
    return {"deleted": inv_id}


@app.get("/api/investigations/{inv_id}/graph")
def graph(inv_id: str):
    inv = _get(inv_id)
    return {
        "nodes": [e.model_dump() for e in inv.entities],
        "edges": [r.model_dump() for r in inv.relations],
        "geo": inv.geo_points(),
        "events": [e.model_dump() for e in sorted(inv.events, key=lambda x: x.ts)],
    }


# -------------------------------------------------- collectors
class Target(BaseModel):
    target: str
    deep: bool = True
    check_live: bool = True


@app.post("/api/investigations/{inv_id}/collect/domain")
def c_domain(inv_id: str, body: Target):
    inv = _get(inv_id); _authz(inv)
    res = collectors.collect_domain(inv, body.target.strip(), deep=body.deep)
    store.save(inv); return res


@app.post("/api/investigations/{inv_id}/collect/ip")
def c_ip(inv_id: str, body: Target):
    inv = _get(inv_id); _authz(inv)
    res = collectors.collect_ip(inv, body.target.strip())
    store.save(inv); return res


@app.post("/api/investigations/{inv_id}/collect/brand")
def c_brand(inv_id: str, body: Target):
    inv = _get(inv_id); _authz(inv)
    res = collectors.collect_brand(inv, body.target.strip(), check_live=body.check_live)
    store.save(inv); return res


@app.post("/api/investigations/{inv_id}/collect/breach")
def c_breach(inv_id: str, body: Target):
    inv = _get(inv_id); _authz(inv)
    res = collectors.collect_breach(inv, body.target.strip())
    store.save(inv); return res


class CTIBody(BaseModel):
    ioc: str | None = None
    cve: str | None = None


@app.post("/api/investigations/{inv_id}/collect/cti")
def c_cti(inv_id: str, body: CTIBody):
    inv = _get(inv_id); _authz(inv)
    res = collectors.collect_cti(inv, body.ioc, body.cve)
    store.save(inv); return res


@app.post("/api/investigations/{inv_id}/collect/profile")
def c_profile(inv_id: str, body: dict):
    inv = _get(inv_id); _authz(inv)
    res = collectors.collect_profile(inv, body)
    store.save(inv); return res


# -------------------------------------------------- HUMINT
class SourceBody(BaseModel):
    codename: str
    reliability: str = "C"
    consent: bool = False
    context: str = ""


@app.post("/api/investigations/{inv_id}/humint/source")
def h_source(inv_id: str, body: SourceBody):
    inv = _get(inv_id); _authz(inv)
    res = humint.add_source(inv, codename=body.codename, reliability=body.reliability,
                            consent=body.consent, context=body.context)
    if "error" in res:
        raise HTTPException(422, res["error"])
    store.save(inv); return res


class NoteBody(BaseModel):
    source_codename: str
    title: str
    content: str
    credibility: str = "3"


@app.post("/api/investigations/{inv_id}/humint/note")
def h_note(inv_id: str, body: NoteBody):
    inv = _get(inv_id); _authz(inv)
    res = humint.add_note(inv, source_codename=body.source_codename, title=body.title,
                          content=body.content, credibility=body.credibility)
    store.save(inv); return res


@app.get("/api/investigations/{inv_id}/humint/summary")
def h_summary(inv_id: str):
    return humint.assess_summary(_get(inv_id))


# -------------------------------------------------- report
@app.post("/api/investigations/{inv_id}/report")
def report(inv_id: str):
    inv = _get(inv_id)
    path = generate_pdf(inv, SIG, scope="forensic")
    return {"path": Path(path).name}


@app.get("/api/investigations/{inv_id}/report.pdf")
def report_download(inv_id: str):
    inv = _get(inv_id)
    path = generate_pdf(inv, SIG, scope="forensic")
    return FileResponse(path, media_type="application/pdf",
                        filename=f"HIDEN_{inv.name}_{inv.id}.pdf")
