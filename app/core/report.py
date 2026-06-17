"""
Forensic Report generator (PDF) — HIDEN by SEC4DATA identity.

Contents: institutional cover, executive summary, correlation graph,
infrastructure distribution map, timeline, threats/IOCs, and a per-module
chapter. Header and footer signed on every page.

Dependencies: reportlab, matplotlib, networkx.
"""

from __future__ import annotations
import datetime as _dt
import io
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Image,
    Table, TableStyle, PageBreak, NextPageTemplate,
)

# --- SEC4DATA palette ---
VOID = colors.HexColor("#05080d")
PANEL = colors.HexColor("#0d1826")
CYAN = colors.HexColor("#00E5FF")
CYAN_DIM = colors.HexColor("#0a8aa0")
INK = colors.HexColor("#c4d3df")
MUTED = colors.HexColor("#62788a")
ALERT = colors.HexColor("#ff3b5c")
WARN = colors.HexColor("#ffb020")
OK = colors.HexColor("#29ffb0")

TYPE_COLOR = {
    "domain": "#00E5FF", "subdomain": "#56c7d6", "ip": "#7ee0c0",
    "lookalike": "#ff3b5c", "certificate": "#b388ff", "asn": "#ffb020",
    "org": "#ffd166", "cve": "#ff7b54", "ioc": "#ff5e7e",
    "source": "#9ad0ff", "case_note": "#8fb3c9", "document": "#c0c9d4",
    "email_domain": "#56c7d6",
}
SEV_COLOR = {"info": MUTED, "low": OK, "medium": WARN, "high": ALERT, "critical": ALERT}

REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------- figures
def _graph_png(inv) -> io.BytesIO:
    G = nx.DiGraph()
    idmap = {e.id: e for e in inv.entities}
    for e in inv.entities:
        G.add_node(e.id)
    for r in inv.relations:
        if r.source in idmap and r.target in idmap:
            G.add_edge(r.source, r.target, threat=r.threat)

    fig, ax = plt.subplots(figsize=(9, 6), facecolor="#05080d")
    ax.set_facecolor("#05080d")
    if len(G) == 0:
        ax.text(0.5, 0.5, "No entities", color="#62788a", ha="center")
        ax.axis("off")
    else:
        pos = nx.spring_layout(G, k=0.9 / math.sqrt(max(len(G), 1)), seed=7, iterations=60)
        for u, v, d in G.edges(data=True):
            x = [pos[u][0], pos[v][0]]; y = [pos[u][1], pos[v][1]]
            ax.plot(x, y, color=("#ff3b5c" if d.get("threat") else "#0a8aa0"),
                    lw=1.4 if d.get("threat") else 0.8, alpha=0.8, zorder=1)
        for nid in G.nodes():
            e = idmap[nid]
            col = TYPE_COLOR.get(e.type.value, "#00E5FF")
            size = 380 if e.type.value == "domain" else 200
            ax.scatter(pos[nid][0], pos[nid][1], s=size, c=col,
                       edgecolors="#05080d", linewidths=1.5, zorder=2)
            lbl = e.label if len(e.label) <= 26 else e.label[:24] + "…"
            ax.annotate(lbl, pos[nid], fontsize=6.5, color="#c4d3df",
                        xytext=(0, 9), textcoords="offset points", ha="center", zorder=3)
        ax.axis("off")
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, facecolor="#05080d", bbox_inches="tight")
    plt.close(fig); buf.seek(0)
    return buf


def _map_png(inv) -> io.BytesIO | None:
    pts = inv.geo_points()
    if not pts:
        return None
    fig, ax = plt.subplots(figsize=(9, 4.6), facecolor="#05080d")
    ax.set_facecolor("#04070c")
    for lon in range(-180, 181, 30):
        ax.axvline(lon, color="#0a8aa0", alpha=0.15, lw=0.5)
    for lat in range(-90, 91, 30):
        ax.axhline(lat, color="#0a8aa0", alpha=0.15, lw=0.5)
    for p in pts:
        threat = p["severity"] in ("high", "critical")
        ax.scatter(p["lon"], p["lat"], s=70 if threat else 45,
                   c="#ff3b5c" if threat else "#00E5FF",
                   edgecolors="#05080d", linewidths=1, alpha=0.85, zorder=3)
        ax.annotate(p["label"], (p["lon"], p["lat"]), fontsize=5.5,
                    color="#c4d3df", xytext=(4, 4), textcoords="offset points")
    ax.set_xlim(-180, 180); ax.set_ylim(-90, 90)
    ax.set_xlabel("Longitude", color="#62788a", fontsize=7)
    ax.set_ylabel("Latitude", color="#62788a", fontsize=7)
    ax.tick_params(colors="#62788a", labelsize=6)
    for s in ax.spines.values():
        s.set_color("#0a8aa0"); s.set_alpha(0.4)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, facecolor="#05080d", bbox_inches="tight")
    plt.close(fig); buf.seek(0)
    return buf


# ----------------------------------------------------------- styles
def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("H1x", parent=ss["Heading1"], textColor=CYAN,
                          fontName="Helvetica-Bold", fontSize=15, spaceBefore=10, spaceAfter=6))
    ss.add(ParagraphStyle("Eyebrow", fontName="Helvetica-Bold", fontSize=8,
                          textColor=CYAN_DIM, spaceAfter=2, leading=10))
    ss.add(ParagraphStyle("Body2", parent=ss["BodyText"], textColor=INK,
                          fontSize=9.5, leading=14))
    ss.add(ParagraphStyle("Small", fontName="Helvetica", fontSize=8,
                          textColor=MUTED, leading=11))
    return ss


# ----------------------------------------------------------- eye mark (cover)
def _eye(canvas, cx, cy, s):
    """Draw the HIDEN eye mark centered at (cx, cy), scale s."""
    canvas.saveState()
    canvas.setStrokeColor(CYAN); canvas.setLineWidth(1.6)
    # almond outline (two arcs approximated by bezier via path)
    p = canvas.beginPath()
    p.moveTo(cx - s, cy)
    p.curveTo(cx - s * 0.5, cy + s * 0.8, cx + s * 0.5, cy + s * 0.8, cx + s, cy)
    p.curveTo(cx + s * 0.5, cy - s * 0.8, cx - s * 0.5, cy - s * 0.8, cx - s, cy)
    canvas.drawPath(p, stroke=1, fill=0)
    # iris
    canvas.setFillColor(CYAN)
    canvas.circle(cx, cy, s * 0.34, stroke=0, fill=1)
    canvas.setFillColor(VOID)
    canvas.circle(cx, cy, s * 0.14, stroke=0, fill=1)
    # ticks
    canvas.setStrokeColor(CYAN); canvas.setLineWidth(1.6)
    canvas.line(cx, cy + s * 0.9, cx, cy + s * 1.15)
    canvas.line(cx, cy - s * 0.9, cx, cy - s * 1.15)
    canvas.restoreState()


# ----------------------------------------------------------- page decoration
def _decorate(canvas, doc, sig):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(VOID); canvas.rect(0, 0, w, h, fill=1, stroke=0)
    canvas.setStrokeColor(CYAN); canvas.setLineWidth(0.6)
    canvas.line(18 * mm, h - 18 * mm, w - 18 * mm, h - 18 * mm)
    canvas.setFillColor(CYAN); canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(18 * mm, h - 16 * mm, sig.get("platform", "HIDEN"))
    canvas.setFillColor(MUTED); canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm + 16 * mm, h - 16 * mm, "· SEC4DATA · Security Operations")
    canvas.drawRightString(w - 18 * mm, h - 16 * mm, sig.get("classification", ""))
    canvas.line(18 * mm, 15 * mm, w - 18 * mm, 15 * mm)
    canvas.setFillColor(MUTED); canvas.setFont("Helvetica", 7)
    canvas.drawString(18 * mm, 11 * mm, f"{sig.get('doc_code','HDN/S4D')} · © SEC4DATA · Luanda · Angola")
    canvas.drawRightString(w - 18 * mm, 11 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _cover(canvas, doc, sig, inv):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(VOID); canvas.rect(0, 0, w, h, fill=1, stroke=0)
    canvas.setStrokeColor(CYAN); canvas.setLineWidth(0.3); canvas.setStrokeAlpha(0.08)
    for x in range(0, int(w), 28):
        canvas.line(x, 0, x, h)
    for y in range(0, int(h), 28):
        canvas.line(0, y, w, y)
    canvas.setStrokeAlpha(1)
    canvas.setStrokeColor(CYAN); canvas.setLineWidth(1.2)
    m = 16 * mm; L = 12 * mm
    for (cx, cy, dx, dy) in [(m, h - m, 1, -1), (w - m, h - m, -1, -1),
                             (m, m, 1, 1), (w - m, m, -1, 1)]:
        canvas.line(cx, cy, cx + dx * L, cy)
        canvas.line(cx, cy, cx, cy + dy * L)

    # eye mark + wordmark
    _eye(canvas, 30 * mm, h - 63 * mm, 9 * mm)
    canvas.setFillColor(colors.white); canvas.setFont("Helvetica-Bold", 40)
    canvas.drawString(42 * mm, h - 70 * mm, "HI")
    wpx = canvas.stringWidth("HI", "Helvetica-Bold", 40)
    canvas.setFillColor(CYAN)
    canvas.drawString(42 * mm + wpx, h - 70 * mm, "DEN")
    canvas.setFillColor(MUTED); canvas.setFont("Helvetica", 11)
    canvas.drawString(42 * mm, h - 78 * mm, f"by SEC4DATA · {sig.get('tagline','')}")

    canvas.setFillColor(CYAN_DIM); canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(24 * mm, h - 110 * mm, "FORENSIC INVESTIGATION REPORT")
    canvas.setFillColor(colors.white); canvas.setFont("Helvetica-Bold", 20)
    canvas.drawString(24 * mm, h - 120 * mm, (inv.name or "Investigation")[:42])
    canvas.setFillColor(INK); canvas.setFont("Helvetica", 10)
    meta = [
        f"Analyst: {inv.analyst}",
        f"Reference: {sig.get('doc_code','HDN/S4D')}-{inv.id.upper()}",
        f"Date: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Entities: {len(inv.entities)}  ·  Relations: {len(inv.relations)}  ·  Events: {len(inv.events)}",
        f"Classification: {sig.get('classification','')}",
    ]
    yy = h - 135 * mm
    for line in meta:
        canvas.drawString(24 * mm, yy, line); yy -= 7 * mm

    canvas.setFillColor(CYAN); canvas.rect(24 * mm, 30 * mm, w - 48 * mm, 14 * mm, fill=1, stroke=0)
    canvas.setFillColor(VOID); canvas.setFont("Helvetica-Bold", 8.5)
    canvas.drawString(28 * mm, 35 * mm,
                      "AUTHORIZED USE · DEFENSIVE — infrastructure geolocation, not people.")
    canvas.restoreState()


# ----------------------------------------------------------- build
def generate(inv, sig: dict, scope: str = "forensic") -> str:
    ss = _styles()
    out_path = REPORTS_DIR / f"HIDEN_{inv.id}.pdf"

    doc = BaseDocTemplate(str(out_path), pagesize=A4,
                          leftMargin=18 * mm, rightMargin=18 * mm,
                          topMargin=24 * mm, bottomMargin=20 * mm)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[frame], onPage=lambda c, d: _cover(c, d, sig, inv)),
        PageTemplate(id="content", frames=[frame], onPage=lambda c, d: _decorate(c, d, sig)),
    ])

    from ..core.models import Severity
    story: list = [NextPageTemplate("content"), PageBreak()]

    story.append(Paragraph("EXECUTIVE SUMMARY", ss["Eyebrow"]))
    story.append(Paragraph(inv.name or "Investigation", ss["H1x"]))
    by_type: dict[str, int] = {}
    for e in inv.entities:
        by_type[e.type.value] = by_type.get(e.type.value, 0) + 1
    threats = [e for e in inv.entities if e.severity in (Severity.high, Severity.critical)]
    story.append(Paragraph(
        f"This investigation consolidates <b>{len(inv.entities)}</b> entities and "
        f"<b>{len(inv.relations)}</b> relations across <b>{len(inv.events)}</b> recorded "
        f"events. <b>{len(threats)}</b> entities were flagged at high/critical risk.",
        ss["Body2"]))
    if inv.authorization_note:
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>Scope/authorization:</b> {inv.authorization_note}", ss["Small"]))

    comp_rows = [["Entity type", "Count"]] + [[k, str(v)] for k, v in sorted(by_type.items())]
    t = Table(comp_rows, colWidths=[110 * mm, 30 * mm]); t.setStyle(_tbl_style())
    story.append(Spacer(1, 8)); story.append(t)

    story.append(Paragraph("CORRELATION GRAPH", ss["Eyebrow"]))
    story.append(Paragraph("Linked infrastructure and entities", ss["H1x"]))
    story.append(Image(_graph_png(inv), width=doc.width, height=doc.width * 0.66))
    story.append(Paragraph("Cyan = assets · red = threats (lookalikes / IOCs).", ss["Small"]))
    story.append(PageBreak())

    mp = _map_png(inv)
    if mp:
        story.append(Paragraph("INFRASTRUCTURE MAP", ss["Eyebrow"]))
        story.append(Paragraph("Geographic distribution of hosts", ss["H1x"]))
        story.append(Image(mp, width=doc.width, height=doc.width * 0.51))
        story.append(Paragraph("Geolocation of infrastructure (IPs/servers), not people.", ss["Small"]))
        story.append(PageBreak())

    if threats:
        story.append(Paragraph("THREATS & IOCs", ss["Eyebrow"]))
        story.append(Paragraph("High/critical risk entities", ss["H1x"]))
        rows = [["Entity", "Type", "Severity", "Detail"]]
        for e in threats:
            detail = e.attrs.get("verdict") or e.attrs.get("isp") or e.attrs.get("severity") or ""
            rows.append([e.label[:38], e.type.value, e.severity.value, str(detail)[:30]])
        t = Table(rows, colWidths=[55 * mm, 28 * mm, 26 * mm, 40 * mm]); t.setStyle(_tbl_style(threat=True))
        story.append(t); story.append(PageBreak())

    story.append(Paragraph("INVESTIGATION TIMELINE", ss["Eyebrow"]))
    story.append(Paragraph("Sequence of events", ss["H1x"]))
    ev_rows = [["Time", "Module", "Sev.", "Event"]]
    for e in sorted(inv.events, key=lambda x: x.ts):
        ts = _dt.datetime.fromtimestamp(e.ts).strftime("%m-%d %H:%M")
        ev_rows.append([ts, e.module, e.severity.value, e.summary[:64]])
    t = Table(ev_rows, colWidths=[22 * mm, 24 * mm, 16 * mm, 90 * mm]); t.setStyle(_tbl_style())
    story.append(t)

    if scope == "forensic":
        story.append(PageBreak())
        story.append(Paragraph("ANNEXES · PER-MODULE DETAIL", ss["Eyebrow"]))
        for mod in sorted({e.module for e in inv.events}):
            evs = [e for e in inv.events if e.module == mod]
            story.append(Paragraph(mod.upper(), ss["H1x"]))
            for e in evs:
                story.append(Paragraph(
                    f"[{_dt.datetime.fromtimestamp(e.ts).strftime('%H:%M')}] "
                    f"<b>{e.action}</b> — {e.summary}", ss["Body2"]))
            story.append(Spacer(1, 6))

    doc.build(story)
    return str(out_path)


def _tbl_style(threat: bool = False) -> TableStyle:
    head = ALERT if threat else CYAN
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), head),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#070d15"), colors.HexColor("#0a121c")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#16384a")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ])
