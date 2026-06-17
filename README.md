# HIDEN by SEC4DATA — Threat Hunting · OSINT · CTI

A robust, dockerized, fully graphical platform for **defensive** intelligence
investigations. Each investigation is a **correlation graph** (Maltego-style), an
**infrastructure geolocation map**, and a **forensic timeline**, with **forensic
PDF** export carrying the SEC4DATA identity.

HUD/SOC aesthetic — deep void + electric cyan (`#00E5FF`).

> **Scope.** Defensive operations on **owned assets or with explicit
> authorization**. Geolocation targets **infrastructure** (IPs, servers, phishing
> domains) — **not people**. The platform performs **no** lookup of individuals or
> third-party breach data; the breach module is limited to the organization's own
> domain (verified ownership).

---

## Quick start (Docker)

```bash
cp .env.example .env      # optional: add API keys
docker compose up --build
# → http://localhost:8000
```

## Run without Docker

```bash
pip install -r requirements.txt
python run.py             # → http://127.0.0.1:8000
```

---

## Workspace

Each investigation opens a workspace with three **synchronized** views:

- **Correlation graph** (D3 force-directed): domain / subdomain / IP / lookalike /
  certificate / ASN / CVE / IOC / HUMINT source nodes, draggable, zoomable.
  Threats (lookalikes, malicious IOCs) are linked in red.
- **Infrastructure map** (Leaflet, dark tiles): assets in cyan, threats in red.
  Selecting a node centers its marker on the map.
- **Forensic timeline**: events by module and severity. Clicking an event
  highlights the entity on the graph and map.

Selecting any entity opens the **inspector** with all attributes.

### Modules / collectors

| Collector | What it adds to the graph |
|-----------|----------------------------|
| Domain | DNS, WHOIS, SPF/DMARC, headers, subdomains -> geolocated IPs |
| IP / Infra | rDNS, geo/ASN, reputation (AbuseIPDB), exposure (Shodan) |
| Brand / Phishing | typosquatting lookalikes; live ones become threat nodes |
| Org Breach | own-domain breaches (catalog + exposure via HIBP) |
| CTI . IOC/CVE | reputation (VirusTotal) and CVE severity (NVD) |
| Fake Profile | impersonation heuristic for a profile you provide |
| HUMINT | case management: sources (with consent), notes, evidence |

### HUMINT (case management)

HUMINT here is **case management**: an auditable, chain-of-custody record of
information obtained from people **with consent/authorization** -- sources
(reliability scale A-F), interview notes (credibility 1-6) and documentary
evidence (hash). Each source requires consent confirmation (the backend refuses
without it). No operational social engineering, no person location.

### Forensic report (PDF)

The **PDF report** button produces a document with the SEC4DATA identity:
institutional cover, executive summary, correlation graph, infrastructure map,
threats/IOCs, timeline, and a **per-module chapter**. Header/footer signed on
every page.

---

## Architecture

```
hiden/
|-- Dockerfile . docker-compose.yml . .env.example . run.py . requirements.txt
`-- app/
    |-- main.py              # FastAPI: investigations, collectors, HUMINT, PDF
    |-- core/
    |   |-- config.py        # product identity & settings (rename here)
    |   |-- models.py        # Investigation = entities + relations + events
    |   |-- store.py         # persistence (one JSON per investigation)
    |   `-- report.py        # forensic PDF (ReportLab + matplotlib + networkx)
    |-- modules/
    |   |-- collectors.py    # run intelligence, write into the graph
    |   `-- humint.py        # case/source management (consent required)
    |-- intel/               # intelligence toolkit (domain/ip/cti/brand/profile/breach)
    `-- web/
        |-- index.html       # HUD/SOC console
        `-- static/
            |-- styles.css   # design system
            `-- app.js       # graph (D3) + map (Leaflet) + timeline, synced
```

Persistence on Docker volumes (`hiden_data`, `hiden_reports`). No external DB.

## API surface (selected)

```
GET    /health                                  liveness probe
GET    /api/meta                                product signature
GET    /api/investigations                      list
POST   /api/investigations                      create (requires authorized=true)
GET    /api/investigations/{id}/graph           nodes + edges + geo + events
POST   /api/investigations/{id}/collect/{mod}   domain|ip|brand|breach|cti|profile
POST   /api/investigations/{id}/humint/source   register source (consent required)
GET    /api/investigations/{id}/report.pdf      forensic PDF
```

Collectors and HUMINT return **403** unless the investigation is marked
authorized; HUMINT source registration returns **422** without consent.

## Optional API keys

`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `HIBP_API_KEY` -- set per
environment (`.env`). The platform runs without them; dependent modules stay
inactive until a key is present.

## Renaming

Product identity lives in `app/core/config.py` (`PRODUCT`). Change it once and the
UI, API metadata and PDF report all follow.

---

(c) SEC4DATA . Luanda . Angola
