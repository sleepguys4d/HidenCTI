"""
HIDEN by SEC4DATA — central configuration & product identity.

Everything brand-related lives here. To rename the product, change PRODUCT
below; the whole application (UI, API metadata, PDF report) updates from it.
"""

from __future__ import annotations
import os


# ---- Product identity -------------------------------------------------------
PRODUCT = {
    "name": "HIDEN",
    "vendor": "SEC4DATA",
    "tagline": "Threat Hunting · OSINT · CTI",
    "subtitle": "Uncover what stays hidden",
    "location": "Luanda · Angola",
    "version": "3.0.0",
    "doc_code": "HDN/S4D/INTEL",
    "classification": "AUTHORIZED USE · DEFENSIVE",
    "accent": "#00E5FF",
}


# ---- Operational scope (shown in UI & report) -------------------------------
SCOPE_NOTICE = (
    "Defensive operations on owned assets or with explicit authorization. "
    "Geolocation targets infrastructure (IPs, servers, phishing domains), "
    "not people. No lookup of individuals or third-party breach data."
)


# ---- API keys (optional, via environment) -----------------------------------
def api_keys() -> dict[str, str | None]:
    return {
        "virustotal": os.getenv("VT_API_KEY") or None,
        "abuseipdb": os.getenv("ABUSEIPDB_API_KEY") or None,
        "shodan": os.getenv("SHODAN_API_KEY") or None,
        "hibp": os.getenv("HIBP_API_KEY") or None,
    }


def signature() -> dict:
    """Flat dict consumed by the API, the frontend and the PDF generator."""
    return {
        "platform": PRODUCT["name"],
        "by": PRODUCT["vendor"],
        "tagline": PRODUCT["tagline"],
        "subtitle": PRODUCT["subtitle"],
        "location": PRODUCT["location"],
        "version": PRODUCT["version"],
        "doc_code": PRODUCT["doc_code"],
        "classification": PRODUCT["classification"],
        "accent": PRODUCT["accent"],
        "scope": SCOPE_NOTICE,
    }
