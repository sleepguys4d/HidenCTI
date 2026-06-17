"""
Module: Fake Profile / Impersonation Detection

Scores observable signals of ONE specific profile (suspected of impersonating
your brand, an executive or a PEP) and returns a fake/impersonation risk score
with justification.

Framing: DEFENSIVE impersonation detection aimed at the organization or its
people. The tool evaluates signals YOU provide from public observation of the
profile — it does not collect or aggregate data on arbitrary individuals.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ProfileSignals:
    handle: str
    account_age_days: Optional[int] = None        # account age in days
    followers: Optional[int] = None
    following: Optional[int] = None
    post_count: Optional[int] = None
    has_profile_photo: Optional[bool] = None
    photo_is_reused: Optional[bool] = None         # imagem encontrada noutro lado (reverse image)
    bio_has_external_links: Optional[bool] = None
    handle_resembles_brand: Optional[bool] = None  # ex.: sec4data_oficial vs sec4data
    name_matches_known_person: Optional[bool] = None
    verified: Optional[bool] = None
    default_username_pattern: Optional[bool] = None  # ex.: nome1928473
    posts_only_promotional: Optional[bool] = None


@dataclass
class Finding:
    weight: int
    reason: str


def analyze(s: ProfileSignals) -> tuple[int, str, list[Finding]]:
    findings: list[Finding] = []

    def add(cond: Optional[bool], weight: int, reason: str) -> None:
        if cond:
            findings.append(Finding(weight, reason))

    add(s.account_age_days is not None and s.account_age_days < 30, 20,
        "Very recent account (< 30 days) — typical of throwaway accounts.")
    add(s.account_age_days is not None and 30 <= s.account_age_days < 180, 8,
        "Relatively new account (< 6 months).")
    add(s.photo_is_reused, 25,
        "Profile photo reused/found elsewhere (possible stolen image).")
    add(s.has_profile_photo is False, 12,
        "No profile photo.")
    add(s.handle_resembles_brand, 22,
        "Handle mimics the brand (variation/added 'official', underscores, etc.).")
    add(s.default_username_pattern, 10,
        "Auto-generated username pattern (name + random digits).")
    add(s.following is not None and s.followers is not None
        and s.following > 0 and s.followers / max(s.following, 1) < 0.05, 12,
        "Very low followers/following ratio (follows many, few follow back).")
    add(s.post_count is not None and s.post_count <= 3, 8,
        "Almost no posts.")
    add(s.posts_only_promotional, 10,
        "Promotional/links content only — scam pattern.")
    add(s.bio_has_external_links and s.account_age_days is not None
        and s.account_age_days < 60, 10,
        "Bio with external links on a recent account.")
    add(s.name_matches_known_person and s.verified is False, 18,
        "Uses a known person's name without verification.")

    # Mitigators
    if s.verified:
        findings.append(Finding(-25, "Platform-verified account."))
    if s.account_age_days is not None and s.account_age_days > 1095:
        findings.append(Finding(-15, "Account older than 3 years."))

    score = max(0, min(100, sum(f.weight for f in findings)))
    if score >= 65:
        verdict = "HIGH risk of fake profile / impersonation"
    elif score >= 35:
        verdict = "MODERATE risk — investigate manually"
    else:
        verdict = "LOW risk based on the provided signals"
    return score, verdict, findings


def run(s: ProfileSignals) -> None:
    from .. import console as c
    c.rule(f"Profile Analysis · {s.handle}")
    score, verdict, findings = analyze(s)
    c.kv("Risk score", f"{score}/100")
    c.kv("Verdict", verdict)
    c.rule("Detected signals")
    if not findings:
        c.info("No risk signals from the provided data.")
    for f in sorted(findings, key=lambda x: -x.weight):
        sign = "+" if f.weight >= 0 else ""
        c.kv(f"{sign}{f.weight}", f.reason)
    c.warn("Decision-support heuristic. Always confirm before reporting/acting.")
