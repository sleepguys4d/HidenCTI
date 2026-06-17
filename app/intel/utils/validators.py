"""Validadores e deteção de tipo de IOC."""

from __future__ import annotations
import ipaddress
import re

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.strip()))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


def is_hash(value: str) -> bool:
    v = value.strip()
    return bool(_MD5_RE.match(v) or _SHA1_RE.match(v) or _SHA256_RE.match(v))


def detect_ioc(value: str) -> str:
    """Devolve: 'ip' | 'domain' | 'email' | 'hash' | 'unknown'."""
    v = value.strip()
    if is_ip(v):
        return "ip"
    if is_hash(v):
        return "hash"
    if is_email(v):
        return "email"
    if is_domain(v):
        return "domain"
    return "unknown"
