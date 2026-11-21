"""Stable, per-tenant PII pseudonyms (LinkedIn portfolio project 10).

Deterministic UUIDv5 digests keep the same value linkable inside one tenant
without storing a reversible map or ever returning the raw value.
"""
from __future__ import annotations

import uuid

from .inspectors import REDACTIONS


class Pseudonymizer:
    def __init__(self, tenant_salt: str) -> None:
        self.tenant_salt = tenant_salt

    def mask(self, value: str, kind: str) -> str:
        digest = uuid.uuid5(
            uuid.NAMESPACE_URL, f"{self.tenant_salt}|{kind}|{value}"
        ).hex
        return f"{kind.upper()}_{digest[:12]}"


def pseudonymize_pii(text: str, tenant: str) -> dict:
    """Replace every detected PII value with its tenant-scoped pseudonym.

    Returns kinds only (no raw values, no reverse map)."""
    pseudonymizer = Pseudonymizer(tenant)
    findings: list[str] = []
    out = text
    for kind, pattern in REDACTIONS:
        def _sub(match, _kind=kind):
            findings.append(_kind)
            return pseudonymizer.mask(match.group(0), _kind)

        out = pattern.sub(_sub, out)
    return {"text": out, "findings": findings}
