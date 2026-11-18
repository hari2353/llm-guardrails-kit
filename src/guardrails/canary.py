"""Canary tripwires (Lakera-style): mint an unguessable token per tenant,
plant it in that tenant's system prompt, and register it here. If the
token ever arrives as INPUT, the tenant's prompt has leaked into the
wild — block and name the tenant, never echoing the canary itself."""
from __future__ import annotations

import secrets


class CanaryRegistry:
    """O(1) canary → tenant lookup; mints are unguessable."""

    def __init__(self) -> None:
        self._canaries: dict[str, str] = {}

    def mint(self, tenant: str) -> str:
        canary = f"CANARY-{secrets.token_hex(12)}"
        self._canaries[canary] = tenant
        return canary

    def owner(self, canary: str) -> str | None:
        return self._canaries.get(canary)

    def scan(self, text: str) -> str | None:
        """The tenant whose canary appears in ``text``, or None."""
        for canary, tenant in self._canaries.items():
            if canary in text:
                return tenant
        return None
