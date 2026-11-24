"""Bounded, in-memory audit trail for blocked guardrail events."""

from __future__ import annotations

from collections import deque


class AuditLog:
    def __init__(self, max_events: int = 200) -> None:
        if max_events < 1:
            raise ValueError("max_events must be >= 1")
        self.max_events = max_events
        self._events: deque[dict] = deque(maxlen=max_events)

    def record(
        self, tenant: str, layer: str, action: str, detail: str | None = None
    ) -> None:
        self._events.append(
            {
                "tenant": tenant,
                "layer": layer,
                "action": action,
                "detail": None if detail is None else str(detail)[:200],
            }
        )

    def recent(self, limit: int = 50) -> list[dict]:
        if limit < 0:
            raise ValueError("limit must be >= 0")
        events = list(self._events)[-limit:] if limit else []
        return list(reversed(events))
