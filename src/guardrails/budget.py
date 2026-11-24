from __future__ import annotations

import json
import os
import time


def estimate_tokens(text: str) -> int:
    """Cheap heuristic (~4 chars/token); tiktoken used when available."""
    try:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return max(len(text) // 4, 1)


class TokenBudget:
    def __init__(self, per_request: int = 8000, per_minute: int = 60000) -> None:
        self.per_request = per_request
        self.per_minute = per_minute
        self._window: list[tuple[float, int]] = []

    def check(self, estimated_tokens: int) -> dict:
        now = time.time()
        self._window = [(ts, tok) for ts, tok in self._window if now - ts < 60]
        allowed = True
        reason = ""
        if estimated_tokens > self.per_request:
            allowed, reason = False, "request budget exceeded"
        elif sum(tok for _, tok in self._window) + estimated_tokens > self.per_minute:
            allowed, reason = False, "minute budget exceeded"
        if allowed:
            self._window.append((now, estimated_tokens))
        return {"allowed": allowed, "reason": reason}


def validate_json_output(raw: str, required_keys: list[str]) -> dict:
    try:
        data = json.loads(
            raw.strip().removeprefix("```json").removesuffix("```").strip()
        )
    except Exception as exc:
        return {"valid": False, "error": f"invalid json: {exc}"}
    missing = [key for key in required_keys if key not in data]
    if missing:
        return {
            "valid": False,
            "error": f"missing keys: {missing}",
            "retry_hint": f"Include {missing}. Reply JSON only.",
        }
    return {"valid": True, "data": data}
