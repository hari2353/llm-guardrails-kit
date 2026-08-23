from __future__ import annotations

import os

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .inspectors import detect_injection, scrub_pii
from .budget import TokenBudget, estimate_tokens


class GuardrailConfig:
    def __init__(self) -> None:
        self.injection_threshold = float(os.getenv("GUARD_INJECTION_THRESHOLD", "0.35"))
        self.per_request_tokens = int(os.getenv("GUARD_PER_REQUEST_TOKENS", "8000"))
        self.scrub_pii = os.getenv("GUARD_SCRUB_PII", "1") == "1"


def install_guardrails(app, config: GuardrailConfig | None = None) -> None:
    """Attach input-guarding middleware to an existing FastAPI app."""
    cfg = config or GuardrailConfig()
    budget = TokenBudget(per_request=cfg.per_request_tokens)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method != "POST":
            return await call_next(request)
        body = await request.body()
        if not body:
            return await call_next(request)
        import json

        try:
            payload = json.loads(body)
        except Exception:
            return JSONResponse(status_code=400, content={"detail": "invalid json"})
        texts: list[str] = []

        def collect(value) -> None:
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, dict):
                for v in value.values():
                    collect(v)
            elif isinstance(value, list):
                for v in value:
                    collect(v)

        collect(payload)
        joined = "\n".join(texts)
        verdict = detect_injection(joined)
        if verdict["score"] >= cfg.injection_threshold:
            return JSONResponse(
                status_code=422,
                content={"detail": "input blocked by guardrails", "matches": [m["rule"] for m in verdict["matches"]]},
            )
        est = estimate_tokens(joined)
        budget_verdict = budget.check(est)
        if not budget_verdict["allowed"]:
            return JSONResponse(status_code=429, content={"detail": budget_verdict["reason"]})
        if cfg.scrub_pii and texts:
            scrubbed = scrub_pii(joined)
            if scrubbed["findings"]:
                return JSONResponse(
                    status_code=422,
                    content={"detail": "pii detected; resubmit sanitized input", "findings": scrubbed["findings"]},
                )
        return await call_next(request)
