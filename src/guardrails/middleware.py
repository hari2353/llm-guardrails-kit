from __future__ import annotations

import os

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from .canary import CanaryRegistry
from .inspectors import detect_injection, scrub_pii
from .budget import TokenBudget, estimate_tokens
from .audit import AuditLog


class GuardrailConfig:
    def __init__(self) -> None:
        self.injection_threshold = float(os.getenv("GUARD_INJECTION_THRESHOLD", "0.35"))
        self.per_request_tokens = int(os.getenv("GUARD_PER_REQUEST_TOKENS", "8000"))
        self.scrub_pii = os.getenv("GUARD_SCRUB_PII", "1") == "1"


def install_guardrails(
    app,
    config: GuardrailConfig | None = None,
    canaries: CanaryRegistry | None = None,
    audit: AuditLog | None = None,
) -> None:
    """Attach input-guarding middleware to an existing FastAPI app.

    ``canaries`` (optional): a registry of planted system-prompt canaries.
    Any canary arriving as input means that tenant's prompt leaked — the
    request is blocked and the tenant named, the canary value never echoed.
    ``audit`` (optional): bounded log of blocked events keyed by tenant."""
    cfg = config or GuardrailConfig()
    budget = TokenBudget(per_request=cfg.per_request_tokens)

    def note(
        request: Request, layer: str, action: str, detail: str | None = None
    ) -> None:
        if audit is not None:
            audit.record(
                request.headers.get("X-Tenant-Id", "unknown"), layer, action, detail
            )

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
        if canaries is not None:
            leaked_tenant = canaries.scan(joined)
            if leaked_tenant is not None:
                note(request, "canary", "blocked", f"leaked_tenant={leaked_tenant}")
                return JSONResponse(
                    status_code=422,
                    content={
                        "detail": "canary_detected: a planted system-prompt canary arrived as input",
                        "matches": ["canary_detected"],
                        "leaked_tenant": leaked_tenant,
                    },
                )
        verdict = detect_injection(joined)
        if verdict["score"] >= cfg.injection_threshold:
            note(request, "injection", "blocked")
            return JSONResponse(
                status_code=422,
                content={
                    "detail": "input blocked by guardrails",
                    "matches": [m["rule"] for m in verdict["matches"]],
                },
            )
        est = estimate_tokens(joined)
        budget_verdict = budget.check(est)
        if not budget_verdict["allowed"]:
            note(request, "budget", "blocked", budget_verdict["reason"])
            return JSONResponse(
                status_code=429, content={"detail": budget_verdict["reason"]}
            )
        if cfg.scrub_pii and texts:
            scrubbed = scrub_pii(joined)
            if scrubbed["findings"]:
                note(request, "pii", "blocked", ",".join(scrubbed["findings"]))
                return JSONResponse(
                    status_code=422,
                    content={
                        "detail": "pii detected; resubmit sanitized input",
                        "findings": scrubbed["findings"],
                    },
                )
        return await call_next(request)
