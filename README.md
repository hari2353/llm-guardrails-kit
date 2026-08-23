# LLM Guardrails Kit

[![ci](https://github.com/hari2353/llm-guardrails-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/hari2353/llm-guardrails-kit/actions/workflows/ci.yml)

Drop-in input guardrails for any FastAPI LLM service: prompt-injection detection, PII scrubbing,
token budgeting, and structured-output validation with retry hints.

```python
from guardrails.middleware import install_guardrails

app = FastAPI()
install_guardrails(app)   # every POST is now screened
```

## Layers

| Layer | What it does | Config |
|---|---|---|
| Injection detector | 7 rule classes (instruction override, prompt-leak, role hijack, delimiter abuse, exfiltration, jailbreak phrases) + base64-encoded payload inspection → score ≥ threshold = blocked `422` | `GUARD_INJECTION_THRESHOLD` |
| PII scrubber | email / intl phone / SSN-like / API keys (sk-, ghp_, AKIA) / credit cards with **Luhn validation** → blocked `422` with findings list | `GUARD_SCRUB_PII` |
| Token budget | per-request cap + rolling 60s window → `429` when exceeded | `GUARD_PER_REQUEST_TOKENS` |
| Output validator | fenced-JSON tolerant parse, missing-key report, retry hint for self-correction loops | library call |

## Design notes

- Middleware walks arbitrary JSON payloads and screens every nested string — no schema coupling
- Blocked responses include machine-readable rule names so callers can log/aggregate attack classes
- Zero hard deps beyond FastAPI; tiktoken optional for exact token counts

## Tests

11 tests incl. adversarial suite: classic jailbreak phrases, base64-wrapped injections, Luhn-passing
vs failing numbers, budget window math, and middleware behavior on clean/injected/PII payloads.

MIT
