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
| Injection detector | 7 rule classes (instruction override, prompt-leak, role hijack, delimiter abuse, exfiltration, jailbreak phrases) + base64-encoded payload inspection, **evasion-normalized** (zero-width/bidi invisibles stripped, cyrillic homoglyphs folded before matching; `evasion_attempt` reported when stripping changed the text) → score ≥ threshold = blocked `422` | `GUARD_INJECTION_THRESHOLD` |
| PII scrubber | email / intl phone / SSN-like / API keys (sk-, ghp_, AKIA) / JWTs / Slack tokens / Google keys / generic labeled secrets (`password=`-style, value-only redaction) / credit cards with **Luhn validation** → blocked `422` with findings list | `GUARD_SCRUB_PII` |
| Canary tripwire | plant an unguessable `CANARY-…` token in each tenant's system prompt (`CanaryRegistry.mint`); if one ever arrives as **input**, that tenant's prompt leaked — blocked `422` naming the tenant, canary value never echoed | optional `canaries=` registry |
| Token budget | per-request cap + rolling 60s window → `429` when exceeded | `GUARD_PER_REQUEST_TOKENS` |
| Output validator | fenced-JSON tolerant parse, missing-key report, retry hint for self-correction loops | library call |

## Design notes

- Middleware walks arbitrary JSON payloads and screens every nested string — no schema coupling
- Blocked responses include machine-readable rule names so callers can log/aggregate attack classes
- Zero hard deps beyond FastAPI; tiktoken optional for exact token counts

## Tests

20 tests incl. adversarial suite: classic jailbreak phrases, base64-wrapped injections, zero-width and
homoglyph evasions (caught after normalization, prose untouched), canary leak tripwires (tenant named,
value never echoed), Luhn-passing vs failing numbers, JWT/Slack/Google/generic-labeled secrets,
budget window math, and middleware behavior on clean/injected/PII payloads.

MIT
