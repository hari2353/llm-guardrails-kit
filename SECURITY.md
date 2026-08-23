# Security Notes

This repo IS a defensive security control — its own posture matters too.

## Controls
- Detection is deny-by-default at threshold: any rule hit ≥ 0.35 score blocks with machine-readable rule names
- PII patterns are allow-listed regex classes; Luhn validation prevents false-positive blocking of order numbers
- Middleware never mutates payloads in place — it blocks (422) so callers cannot bypass via partial sanitization
- Budget window uses (timestamp, tokens) pairs; bounded memory per app instance
- No network calls, no secrets read, no logging of payload contents

## Known gaps
- Heuristic injection detection is bypassable by novel phrasing — pair with a model-based classifier for adversarial tenants
- Regex PII coverage is best-effort; production deployments should add NER-based detection
- Per-process budget state — multi-replica deployments need shared counters
