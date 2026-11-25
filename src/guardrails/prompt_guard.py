"""Prompt injection detection (cross-pollinated from dair-ai/Prompt-Engineering-Guide).

Deterministic, dependency-free scanner for common prompt-injection patterns:
instruction override, role hijacking, delimiter smuggling, and exfiltration
requests. Returns a risk score and the matched patterns.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "ignore_previous",
        re.compile(
            r"ignore (all |the )?(previous|prior|above) (instructions|prompts|rules)",
            re.IGNORECASE,
        ),
        0.9,
    ),
    (
        "role_hijack",
        re.compile(r"you are now|act as (a |an )?(?!assistant)", re.IGNORECASE),
        0.7,
    ),
    ("system_override", re.compile(r"(^|\n)\s*system\s*:", re.IGNORECASE), 0.8),
    (
        "delimiter_smuggle",
        re.compile(r"<\|.*?\|>|```system|###\s*instruction", re.IGNORECASE),
        0.6,
    ),
    (
        "exfil_request",
        re.compile(
            r"(reveal|print|show|leak).*(secret|password|api.?key|token|hidden)",
            re.IGNORECASE,
        ),
        0.85,
    ),
    (
        "jailbreak",
        re.compile(r"jailbreak|do anything now|dan mode|developer mode", re.IGNORECASE),
        0.95,
    ),
]


def scan_prompt(text: str) -> dict:
    if not isinstance(text, str):
        raise TypeError("text must be a str")
    matches = []
    score = 0.0
    for name, pattern, weight in _PATTERNS:
        if pattern.search(text):
            matches.append(name)
            score = max(score, weight)
    # Multiple distinct patterns raise risk.
    if len(matches) >= 2:
        score = min(1.0, score + 0.1 * (len(matches) - 1))
    return {
        "risk_score": round(score, 4),
        "matched": matches,
        "safe": score < 0.5,
        "patterns_checked": len(_PATTERNS),
    }
