from __future__ import annotations

import base64
import re

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore_instructions", re.compile(r"ignore (all |any |the )?(previous|prior|above) instructions", re.I)),
    ("system_prompt_leak", re.compile(r"(reveal|show|print|repeat) (your|the) (system prompt|instructions)", re.I)),
    ("role_hijack", re.compile(r"you are now (a|an) (unrestricted|DAN|evil|hacker)", re.I)),
    ("delimiter_abuse", re.compile(r"<\|(im_start|im_end|endoftext|system)\|>", re.I)),
    ("override_directive", re.compile(r"(new|updated) (system )?(directive|instructions):", re.I)),
    ("exfiltration", re.compile(r"(send|post) .{0,40} to https?://", re.I)),
    ("jailbreak_phrase", re.compile(r"\b(dev mode|do anything now|no restrictions)\b", re.I)),
]


def detect_injection(text: str) -> dict:
    matches = []
    for name, pattern in PATTERNS:
        found = pattern.search(text)
        if found:
            matches.append({"rule": name, "span": found.group(0)[:60]})
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8")
        for name, pattern in PATTERNS:
            if pattern.search(decoded):
                matches.append({"rule": f"{name}_in_base64", "span": "decoded-payload"})
    except Exception:
        pass

    score = min(0.35 * len(matches), 1.0)
    return {"score": round(score, 3), "matches": matches, "blocked": score >= 0.35}


REDACTIONS = [
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")),
    ("phone_intl", re.compile(r"\+\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}")),
    ("ssn_like", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("api_key", re.compile(r"\b(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16})\b")),
]


def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in number]
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def scrub_pii(text: str) -> dict:
    redacted = text
    findings = []
    for name, pattern in REDACTIONS:
        def _sub(match, _name=name):
            findings.append(_name)
            return f"[REDACTED_{_name.upper()}]"

        redacted = pattern.sub(_sub, redacted)

    cc_pattern = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def _cc_sub(match):
        raw = match.group(0)
        digits_only = re.sub(r"[ -]", "", raw)
        if _luhn_ok(digits_only):
            findings.append("credit_card")
            return "[REDACTED_CREDIT_CARD]"
        return raw

    redacted = cc_pattern.sub(_cc_sub, redacted)
    return {"redacted": redacted, "findings": sorted(set(findings))}
