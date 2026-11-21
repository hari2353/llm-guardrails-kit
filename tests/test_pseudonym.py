import json

from guardrails.audit import AuditLog
from guardrails.pseudonym import Pseudonymizer, pseudonymize_pii


def test_same_tenant_same_value_is_stable():
    first = Pseudonymizer("tenant-a").mask("alice@example.com", "email")
    second = Pseudonymizer("tenant-a").mask("alice@example.com", "email")
    assert first == second
    assert first.startswith("EMAIL_")
    assert len(first) == len("EMAIL_") + 12


def test_different_tenant_differs():
    a = Pseudonymizer("tenant-a").mask("alice@example.com", "email")
    b = Pseudonymizer("tenant-b").mask("alice@example.com", "email")
    assert a != b


def test_kind_is_part_of_the_pseudonym():
    p = Pseudonymizer("tenant-a")
    assert p.mask("12345", "email") != p.mask("12345", "phone_intl")


def test_pseudonymize_replaces_multiple_kinds_and_hides_raw_values():
    text = "Contact a@b.com or +91 98765 43210, key sk-abcdefghijklmnopqrstuvwx"
    out = pseudonymize_pii(text, "acme")
    assert set(out["findings"]) == {"email", "phone_intl", "api_key"}
    assert "a@b.com" not in out["text"]
    assert "98765" not in out["text"]
    assert "sk-abcdefghijklmnopqrstuvwx" not in out["text"]
    assert "EMAIL_" in out["text"]
    assert "PHONE_INTL_" in out["text"]
    assert "API_KEY_" in out["text"]
    # findings are kinds only: no reversible map and no raw value
    encoded = json.dumps(out)
    assert "a@b.com" not in encoded
    assert "sk-abcdefghijklmnopqrstuvwx" not in encoded


def test_pseudonymize_leaves_prose_untouched():
    prose = "Please summarize the Kubernetes guide — naïve café, 90% done."
    out = pseudonymize_pii(prose, "acme")
    assert out["text"] == prose
    assert out["findings"] == []


def test_audit_log_is_bounded_and_recent_is_newest_first():
    log = AuditLog(max_events=3)
    for i in range(5):
        log.record("acme", "middleware", f"action-{i}")
    events = log.recent()
    assert len(events) == 3
    assert [e["action"] for e in events] == ["action-4", "action-3", "action-2"]
    assert len(log.recent(limit=100)) == 3
    assert log.recent(limit=1)[0]["action"] == "action-4"


def test_audit_log_records_tenant_layer_and_bounded_detail():
    log = AuditLog()
    log.record("acme", "pii", "blocked", "x" * 5000)
    event = log.recent()[0]
    assert event["tenant"] == "acme"
    assert event["layer"] == "pii"
    assert event["action"] == "blocked"
    assert len(event["detail"]) <= 200
