from guardrails.datasheet import build_datasheet


def test_datasheet_contains_layers_and_thresholds():
    sheet = build_datasheet(
        "input-guard",
        2,
        layers=("injection", "pii", "budget"),
        thresholds={"injection_threshold": 0.35},
        intended_use="Block unsafe prompts before the model.",
        limitations=("Heuristic thresholds, not a classifier.",),
    )
    text = sheet.to_markdown()
    assert "# Guardrail datasheet: input-guard v2" in text
    assert "- injection" in text
    assert "injection_threshold: 0.35" in text
    assert "Heuristic thresholds" in text


def test_missing_optional_sections_rendered():
    sheet = build_datasheet(
        "input-guard",
        1,
        layers=("pii",),
        intended_use="Scrub PII.",
        limitations=("False positives on code.",),
    )
    text = sheet.to_markdown()
    assert text.count("not documented") == 3


def test_datasheet_rejects_invalid():
    for kwargs in (
        {
            "name": " ",
            "version": 1,
            "layers": ("pii",),
            "intended_use": "use",
            "limitations": ("x",),
        },
        {
            "name": "g",
            "version": 0,
            "layers": ("pii",),
            "intended_use": "use",
            "limitations": ("x",),
        },
        {
            "name": "g",
            "version": 1,
            "layers": (),
            "intended_use": "use",
            "limitations": ("x",),
        },
        {
            "name": "g",
            "version": 1,
            "layers": ("pii",),
            "intended_use": " ",
            "limitations": ("x",),
        },
        {
            "name": "g",
            "version": 1,
            "layers": ("pii",),
            "intended_use": "use",
            "limitations": (),
        },
    ):
        try:
            build_datasheet(**kwargs)
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid input: {kwargs}")


def test_datasheet_is_deterministic():
    kwargs = dict(
        name="g",
        version=1,
        layers=("pii",),
        intended_use="use",
        limitations=("x",),
        privacy={"pii": "none stored"},
        environmental={"kwh": 0.1},
    )
    first = build_datasheet(**kwargs).to_markdown()
    second = build_datasheet(**kwargs).to_markdown()
    assert first == second
