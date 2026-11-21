"""Versioned guardrail policy datasheet (ML-Sensors cross-pollination).

Documents which layers run, their thresholds, intended use, limitations and
privacy posture, so a deployed policy can be audited like an ML sensor.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GuardrailDatasheet:
    name: str
    version: int
    layers: tuple[str, ...]
    thresholds: dict[str, object]
    intended_use: str
    limitations: tuple[str, ...]
    privacy: dict[str, object]
    environmental: dict[str, object]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("name must be non-empty")
        if self.version < 1:
            raise ValueError("version must be >= 1")
        if not self.layers:
            raise ValueError("layers must be non-empty")
        if not self.intended_use.strip():
            raise ValueError("intended_use must be non-empty")
        if not self.limitations or any(not item.strip() for item in self.limitations):
            raise ValueError("at least one non-empty limitation is required")

    def to_markdown(self) -> str:
        lines = [
            f"# Guardrail datasheet: {self.name} v{self.version}",
            "",
            "## Layers",
            "",
        ]
        lines.extend(f"- {layer}" for layer in self.layers)
        lines.extend(["", "## Thresholds", ""])
        if self.thresholds:
            lines.extend(f"- {key}: {value}" for key, value in self.thresholds.items())
        else:
            lines.append("not documented")
        lines.extend(["", "## Intended use", "", self.intended_use, "", "## Limitations", ""])
        lines.extend(f"- {item}" for item in self.limitations)
        for title, payload in (("Privacy", self.privacy), ("Environmental", self.environmental)):
            lines.extend(["", f"## {title}", ""])
            if payload:
                lines.extend(f"- {key}: {value}" for key, value in payload.items())
            else:
                lines.append("not documented")
        lines.append("")
        return "\n".join(lines)


def build_datasheet(
    name: str,
    version: int,
    *,
    layers: tuple[str, ...] | list[str],
    thresholds: dict[str, object] | None = None,
    intended_use: str,
    limitations: tuple[str, ...] | list[str],
    privacy: dict[str, object] | None = None,
    environmental: dict[str, object] | None = None,
) -> GuardrailDatasheet:
    return GuardrailDatasheet(
        name=name,
        version=version,
        layers=tuple(layers),
        thresholds=dict(thresholds or {}),
        intended_use=intended_use,
        limitations=tuple(limitations),
        privacy=dict(privacy or {}),
        environmental=dict(environmental or {}),
    )
