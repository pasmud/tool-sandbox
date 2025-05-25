"""Data models for tool-sandbox."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_value(cls, value: str | "Severity") -> "Severity":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(
            f"unknown severity {value!r}; expected one of: "
            + ", ".join(m.value for m in cls)
        )

    @property
    def rank(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Verdict(str, Enum):
    """Overall or per-finding verdict."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"

    @classmethod
    def from_value(cls, value: str | "Verdict") -> "Verdict":
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(
            f"unknown verdict {value!r}; expected one of: "
            + ", ".join(m.value for m in cls)
        )

    @property
    def rank(self) -> int:
        return {Verdict.ALLOW: 0, Verdict.FLAG: 1, Verdict.BLOCK: 2}[self]

    @classmethod
    def combine(cls, left: "Verdict", right: "Verdict") -> "Verdict":
        return left if left.rank >= right.rank else right


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation in an execution plan."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
