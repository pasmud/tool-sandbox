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
    id: str | None = None

    def __post_init__(self) -> None:
        if not self.tool or not str(self.tool).strip():
            raise ValueError("tool call must have a non-empty tool name")
        if not isinstance(self.args, dict):
            raise ValueError(f"tool call {self.tool!r} args must be an object")

    @classmethod
    def from_dict(cls, data: dict[str, Any], index: int) -> "ToolCall":
        if not isinstance(data, dict):
            raise ValueError(f"plan step {index} must be an object")
        unknown = set(data) - {"tool", "name", "args", "arguments", "id"}
        if unknown:
            raise ValueError(
                f"plan step {index} has unknown fields: "
                + ", ".join(sorted(unknown))
            )
        tool = data.get("tool", data.get("name"))
        if tool is None:
            raise ValueError(f"plan step {index} missing required field: tool")
        raw_args = data.get("args", data.get("arguments", {}))
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, dict):
            raise ValueError(f"plan step {index} args must be an object")
        step_id = data.get("id")
        if step_id is not None:
            step_id = str(step_id)
        return cls(tool=str(tool), args=dict(raw_args), id=step_id)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"tool": self.tool, "args": dict(self.args)}
        if self.id is not None:
            data["id"] = self.id
        return data

    def label(self, index: int) -> str:
        base = self.id if self.id else f"step-{index + 1}"
        return f"{base} ({self.tool})"


@dataclass(frozen=True)
class Plan:
    """An agent execution plan to be checked."""

    steps: tuple[ToolCall, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Any) -> "Plan":
        if isinstance(data, list):
            steps_raw = data
            metadata: dict[str, Any] = {}
        elif isinstance(data, dict):
            unknown = set(data) - {"steps", "metadata", "plan", "name", "version"}
            if unknown:
                raise ValueError(
                    "plan has unknown fields: " + ", ".join(sorted(unknown))
                )
            steps_raw = data.get("steps", data.get("plan"))
            if steps_raw is None:
                raise ValueError("plan object must contain a 'steps' list")
            metadata = dict(data.get("metadata", {}))
            if "name" in data:
                metadata.setdefault("name", data["name"])
            if "version" in data:
                metadata.setdefault("version", data["version"])
        else:
            raise ValueError("plan must be a JSON array or object with 'steps'")

        if not isinstance(steps_raw, list):
            raise ValueError("plan steps must be a list")
        steps = tuple(ToolCall.from_dict(item, i) for i, item in enumerate(steps_raw))
        return cls(steps=steps, metadata=metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [step.to_dict() for step in self.steps],
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class PathRule:
    """Policy constraints for filesystem-like path arguments."""

    allowed_prefixes: tuple[str, ...] = ()
    denied_prefixes: tuple[str, ...] = ()
    denied_patterns: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Any) -> "PathRule":
        if not isinstance(data, dict):
            raise ValueError("path rule must be an object")
        unknown = set(data) - {"allowed_prefixes", "denied_prefixes", "denied_patterns"}
        if unknown:
            raise ValueError(
                "path rule has unknown fields: " + ", ".join(sorted(unknown))
            )

        def _str_tuple(key: str) -> tuple[str, ...]:
            raw = data.get(key, ())
            if isinstance(raw, list):
                raw = tuple(raw)
            if not isinstance(raw, tuple):
                raise ValueError(f"path rule {key} must be a list of strings")
            return tuple(str(item) for item in raw)

        return cls(
            allowed_prefixes=_str_tuple("allowed_prefixes"),
            denied_prefixes=_str_tuple("denied_prefixes"),
            denied_patterns=_str_tuple("denied_patterns"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_prefixes": list(self.allowed_prefixes),
            "denied_prefixes": list(self.denied_prefixes),
            "denied_patterns": list(self.denied_patterns),
        }


@dataclass(frozen=True)
class Policy:
    """Sandbox policy controlling which tool calls are allowed."""

    allowed_tools: tuple[str, ...] = ()
    denied_tools: tuple[str, ...] = ()
    denied_arg_patterns: tuple[str, ...] = ()
    path_rules: PathRule = field(default_factory=PathRule)
