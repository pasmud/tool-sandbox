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
    max_steps: int | None = None
    max_arg_chars: int | None = None
    allow_network_tools: bool = False
    network_tools: tuple[str, ...] = ("http_request", "curl", "wget", "fetch")
    filesystem_tools: tuple[str, ...] = (
        "read_file",
        "write_file",
        "list_dir",
        "delete_file",
        "move_file",
        "copy_file",
    )
    shell_tools: tuple[str, ...] = ("shell", "bash", "exec", "run_command")
    deny_shell: bool = False

    def __post_init__(self) -> None:
        if self.max_steps is not None and self.max_steps < 0:
            raise ValueError("max_steps must be >= 0")
        if self.max_arg_chars is not None and self.max_arg_chars < 0:
            raise ValueError("max_arg_chars must be >= 0")

    @classmethod
    def from_dict(cls, data: Any) -> "Policy":
        if not isinstance(data, dict):
            raise ValueError("policy must be an object")
        known = {
            "allowed_tools",
            "denied_tools",
            "denied_arg_patterns",
            "path_rules",
            "paths",
            "max_steps",
            "max_arg_chars",
            "allow_network_tools",
            "network_tools",
            "filesystem_tools",
            "shell_tools",
            "deny_shell",
        }
        unknown = set(data) - known
        if unknown:
            raise ValueError(
                "policy has unknown fields: " + ", ".join(sorted(unknown))
            )

        def _str_tuple(key: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
            raw = data.get(key, default)
            if isinstance(raw, list):
                raw = tuple(raw)
            if not isinstance(raw, tuple):
                raise ValueError(f"policy {key} must be a list of strings")
            return tuple(str(item) for item in raw)

        def _opt_int(key: str) -> int | None:
            raw = data.get(key)
            if raw is None:
                return None
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise ValueError(f"policy {key} must be an integer or null")
            return int(raw)

        path_rules_raw = data.get("path_rules", data.get("paths", {}))
        path_rules = PathRule.from_dict(path_rules_raw) if path_rules_raw else PathRule()

        return cls(
            allowed_tools=_str_tuple("allowed_tools", ()),
            denied_tools=_str_tuple("denied_tools", ()),
            denied_arg_patterns=_str_tuple("denied_arg_patterns", ()),
            path_rules=path_rules,
            max_steps=_opt_int("max_steps"),
            max_arg_chars=_opt_int("max_arg_chars"),
            allow_network_tools=bool(data.get("allow_network_tools", False)),
            network_tools=_str_tuple(
                "network_tools", ("http_request", "curl", "wget", "fetch")
            ),
            filesystem_tools=_str_tuple(
                "filesystem_tools",
                (
                    "read_file",
                    "write_file",
                    "list_dir",
                    "delete_file",
                    "move_file",
                    "copy_file",
                ),
            ),
            shell_tools=_str_tuple("shell_tools", ("shell", "bash", "exec", "run_command")),
            deny_shell=bool(data.get("deny_shell", False)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_tools": list(self.allowed_tools),
            "denied_tools": list(self.denied_tools),
            "denied_arg_patterns": list(self.denied_arg_patterns),
            "path_rules": self.path_rules.to_dict(),
            "max_steps": self.max_steps,
            "max_arg_chars": self.max_arg_chars,
            "allow_network_tools": self.allow_network_tools,
            "network_tools": list(self.network_tools),
            "filesystem_tools": list(self.filesystem_tools),
            "shell_tools": list(self.shell_tools),
            "deny_shell": self.deny_shell,
        }


@dataclass(frozen=True)
class Finding:
    """A policy finding for a plan step."""

    rule_id: str
    severity: Severity
