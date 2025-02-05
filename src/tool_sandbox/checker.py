"""Policy checking logic for agent tool execution plans."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Finding, Plan, Policy, Report, Severity, ToolCall, Verdict


def load_plan(source: str | Path | dict | list) -> Plan:
    """Load a plan from a path, JSON string, or already-parsed object."""
    data = _load_jsonish(source, label="plan")
    return Plan.from_dict(data)


def load_policy(source: str | Path | dict | None) -> Policy:
    """Load a policy from a path, JSON string, dict, or None for defaults."""
    if source is None:
        return Policy()
    data = _load_jsonish(source, label="policy")
    return Policy.from_dict(data)


def _load_jsonish(source: str | Path | dict | list, *, label: str) -> Any:
    if isinstance(source, (dict, list)):
        return source
    if isinstance(source, Path):
        return _read_json_file(source, label=label)
    if isinstance(source, str):
        # Treat as path if it exists; otherwise try parsing as JSON text.
        # This keeps CLI ergonomics predictable.
        candidate = Path(source)
        if candidate.exists():
            return _read_json_file(candidate, label=label)
        try:
            return json.loads(source)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{label} string is not an existing file and is not valid JSON: {exc}"
            ) from exc
    raise TypeError(f"{label} must be a path, JSON string, or parsed object")


def _read_json_file(path: Path, *, label: str) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {label} file {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {label} file {path}: {exc}") from exc


def check_plan(plan: Plan | dict | list | str | Path, policy: Policy | dict | str | Path | None = None) -> Report:
    """Check an execution plan against a sandbox policy.

    The policy is evaluated deterministically. Findings are emitted in plan
    order, and the overall verdict is the most severe finding verdict.
    """
