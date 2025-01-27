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
