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
