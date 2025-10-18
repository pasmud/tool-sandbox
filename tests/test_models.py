"""Tests for tool_sandbox.models."""

from __future__ import annotations

import unittest

from tool_sandbox.models import (
    Finding,
    PathRule,
    Plan,
    Policy,
    Report,
    Severity,
    ToolCall,
    Verdict,
)


class SeverityTests(unittest.TestCase):
    def test_from_value_accepts_enum_and_string(self) -> None:
        self.assertIs(Severity.from_value(Severity.HIGH), Severity.HIGH)
        self.assertIs(Severity.from_value("critical"), Severity.CRITICAL)
        self.assertIs(Severity.from_value(" LOW "), Severity.LOW)

    def test_from_value_rejects_unknown(self) -> None:
        with self.assertRaises(ValueError):
            Severity.from_value("urgent")

    def test_rank_ordering(self) -> None:
        self.assertLess(Severity.LOW.rank, Severity.MEDIUM.rank)
        self.assertLess(Severity.MEDIUM.rank, Severity.HIGH.rank)
        self.assertLess(Severity.HIGH.rank, Severity.CRITICAL.rank)


class VerdictTests(unittest.TestCase):
    def test_from_value(self) -> None:
        self.assertIs(Verdict.from_value("allow"), Verdict.ALLOW)
        self.assertIs(Verdict.from_value(Verdict.BLOCK), Verdict.BLOCK)
