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

    def test_combine_returns_most_severe(self) -> None:
        self.assertIs(Verdict.combine(Verdict.ALLOW, Verdict.FLAG), Verdict.FLAG)
        self.assertIs(Verdict.combine(Verdict.BLOCK, Verdict.FLAG), Verdict.BLOCK)
        self.assertIs(Verdict.combine(Verdict.ALLOW, Verdict.ALLOW), Verdict.ALLOW)


class ToolCallTests(unittest.TestCase):
    def test_from_dict_minimal(self) -> None:
        call = ToolCall.from_dict({"tool": "read_file", "args": {"path": "/a"}}, 0)
        self.assertEqual(call.tool, "read_file")
        self.assertEqual(call.args, {"path": "/a"})
        self.assertIsNone(call.id)

    def test_from_dict_accepts_name_and_arguments(self) -> None:
        call = ToolCall.from_dict({"name": "shell", "arguments": {"cmd": "ls"}, "id": "s1"}, 3)
        self.assertEqual(call.tool, "shell")
        self.assertEqual(call.args, {"cmd": "ls"})
        self.assertEqual(call.id, "s1")
        self.assertEqual(call.label(3), "s1 (shell)")
