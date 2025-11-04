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

    def test_from_dict_rejects_missing_tool(self) -> None:
        with self.assertRaises(ValueError):
            ToolCall.from_dict({"args": {}}, 0)

    def test_from_dict_rejects_unknown_fields(self) -> None:
        with self.assertRaises(ValueError):
            ToolCall.from_dict({"tool": "x", "args": {}, "extra": 1}, 0)

    def test_from_dict_rejects_non_object_args(self) -> None:
        with self.assertRaises(ValueError):
            ToolCall.from_dict({"tool": "x", "args": []}, 0)

    def test_empty_tool_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ToolCall(tool="")

    def test_to_dict_round_trip(self) -> None:
        call = ToolCall(tool="write_file", args={"path": "/tmp/a"}, id="w1")
        restored = ToolCall.from_dict(call.to_dict(), 0)
        self.assertEqual(restored, call)


class PlanTests(unittest.TestCase):
    def test_from_list(self) -> None:
        plan = Plan.from_dict([{"tool": "read_file", "args": {"path": "/x"}}])
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].tool, "read_file")

    def test_from_object_with_metadata(self) -> None:
        plan = Plan.from_dict(
            {
                "name": "p1",
                "version": "2",
                "steps": [{"tool": "t", "args": {}}],
                "metadata": {"owner": "test"},
            }
        )
        self.assertEqual(plan.metadata["name"], "p1")
        self.assertEqual(plan.metadata["version"], "2")
        self.assertEqual(plan.metadata["owner"], "test")

    def test_rejects_unknown_top_level_field(self) -> None:
        with self.assertRaises(ValueError):
            Plan.from_dict({"steps": [], "oops": True})

    def test_rejects_missing_steps(self) -> None:
        with self.assertRaises(ValueError):
            Plan.from_dict({"name": "x"})

    def test_rejects_non_list_steps(self) -> None:
        with self.assertRaises(ValueError):
            Plan.from_dict({"steps": "nope"})


class PolicyTests(unittest.TestCase):
    def test_defaults(self) -> None:
        policy = Policy.from_dict({})
        self.assertEqual(policy.allowed_tools, ())
        self.assertFalse(policy.allow_network_tools)
        self.assertFalse(policy.deny_shell)
        self.assertIsNone(policy.max_steps)

    def test_from_dict_full(self) -> None:
        policy = Policy.from_dict(
            {
                "allowed_tools": ["read_file"],
                "denied_tools": ["shell"],
                "denied_arg_patterns": ["rm\\s+-rf"],
                "path_rules": {
                    "allowed_prefixes": ["/workspace"],
                    "denied_prefixes": ["/etc"],
                    "denied_patterns": ["\\.env$"],
                },
                "max_steps": 5,
                "max_arg_chars": 100,
                "allow_network_tools": True,
                "deny_shell": True,
            }
        )
        self.assertEqual(policy.allowed_tools, ("read_file",))
        self.assertEqual(policy.path_rules.allowed_prefixes, ("/workspace",))
        self.assertEqual(policy.max_steps, 5)
        self.assertTrue(policy.allow_network_tools)

    def test_rejects_unknown_field(self) -> None:
        with self.assertRaises(ValueError):
            Policy.from_dict({"nope": 1})

    def test_rejects_bad_max_steps(self) -> None:
        with self.assertRaises(ValueError):
            Policy.from_dict({"max_steps": -1})
        with self.assertRaises(ValueError):
            Policy.from_dict({"max_steps": "1"})
