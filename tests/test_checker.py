"""Tests for tool_sandbox.checker."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tool_sandbox.checker import check_plan, load_plan, load_policy
from tool_sandbox.models import Policy, Verdict


class LoadersTests(unittest.TestCase):
    def test_load_plan_from_dict_and_list(self) -> None:
        plan = load_plan([{"tool": "read_file", "args": {"path": "/a"}}])
        self.assertEqual(len(plan.steps), 1)
        plan2 = load_plan({"steps": [{"tool": "read_file", "args": {}}]})
        self.assertEqual(len(plan2.steps), 1)

    def test_load_plan_from_file_and_json_string(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "plan.json"
            path.write_text('[{"tool": "read_file", "args": {"path": "/a"}}]', encoding="utf-8")
            plan = load_plan(path)
            self.assertEqual(plan.steps[0].tool, "read_file")
            plan2 = load_plan(path.read_text(encoding="utf-8"))
            self.assertEqual(plan2.steps[0].args["path"], "/a")

    def test_load_plan_errors(self) -> None:
        with self.assertRaises(ValueError):
            load_plan("{not json")
        with self.assertRaises(TypeError):
            load_plan(123)  # type: ignore[arg-type]

    def test_load_policy_defaults_and_file(self) -> None:
        policy = load_policy(None)
        self.assertFalse(policy.allow_network_tools)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text('{"deny_shell": true, "max_steps": 3}', encoding="utf-8")
            loaded = load_policy(path)
            self.assertTrue(loaded.deny_shell)
            self.assertEqual(loaded.max_steps, 3)

    def test_load_policy_rejects_bad_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "policy.json"
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(path)
