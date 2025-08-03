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
