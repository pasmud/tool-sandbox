"""Tests for the tool_sandbox CLI."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tool_sandbox.cli import main


class CLIMainTests(unittest.TestCase):
    def run_main(self, argv: list[str], stdin: str | None = None) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        old_stdin = sys.stdin
        try:
            if stdin is not None:
                sys.stdin = io.StringIO(stdin)
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(argv)
        finally:
            sys.stdin = old_stdin
        return code, stdout.getvalue(), stderr.getvalue()

    def test_version(self) -> None:
        code, out, err = self.run_main(["--version"])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip())
        self.assertEqual(err, "")

    def test_no_command_returns_2(self) -> None:
        code, out, _err = self.run_main([])
        self.assertEqual(code, 2)
        self.assertIn("tool-sandbox", out)

    def test_check_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plan = root / "plan.json"
            policy = root / "policy.json"
            plan.write_text(
                json.dumps([{"tool": "read_file", "args": {"path": "/workspace/a.txt"}}]),
                encoding="utf-8",
            )
            policy.write_text(
                json.dumps(
                    {
                        "allowed_tools": ["read_file"],
                        "path_rules": {"allowed_prefixes": ["/workspace"]},
                    }
                ),
                encoding="utf-8",
            )
            code, out, err = self.run_main(["check", str(plan), "--policy", str(policy)])
            self.assertEqual(code, 0, msg=out + err)
            report = json.loads(out)
            self.assertEqual(report["verdict"], "allow")

    def test_check_text_output_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps([{"tool": "http_request", "args": {"url": "https://example.com"}}]),
                encoding="utf-8",
            )
            code, out, _err = self.run_main(["check", str(plan), "--format", "text"])
            self.assertEqual(code, 1)
            self.assertIn("Verdict: BLOCK", out)
            self.assertIn("TOOL004", out)

    def test_check_strict_blocks_on_block(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plan = root / "plan.json"
            policy = root / "policy.json"
            plan.write_text(
                json.dumps([{"tool": "read_file", "args": {"path": "/etc/passwd"}}]),
                encoding="utf-8",
            )
            policy.write_text(json.dumps({"path_rules": {"denied_prefixes": ["/etc"]}}), encoding="utf-8")
            code, _out, _err = self.run_main(["check", str(plan), "--policy", str(policy), "--strict"])
            self.assertEqual(code, 1)

    def test_strict_exit_code_for_flag_verdict(self) -> None:
        # The checker currently emits BLOCK findings; strict mode should also
        # treat a FLAG verdict as non-zero per CLI contract.
        from tool_sandbox.cli import _exit_code
        from tool_sandbox.models import Verdict

        self.assertEqual(_exit_code(Verdict.FLAG, strict=False), 0)
        self.assertEqual(_exit_code(Verdict.FLAG, strict=True), 1)
        self.assertEqual(_exit_code(Verdict.ALLOW, strict=True), 0)
        self.assertEqual(_exit_code(Verdict.BLOCK, strict=False), 1)

    def test_check_stdin(self) -> None:
        plan_json = json.dumps([{"tool": "read_file", "args": {"path": "/workspace/x"}}])
        code, out, err = self.run_main(
            [
                "check",
                "-",
                "--policy",
                json.dumps({"allowed_tools": ["read_file"], "path_rules": {"allowed_prefixes": ["/workspace"]}}),
            ],
            stdin=plan_json,
        )
        # --policy expects a path or JSON string; load_policy handles file path or JSON? It tries Path.exists then json.loads.
        # Our CLI passes policy through load_policy which accepts path/json string/dict; here we pass a string arg that is not a file - load_policy will json.loads it.
        self.assertEqual(code, 0, msg=out + err)
        self.assertEqual(json.loads(out)["verdict"], "allow")

    def test_check_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plan = root / "plan.json"
            out_file = root / "report.json"
            plan.write_text(json.dumps([{"tool": "read_file", "args": {"path": "/workspace/a"}}]), encoding="utf-8")
            code, out, err = self.run_main(
                [
                    "check",
                    str(plan),
                    "--policy",
                    json.dumps({"allowed_tools": ["read_file"], "path_rules": {"allowed_prefixes": ["/workspace"]}}),
                    "--output",
                    str(out_file),
                ]
            )
            self.assertEqual(code, 0, msg=err)
            self.assertEqual(out, "")
            report = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(report["verdict"], "allow")

    def test_check_quiet(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            plan = root / "plan.json"
            plan.write_text(
                json.dumps([{"tool": "http_request", "args": {"url": "https://example.com"}}]),
                encoding="utf-8",
            )
            code, out, err = self.run_main(["check", str(plan), "--quiet"])
            self.assertEqual(code, 1)
            self.assertEqual(out, "")
            self.assertEqual(err, "")
