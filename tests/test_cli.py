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
