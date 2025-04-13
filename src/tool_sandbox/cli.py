"""Command-line interface for tool-sandbox."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .checker import check_plan, load_plan, load_policy
from .models import Verdict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tool-sandbox",
        description="Sandbox policy checker for agent tool execution plans.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit.",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser(
        "check",
        help="Check an execution plan against a sandbox policy.",
        description="Check an execution plan JSON file against a sandbox policy JSON file.",
    )
    check.add_argument("plan", help="Path to plan JSON file, or '-' for stdin.")
    check.add_argument(
        "--policy",
        "-p",
        default=None,
        help="Path to policy JSON file. Defaults to built-in safe defaults.",
    )
    check.add_argument(
        "--format",
        "-f",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json).",
    )
    check.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write report to this file instead of stdout.",
    )
    check.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on FLAG as well as BLOCK (default: BLOCK only).",
    )
    check.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress report output; rely on exit code.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
