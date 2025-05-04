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
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.version:
        from . import __version__

        print(__version__)
        return 0

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "check":
        return _cmd_check(args, parser)

    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover


def _cmd_check(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        plan = _load_plan_arg(args.plan)
        policy = load_policy(args.policy) if args.policy else load_policy(None)
        report = check_plan(plan, policy)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        rendered = _render_report(report.to_dict(), fmt=args.format)
        if args.output:
            try:
                Path(args.output).write_text(
                    rendered + ("" if rendered.endswith("\n") else "\n"),
                    encoding="utf-8",
                )
            except OSError as exc:
                print(f"error: cannot write output {args.output}: {exc}", file=sys.stderr)
                return 2
        else:
            print(rendered)

    return _exit_code(report.verdict, strict=bool(args.strict))


def _load_plan_arg(value: str) -> Any:
    if value == "-":
        try:
            raw = sys.stdin.read()
        except OSError as exc:
            raise ValueError(f"cannot read plan from stdin: {exc}") from exc
        try:
            return load_plan(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on stdin: {exc}") from exc
    return load_plan(value)


def _render_report(report: dict[str, Any], *, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True)
    if fmt == "text":
        return _render_text(report)
    raise ValueError(f"unsupported format: {fmt}")


def _render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    verdict = str(report.get("verdict", "unknown")).upper()
    lines.append(f"Verdict: {verdict}")
    lines.append(f"Steps checked: {report.get('steps_checked', 0)}")
    lines.append(f"Findings: {report.get('finding_count', 0)}")
    counts = report.get("counts", {})
    if counts:
        lines.append(
            "Counts: "
            + ", ".join(f"{k}={counts[k]}" for k in ("block", "flag", "allow") if k in counts)
        )
    findings = report.get("findings", [])
    if findings:
        lines.append("")
        lines.append("Details:")
        for finding in findings:
            step = finding.get("step_index")
            tool = finding.get("tool")
            location = ""
            if step is not None:
                location = f" step={step}"
            if tool:
                location += f" tool={tool}"
            lines.append(
                f"- [{finding.get('verdict', '?').upper()} {finding.get('severity', '?').upper()} {finding.get('rule_id', '?')}]"
                f"{location}: {finding.get('message', '')}"
            )
    return "\n".join(lines)


def _exit_code(verdict: Verdict, *, strict: bool) -> int:
    if verdict is Verdict.BLOCK:
        return 1
    if strict and verdict is Verdict.FLAG:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
