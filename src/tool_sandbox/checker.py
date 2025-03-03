"""Policy checking logic for agent tool execution plans."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Finding, Plan, Policy, Report, Severity, ToolCall, Verdict


def load_plan(source: str | Path | dict | list) -> Plan:
    """Load a plan from a path, JSON string, or already-parsed object."""
    data = _load_jsonish(source, label="plan")
    return Plan.from_dict(data)


def load_policy(source: str | Path | dict | None) -> Policy:
    """Load a policy from a path, JSON string, dict, or None for defaults."""
    if source is None:
        return Policy()
    data = _load_jsonish(source, label="policy")
    return Policy.from_dict(data)


def _load_jsonish(source: str | Path | dict | list, *, label: str) -> Any:
    if isinstance(source, (dict, list)):
        return source
    if isinstance(source, Path):
        return _read_json_file(source, label=label)
    if isinstance(source, str):
        # Treat as path if it exists; otherwise try parsing as JSON text.
        # This keeps CLI ergonomics predictable.
        candidate = Path(source)
        if candidate.exists():
            return _read_json_file(candidate, label=label)
        try:
            return json.loads(source)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{label} string is not an existing file and is not valid JSON: {exc}"
            ) from exc
    raise TypeError(f"{label} must be a path, JSON string, or parsed object")


def _read_json_file(path: Path, *, label: str) -> Any:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {label} file {path}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {label} file {path}: {exc}") from exc


def check_plan(plan: Plan | dict | list | str | Path, policy: Policy | dict | str | Path | None = None) -> Report:
    """Check an execution plan against a sandbox policy.

    The policy is evaluated deterministically. Findings are emitted in plan
    order, and the overall verdict is the most severe finding verdict.
    """

    plan_obj = plan if isinstance(plan, Plan) else load_plan(plan)
    policy_obj = policy if isinstance(policy, Policy) else load_policy(policy)

    findings: list[Finding] = []
    findings.extend(_check_plan_limits(plan_obj, policy_obj))
    for index, step in enumerate(plan_obj.steps):
        findings.extend(_check_step(step, index, policy_obj))

    verdict = Verdict.ALLOW
    for finding in findings:
        verdict = Verdict.combine(verdict, finding.verdict)

    return Report(
        verdict=verdict,
        findings=findings,
        steps_checked=len(plan_obj.steps),
        policy=policy_obj.to_dict(),
        metadata=dict(plan_obj.metadata),
    )


def _check_plan_limits(plan: Plan, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    if policy.max_steps is not None and len(plan.steps) > policy.max_steps:
        findings.append(
            Finding(
                rule_id="PLAN001",
                severity=Severity.HIGH,
                verdict=Verdict.BLOCK,
                message=(
                    f"plan has {len(plan.steps)} steps, exceeding max_steps={policy.max_steps}"
                ),
                detail={"step_count": len(plan.steps), "max_steps": policy.max_steps},
            )
        )
    return findings


def _check_step(step: ToolCall, index: int, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    tool = step.tool
    tool_norm = tool.strip().lower()

    if policy.denied_tools and _matches_any(tool_norm, policy.denied_tools):
        findings.append(
            Finding(
                rule_id="TOOL001",
                severity=Severity.CRITICAL,
                verdict=Verdict.BLOCK,
                message=f"{step.label(index)} is explicitly denied by policy",
                step_index=index,
                tool=tool,
                detail={"denied_tools": list(policy.denied_tools)},
            )
        )

    if policy.allowed_tools and not _matches_any(tool_norm, policy.allowed_tools):
        findings.append(
            Finding(
                rule_id="TOOL002",
                severity=Severity.HIGH,
                verdict=Verdict.BLOCK,
                message=f"{step.label(index)} is not in allowed_tools",
                step_index=index,
                tool=tool,
                detail={"allowed_tools": list(policy.allowed_tools)},
            )
        )

    if policy.deny_shell and _matches_any(tool_norm, policy.shell_tools):
        findings.append(
            Finding(
                rule_id="TOOL003",
                severity=Severity.CRITICAL,
                verdict=Verdict.BLOCK,
                message=f"{step.label(index)} uses a shell tool but deny_shell is enabled",
                step_index=index,
                tool=tool,
                detail={"shell_tools": list(policy.shell_tools)},
            )
        )

    if not policy.allow_network_tools and _matches_any(tool_norm, policy.network_tools):
        findings.append(
            Finding(
                rule_id="TOOL004",
                severity=Severity.HIGH,
                verdict=Verdict.BLOCK,
                message=f"{step.label(index)} uses a network tool but allow_network_tools is false",
                step_index=index,
                tool=tool,
                detail={"network_tools": list(policy.network_tools)},
            )
        )

    findings.extend(_check_arg_size(step, index, policy))
    findings.extend(_check_denied_arg_patterns(step, index, policy))
    findings.extend(_check_paths(step, index, policy))
    return findings


def _matches_any(value: str, candidates: tuple[str, ...] | list[str]) -> bool:
    value_norm = value.strip().lower()
    return any(value_norm == str(c).strip().lower() for c in candidates)


def _check_arg_size(step: ToolCall, index: int, policy: Policy) -> list[Finding]:
    if policy.max_arg_chars is None:
        return []
    try:
        rendered = json.dumps(step.args, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        rendered = str(step.args)
    size = len(rendered)
    if size > policy.max_arg_chars:
        return [
            Finding(
                rule_id="ARG001",
                severity=Severity.MEDIUM,
                verdict=Verdict.BLOCK,
                message=(
                    f"{step.label(index)} args are {size} chars, exceeding max_arg_chars={policy.max_arg_chars}"
                ),
                step_index=index,
                tool=step.tool,
                detail={"arg_chars": size, "max_arg_chars": policy.max_arg_chars},
            )
        ]
    return []


def _check_denied_arg_patterns(step: ToolCall, index: int, policy: Policy) -> list[Finding]:
    if not policy.denied_arg_patterns:
        return []
    try:
        rendered = json.dumps(step.args, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        rendered = str(step.args)
    findings: list[Finding] = []
    for pattern in policy.denied_arg_patterns:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid denied_arg_patterns regex {pattern!r}: {exc}") from exc
        match = regex.search(rendered)
        if match:
            findings.append(
                Finding(
                    rule_id="ARG002",
                    severity=Severity.HIGH,
                    verdict=Verdict.BLOCK,
                    message=(
                        f"{step.label(index)} args match denied pattern {pattern!r}"
                    ),
                    step_index=index,
                    tool=step.tool,
                    detail={"pattern": pattern, "match": match.group(0)},
                )
            )
    return findings


_PATH_ARG_KEYS = {
    "path",
    "paths",
    "file",
    "files",
    "filename",
    "filepath",
    "file_path",
    "dir",
    "directory",
    "cwd",
    "source",
    "destination",
    "target",
    "target_path",
}


def _check_paths(step: ToolCall, index: int, policy: Policy) -> list[Finding]:
    # Apply path rules to filesystem tools, or to any step that has obvious path args.
    tool_norm = step.tool.strip().lower()
