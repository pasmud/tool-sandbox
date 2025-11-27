# tool-sandbox

`tool-sandbox` is a small, deterministic sandbox policy checker for agent tool execution plans. It inspects a planned sequence of tool calls before execution and reports whether each step is allowed, flagged, or blocked by policy.

The goal is practical guardrails: catch obviously risky tool usage, out-of-scope paths, shell/network escapes, and suspicious argument patterns before an agent acts.

## Features

- **Plan validation**: parse execution plans from JSON files (or stdin) with clear schema errors.
- **Policy-driven checks**: allow/deny tool lists, shell and network controls, argument size limits, regex-based argument denies, and path prefix/pattern rules.
- **Deterministic reports**: stable JSON/text output with per-step findings, severities, and an overall verdict.
- **CLI-first**: `python -m tool_sandbox check ...` for CI or pre-execution gates.
- **Stdlib-only runtime**: no third-party runtime dependencies; tests run offline.

## Install

From the repository root:

