# agent-tool-call-audit

Audit coding-agent tool-call logs for risky actions, repeated failures, and
missing review signals before a run is accepted as safe.

The tool is intentionally narrow. It does not execute commands, inspect private
systems, or require a hosted service. It reads JSONL or plain-text transcripts
and reports deterministic findings a reviewer can inspect.

## Why

Preflight guards are useful, but agent runs also need post-run review. A session
can include destructive shell commands, sensitive tool calls, repeated failed
attempts, or secret-looking material even when the final answer sounds careful.

Use this before:

- accepting a long coding-agent run,
- importing tool-call history into a run ledger,
- reusing command output as closeout evidence,
- investigating why an agent kept retrying the same failing action.

## Install

```sh
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install -e .
```

## Usage

Audit a saved JSONL transcript:

```sh
agent-tool-call-audit examples/tool-calls.jsonl --fail-on high
```

JSON output for automation:

```sh
agent-tool-call-audit examples/tool-calls.jsonl --format json --min-score 80
```

Plain-text logs are supported as a fallback:

```sh
agent-tool-call-audit examples/tool-calls.txt --fail-on medium
```

Require approval evidence for sensitive external actions:

```sh
agent-tool-call-audit examples/tool-calls.jsonl --require-approval --fail-on high
```

## Input Shape

JSONL records can use any of these common field names:

- `tool`, `name`, or `recipient_name` for the tool name,
- `args`, `input`, `parameters`, or `arguments` for tool input,
- `result`, `output`, `stdout`, or `stderr` for tool output,
- `exit_code`, `returncode`, `status`, or `error` for outcome.

The parser is permissive so it can handle Codex-style, MCP-style, and
homegrown run logs.

When `--require-approval` is enabled, sensitive tool calls and external action
commands need explicit approval evidence in the log. The audit recognizes
fields or text such as `approval_receipt`, `permission_receipt`,
`authorization_receipt`, `approved_by`, `authorized_by`, `human_approved: true`,
or `approved: true`.

## What It Detects

- Destructive shell commands such as force pushes, hard resets, broad deletes,
  `sudo`, unsafe install pipes, and dangerous chmod patterns.
- Sensitive tool names such as send, delete, deploy, publish, payment, and
  credential actions.
- Repeated failed commands or tool calls.
- Tool input or output that appears to contain secret material markers.
- Shell commands without a working directory in structured logs.
- Bypass language such as skipping hooks or ignoring safety checks.
- Missing approval or receipt evidence for sensitive external actions when
  `--require-approval` is enabled.

## Output

Markdown output includes:

- overall status and score,
- approval-required and approval-evidence call counts,
- finding severity, rule, tool name, and reason,
- redacted evidence snippets,
- repeated-failure counts,
- reviewer follow-up checks.

JSON output exposes the same data for CI gates, proof packets, or run ledgers.

## Limits

- This is not a sandbox or permission system.
- This does not prove a command executed safely.
- Plain-text parsing is best-effort; JSONL gives better evidence.
- A clean report means no configured tool-call risk was detected, not that the
  run is harmless.

## Verify

```sh
make test
make lint
make build
make smoke
```
