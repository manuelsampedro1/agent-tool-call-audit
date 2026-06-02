# AGENTS.md

## Scope

This repository contains `agent-tool-call-audit`, a dependency-free Python CLI
for auditing coding-agent tool-call logs.

## Rules

- Keep the project standard-library only.
- Do not execute commands from transcripts.
- Do not add network calls, telemetry, credentials, or hosted services.
- Redact secret-looking evidence in rendered output.
- Preserve Markdown and JSON output for humans and automation.
- Add tests whenever a new tool-call rule, parser field, or severity changes.

## Verification

Run these before closing relevant changes:

```sh
make test
make lint
make build
make smoke
```

For packaging changes, also verify editable install in a temporary virtual
environment before public promotion.

## Closeout

Report changed behavior, exact verification commands, residual risks, and any
rule limits that remain. Do not claim this tool is a sandbox or a complete
security audit.
