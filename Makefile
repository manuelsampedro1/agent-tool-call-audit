.PHONY: test lint build smoke

test:
	PYTHONPATH=src python3 -m unittest discover -s tests

lint:
	python3 -m py_compile src/agent_tool_call_audit/*.py tests/*.py

build:
	python3 -m compileall -q src tests

smoke:
	PYTHONPATH=src python3 -m agent_tool_call_audit examples/tool-calls.jsonl --min-score 0
	PYTHONPATH=src python3 -m agent_tool_call_audit examples/tool-calls.jsonl --format json --fail-on high >/tmp/agent-tool-call-audit-smoke.json || test $$? -eq 1
	PYTHONPATH=src python3 -m agent_tool_call_audit examples/tool-calls.jsonl --require-approval --fail-on high >/tmp/agent-tool-call-audit-approval-smoke.txt || test $$? -eq 1
