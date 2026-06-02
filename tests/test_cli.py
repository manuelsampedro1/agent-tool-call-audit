import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_tool_call_audit import cli


SAFE_LOG = """{"tool":"functions.exec_command","args":{"cmd":"make test","workdir":"/repo"},"exit_code":0}
{"tool":"functions.exec_command","args":{"cmd":"make lint","workdir":"/repo"},"exit_code":0}
"""

RISKY_LOG = """{"tool":"functions.exec_command","args":{"cmd":"git reset --hard HEAD~1","workdir":"/repo"},"exit_code":0}
{"tool":"gmail._send_email","args":{"to":"reviewer@example.com","body":"hello"},"status":"success"}
{"tool":"functions.exec_command","args":{"cmd":"npm test","workdir":"/repo"},"exit_code":1}
{"tool":"functions.exec_command","args":{"cmd":"npm test","workdir":"/repo"},"exit_code":1}
"""

SECRET_LOG = """{"tool":"functions.exec_command","args":{"cmd":"printenv","workdir":"/repo"},"stdout":"OPENAI_API_KEY=[redacted-value]"}
"""


class TestAgentToolCallAudit(unittest.TestCase):
    def test_safe_log_passes(self):
        report = cli.audit_calls(cli.parse_log(SAFE_LOG))
        self.assertEqual(report.status, "pass")
        self.assertEqual(report.findings, [])
        self.assertEqual(report.score, 100)

    def test_detects_destructive_command_sensitive_tool_and_repeated_failure(self):
        report = cli.audit_calls(cli.parse_log(RISKY_LOG))
        rules = {finding.rule for finding in report.findings}
        self.assertIn("destructive-git", rules)
        self.assertIn("sensitive-tool", rules)
        self.assertIn("repeated-failure", rules)
        self.assertEqual(report.repeated_failures["npm test"], 2)
        self.assertEqual(report.status, "block")

    def test_detects_secret_marker_and_redacts_evidence(self):
        report = cli.audit_calls(cli.parse_log(SECRET_LOG))
        finding = report.findings[0]
        self.assertEqual(finding.rule, "secret-marker")
        self.assertIn("[secret-marker]", finding.evidence)

    def test_plain_text_fallback(self):
        text = 'TOOL functions.exec_command cmd="git push --force" exit_code=0'
        report = cli.audit_calls(cli.parse_log(text))
        self.assertEqual(report.findings[0].rule, "force-push")

    def test_json_output_and_failure_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "calls.jsonl"
            path.write_text(RISKY_LOG, encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main([str(path), "--format", "json", "--fail-on", "high"])
            self.assertEqual(code, 1)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["status"], "block")

    def test_missing_workdir_is_low_severity(self):
        log = '{"tool":"functions.exec_command","args":{"cmd":"make test"},"exit_code":0}'
        report = cli.audit_calls(cli.parse_log(log))
        self.assertEqual(report.findings[0].rule, "missing-workdir")
        self.assertEqual(report.findings[0].severity, "low")


if __name__ == "__main__":
    unittest.main()
