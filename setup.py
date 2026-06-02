from setuptools import find_packages, setup


setup(
    name="agent-tool-call-audit",
    version="0.1.0",
    description="Audit coding-agent tool-call logs for risky actions and repeated failures.",
    packages=find_packages("src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "agent-tool-call-audit=agent_tool_call_audit.cli:main",
        ],
    },
)
