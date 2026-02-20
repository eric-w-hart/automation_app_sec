import os
import json
import subprocess
from typing import List, Dict, Any
from pathlib import Path
from openai import OpenAI

#------------------------------------
# Security Agent
# NOTE: This is probabalistic will NOT replace traditional SAST scanners, needs strict JSON validation and should be sandboxed.
#------------------------------------

class SecurityAgent:
    """
    AI-powered security scanning agent for CI/CD pipelines.
    Performs:
        - AI-based SAST scanning
        - Dependency vulnerability scanning (SCA)
    """

    def __init__(self, openai_api_key: str, severity_threshold: str = "HIGH") -> None:
        self.client = OpenAI(api_key=openai_api_key)
        self.severity_threshold = severity_threshold
        self.severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

    # ------------------------
    # SAST (AI-based analysis)
    # ------------------------
    def run_sast(self, source_code: str) -> List[Dict[str, Any]]:
        """
        Use an LLM to analyze code for security vulnerabilities.
        Returns structured vulnerability findings.
        """
        prompt = f"""
        You are a senior application security engineer.
        Analyze the following code for security vulnerabilities.

        Return JSON list with:
        - type
        - severity (LOW, MEDIUM, HIGH, CRITICAL)
        - description
        - recommendation
        - line_number (if available)

        Code:
        {source_code}
        """

        response = self.client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )

        try:
            findings = json.loads(response.choices[0].message.content)
        except json.JSONDecodeError:
            findings = []

        return findings

    # ------------------------
    # SCA (Dependency scanning)
    # ------------------------
    def run_sca(self) -> List[Dict[str, Any]]:
        """
        Run pip-audit to detect vulnerable dependencies.
        """
        result = subprocess.run(
            ["pip-audit", "-f", "json"],
            capture_output=True,
            text=True
        )

        if result.returncode not in [0, 1]:
            raise RuntimeError("pip-audit failed")

        try:
            audit_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for dep in audit_data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                findings.append({
                    "type": "Dependency Vulnerability",
                    "package": dep["name"],
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "description": vuln.get("description", ""),
                    "recommendation": f"Upgrade to {vuln.get('fix_versions')}"
                })

        return findings

    # ------------------------
    # Severity Evaluation
    # ------------------------
    def should_fail_pipeline(self, findings: List[Dict[str, Any]]) -> bool:
        threshold_index = self.severity_order.index(self.severity_threshold)

        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity in self.severity_order:
                if self.severity_order.index(severity) >= threshold_index:
                    return True

        return False


def load_repository_code(repo_path: str) -> str:
    """
    Load all Python files from repository into a single string.
    """
    code = []
    for path in Path(repo_path).rglob("*.py"):
        code.append(path.read_text())

    return "\n\n".join(code)


def main():
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        raise EnvironmentError("OPENAI_API_KEY not set")

    agent = SecurityAgent(openai_api_key)

    print("Running SAST...")
    source_code = load_repository_code(".")
    sast_findings = agent.run_sast(source_code)

    print("Running SCA...")
    sca_findings = agent.run_sca()

    all_findings = sast_findings + sca_findings

    print(json.dumps(all_findings, indent=2))

    if agent.should_fail_pipeline(all_findings):
        print("❌ Security threshold exceeded. Failing pipeline.")
        exit(1)

    print("✅ Security checks passed.")
    exit(0)


if __name__ == "__main__":
    main()