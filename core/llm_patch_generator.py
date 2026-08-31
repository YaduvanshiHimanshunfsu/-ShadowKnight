"""
LLM Patch Generator — ShadowKnight CRS v6.0
=============================================
Autonomously generates security patches using Gemini 2.5 Flash.

This is the "autonomously patches it" component of the AI Kavach
Cyber-Reasoning System pipeline:

  Monitor → Detect → [Static/Dynamic Analysis] → [Fuzz] →
  [LLM Patch Generator] → [Regression Harness] → Report

Architecture:
  1. Receives a structured vulnerability report (from StaticVulnerabilityScanner
     or FuzzerHarness crash analysis)
  2. Builds an expert-level security prompt for Gemini
  3. Parses the LLM response into a unified diff patch
  4. Optionally applies the patch to disk (requires `patch` utility)
  5. Returns a rich result object for the regression harness

Part of: ShadowKnight CRS (Cyber-Reasoning System)
DOI: 10.5281/zenodo.18524153
"""

import json
import subprocess
import tempfile
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

import google.generativeai as genai


# ---------------------------------------------------------------------------
# Prompt Engineering
# ---------------------------------------------------------------------------

PATCH_GENERATION_PROMPT = """
You are a senior security engineer with expertise in:
- Memory safety vulnerabilities (buffer overflows, UAF, format strings)
- Python security (injection, insecure deserialization, path traversal)
- Configuration hardening (privilege escalation, weak permissions)
- OWASP Top 10 and CWE categories

You have been given the following vulnerability discovered by automated analysis:

=== VULNERABILITY REPORT ===
File:        {file_path}
Type:        {vuln_type}
Severity:    {severity}
Tool:        {tool_source}
Description: {description}
CWE:         {cwe}

Vulnerable Code:
```
{vulnerable_code}
```

=== TASK ===
1. Perform root-cause analysis
2. Generate a MINIMAL, SAFE, backward-compatible patch in unified diff format
3. Explain the patch and why it eliminates the vulnerability
4. Provide a unit test that proves the vulnerability is fixed
5. Note any edge cases or limitations

Respond ONLY with a valid JSON object (no markdown fences in the root):
{{
  "root_cause": "Concise explanation of WHY this is vulnerable",
  "patch_diff": "--- a/original\\n+++ b/patched\\n@@ -N,M +N,M @@\\n ...",
  "patch_explanation": "What the patch does and why it's secure",
  "cwe_id": "CWE-XXX",
  "cve_similar": ["CVE-YYYY-NNNNN or None"],
  "mitre_attack_ttps": ["T1xxx.xxx"],
  "confidence": 0.0,
  "test_case": "def test_patch():\\n    # Python code to verify patch\\n    pass",
  "caveats": ["Any edge cases or limitations of this patch"]
}}
"""


# ---------------------------------------------------------------------------
# LLMPatchGenerator Class
# ---------------------------------------------------------------------------

class LLMPatchGenerator:
    """
    Generates security patches autonomously using Gemini 2.5 Flash.

    Usage:
        generator = LLMPatchGenerator(api_key="AIza...")
        result = generator.generate_patch(vulnerability_dict)
        if result['confidence'] > 0.7:
            generator.apply_patch(result['patch_diff'], 'target/file.py')
    """

    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        """
        Args:
            api_key:    Google Gemini API key
            model_name: Gemini model to use (flash for speed)
        """
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(model_name)
        self.model_name = model_name
        self._patch_history: list = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_patch(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a security patch for a given vulnerability.

        Args:
            vulnerability: Dict with keys:
                - file (str): path to vulnerable file
                - type (str): vulnerability type (e.g. 'buffer_overflow')
                - severity (str): CRITICAL|HIGH|MEDIUM|LOW
                - description (str): human-readable description
                - code (str): the vulnerable code snippet
                - cwe (str, optional): CWE ID
                - tool_source (str, optional): scanner that found this

        Returns:
            Dict with patch_diff, explanation, confidence, test_case, etc.
        """
        prompt = PATCH_GENERATION_PROMPT.format(
            file_path=vulnerability.get('file', 'unknown'),
            vuln_type=vulnerability.get('type', 'unknown'),
            severity=vulnerability.get('severity', 'UNKNOWN'),
            tool_source=vulnerability.get('tool_source', 'automated_analysis'),
            description=vulnerability.get('description', 'No description provided'),
            cwe=vulnerability.get('cwe', 'Unknown'),
            vulnerable_code=vulnerability.get('code', 'Code not available'),
        )

        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()

            # Strip markdown code fences if present
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]

            result = json.loads(response_text.strip())

            # Enrich result with metadata
            result['vulnerability_input'] = vulnerability
            result['generated_at'] = datetime.now().isoformat()
            result['model_used'] = self.model_name
            result['generation_success'] = True

            # Track history
            self._patch_history.append(result)

            return result

        except json.JSONDecodeError as e:
            return self._error_result(vulnerability, f"JSON parse error: {e}")
        except Exception as e:
            return self._error_result(vulnerability, str(e))

    def apply_patch(self, patch_diff: str, target_file: str,
                    dry_run: bool = False) -> Dict[str, Any]:
        """
        Apply a unified diff patch to a target file.

        Args:
            patch_diff: Unified diff string (from generate_patch)
            target_file: Path to the file to patch
            dry_run: If True, test the patch without applying it

        Returns:
            Dict with success, return_code, output
        """
        if not Path(target_file).exists():
            return {'success': False, 'error': f'File not found: {target_file}'}

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.patch', delete=False
        ) as f:
            f.write(patch_diff)
            patch_file = f.name

        cmd = ['patch']
        if dry_run:
            cmd.append('--dry-run')
        cmd.extend(['-p1', target_file, patch_file])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            return {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'dry_run': dry_run,
                'target_file': target_file,
            }
        except FileNotFoundError:
            return {
                'success': False,
                'error': '`patch` utility not found. Install with: apt install patch',
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Patch application timed out'}
        finally:
            Path(patch_file).unlink(missing_ok=True)

    def batch_patch(self, vulnerabilities: list) -> list:
        """
        Process multiple vulnerabilities in sequence.

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            List of patch results
        """
        results = []
        for vuln in vulnerabilities:
            result = self.generate_patch(vuln)
            results.append(result)
        return results

    def get_patch_history(self) -> list:
        """Return list of all patches generated in this session."""
        return self._patch_history

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _error_result(self, vulnerability: Dict, error_msg: str) -> Dict:
        """Return a structured error result."""
        return {
            'generation_success': False,
            'error': error_msg,
            'root_cause': 'Analysis failed — manual review required',
            'patch_diff': '',
            'patch_explanation': '',
            'confidence': 0.0,
            'test_case': '',
            'caveats': ['Automated patch generation failed'],
            'vulnerability_input': vulnerability,
            'generated_at': datetime.now().isoformat(),
            'model_used': self.model_name,
        }


# ---------------------------------------------------------------------------
# CLI Entrypoint (for testing)
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import os

    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print('❌ Set GEMINI_API_KEY environment variable')
        exit(1)

    generator = LLMPatchGenerator(api_key)

    # Example: SQL injection in a Python web handler
    sample_vuln = {
        'file': 'app/handlers/user.py',
        'type': 'sql_injection',
        'severity': 'CRITICAL',
        'description': 'User input directly concatenated into SQL query without sanitization',
        'cwe': 'CWE-89',
        'tool_source': 'bandit',
        'code': '''
def get_user(username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
'''
    }

    print('🔧 Generating patch...')
    result = generator.generate_patch(sample_vuln)

    if result['generation_success']:
        print(f"✅ Patch generated (confidence: {result['confidence']:.2f})")
        print(f"📋 Root cause: {result['root_cause']}")
        print(f"\n📄 Patch diff:\n{result['patch_diff']}")
        print(f"\n🧪 Test case:\n{result['test_case']}")
    else:
        print(f"❌ Failed: {result['error']}")
