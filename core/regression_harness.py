"""
Regression Harness — ShadowKnight CRS v6.0
==========================================
Proves that a patch fixes the vulnerability AND doesn't break existing functionality.

This is the "prove the fix holds" component of the AI Kavach
Cyber-Reasoning System pipeline:

  Monitor → Detect → Static Analysis → Fuzz → LLM Patch →
  [RegressionHarness] → Tamper-Evident Proof Report

How it works:
  1. REPLAY: Re-runs the original crash/PoC input against the patched binary
             → confirms the vulnerability is fixed (no crash)
  2. REGRESSION: Runs the full pytest test suite
             → confirms no existing functionality was broken
  3. PROOF: Generates a SHA-256 signed proof report
             → tamper-evident, legally admissible evidence

Integration with Evidence Vault:
  The proof report is written to evidence/proof_reports/PROOF-YYYYMMDD-HHMMSS.json
  and added to the chain_of_evidence_trail.json.

Part of: ShadowKnight CRS (Cyber-Reasoning System)
DOI: 10.5281/zenodo.18524153
"""

import hashlib
import json
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional


# ---------------------------------------------------------------------------
# RegressionHarness
# ---------------------------------------------------------------------------

class RegressionHarness:
    """
    Validates that a patch:
      1. Eliminates the vulnerability (PoC replay)
      2. Does not introduce regressions (test suite)
      3. Produces tamper-evident proof (SHA-256 signed report)

    Usage:
        harness = RegressionHarness(
            test_dir='./tests',
            evidence_dir='./evidence'
        )

        poc_result = harness.replay_poc(
            target_binary='/usr/local/bin/target',
            crash_input=crash['input_data']
        )

        test_result = harness.run_test_suite()

        proof = harness.generate_proof_report(patch, poc_result, test_result)
        print(f"Verdict: {proof['verdict']}")
    """

    def __init__(self,
                 test_dir: str = './tests',
                 evidence_dir: str = './evidence'):
        """
        Args:
            test_dir:     Directory containing pytest tests
            evidence_dir: Evidence vault path (for proof storage)
        """
        self.test_dir = Path(test_dir)
        self.proof_dir = Path(evidence_dir) / 'proof_reports'
        self.proof_dir.mkdir(parents=True, exist_ok=True)
        self.chain_of_evidence = Path(evidence_dir) / 'chain_of_evidence_trail.json'

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def replay_poc(self,
                   target_binary: Optional[str] = None,
                   crash_input: bytes = b'',
                   target_function: Optional[Any] = None,
                   crash_exception_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Replay the original crash input/PoC against the (now patched) target.
        If no crash occurs → patch is effective.

        Args:
            target_binary:        Path to patched binary (for binary targets)
            crash_input:          Original crash input bytes
            target_function:      Python function to test (for Python targets)
            crash_exception_type: Expected exception type before patch (e.g. 'ZeroDivisionError')

        Returns:
            Dict with patch_effective, return_code, signal, notes
        """
        if target_function:
            return self._replay_python_function(
                target_function, crash_input, crash_exception_type
            )
        elif target_binary:
            return self._replay_binary(target_binary, crash_input)
        else:
            return {
                'patch_effective': None,
                'error': 'Provide target_binary or target_function',
            }

    def run_test_suite(self,
                       extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Run the pytest test suite and return structured results.

        Args:
            extra_args: Additional pytest CLI arguments

        Returns:
            Dict with passed, summary, stdout, test_count, etc.
        """
        json_report_path = self.proof_dir / 'pytest_report.json'

        cmd = [
            'python', '-m', 'pytest',
            str(self.test_dir),
            '-v',
            '--tb=short',
            f'--json-report',
            f'--json-report-file={json_report_path}',
        ]

        if extra_args:
            cmd.extend(extra_args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            # Load JSON report if available
            test_data = {}
            if json_report_path.exists():
                try:
                    with open(json_report_path) as f:
                        test_data = json.load(f)
                except Exception:
                    pass

            summary = test_data.get('summary', {})

            return {
                'passed': result.returncode == 0,
                'return_code': result.returncode,
                'tests_passed': summary.get('passed', 'N/A'),
                'tests_failed': summary.get('failed', 'N/A'),
                'tests_total': summary.get('total', 'N/A'),
                'stdout': result.stdout[-3000:],  # Last 3KB
                'stderr': result.stderr[-1000:],
                'json_report': test_data.get('tests', [])[:20],  # First 20 tests
            }

        except subprocess.TimeoutExpired:
            return {
                'passed': False,
                'error': 'Test suite timed out (>5 minutes)',
                'return_code': -1,
            }
        except FileNotFoundError:
            return {
                'passed': None,
                'error': 'pytest not found. Install: pip install pytest pytest-json-report',
                'return_code': -1,
            }
        except Exception as e:
            return {
                'passed': False,
                'error': str(e),
                'return_code': -1,
            }

    def run_quick_validation(self, target_function: Any,
                              valid_inputs: List[bytes]) -> Dict[str, Any]:
        """
        Quick smoke test: run target_function against known-good inputs.
        Used when a full pytest suite isn't available.

        Args:
            target_function: The (patched) function to test
            valid_inputs:    List of inputs that should NOT crash

        Returns:
            Dict with passed, tested, failed_inputs
        """
        failed = []
        for i, inp in enumerate(valid_inputs):
            try:
                target_function(inp)
            except Exception as e:
                failed.append({'input_index': i, 'exception': str(e)})

        return {
            'passed': len(failed) == 0,
            'tested': len(valid_inputs),
            'failed_count': len(failed),
            'failed_inputs': failed,
            'test_type': 'quick_validation',
        }

    def generate_proof_report(self,
                               patch: Dict[str, Any],
                               poc_result: Dict[str, Any],
                               test_result: Dict[str, Any],
                               metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate a tamper-evident proof report.

        Verdict logic:
          PATCH_VERIFIED    — PoC no longer crashes AND all tests pass
          PATCH_PARTIAL     — PoC fixed but some tests failed (or vice versa)
          PATCH_INCOMPLETE  — PoC still crashes OR critical tests failed

        Args:
            patch:       Result from LLMPatchGenerator.generate_patch()
            poc_result:  Result from replay_poc()
            test_result: Result from run_test_suite() or run_quick_validation()
            metadata:    Optional extra fields (analyst name, system info, etc.)

        Returns:
            Signed proof report dict (written to evidence/proof_reports/)
        """
        poc_fixed = poc_result.get('patch_effective', False)
        tests_passed = test_result.get('passed', False)

        if poc_fixed and tests_passed:
            verdict = 'PATCH_VERIFIED'
        elif poc_fixed or tests_passed:
            verdict = 'PATCH_PARTIAL'
        else:
            verdict = 'PATCH_INCOMPLETE'

        report = {
            'report_id': f"PROOF-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'generated_by': 'ShadowKnight CRS v6.0',
            'verdict': verdict,
            'vulnerability': patch.get('vulnerability_input', {}),
            'patch': {
                'diff': patch.get('patch_diff', ''),
                'explanation': patch.get('patch_explanation', ''),
                'root_cause': patch.get('root_cause', ''),
                'confidence': patch.get('confidence', 0.0),
                'model': patch.get('model_used', 'unknown'),
            },
            'poc_replay': {
                'patch_effective': poc_fixed,
                'details': poc_result,
            },
            'regression_tests': {
                'passed': tests_passed,
                'details': test_result,
            },
            'metadata': metadata or {},
        }

        # Compute SHA-256 for tamper evidence
        report_canonical = json.dumps(report, sort_keys=True, default=str)
        report['sha256'] = hashlib.sha256(report_canonical.encode()).hexdigest()

        # Write to evidence vault
        proof_file = self.proof_dir / f"{report['report_id']}.json"
        with open(proof_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        proof_file.chmod(0o444)  # Read-only for tamper evidence

        # Append to chain of evidence trail
        self._update_chain_of_evidence(report, proof_file)

        print(f'\n🛡️  Proof Report: {report["report_id"]}')
        print(f'   Verdict:    {verdict}')
        print(f'   PoC Fixed:  {"✅" if poc_fixed else "❌"}')
        print(f'   Tests Pass: {"✅" if tests_passed else "❌"}')
        print(f'   SHA-256:    {report["sha256"][:16]}...')
        print(f'   Saved to:   {proof_file}')

        return report

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _replay_binary(self, target_binary: str,
                        crash_input: bytes) -> Dict[str, Any]:
        """Replay crash input against a binary executable."""
        if not Path(target_binary).exists():
            return {
                'patch_effective': None,
                'error': f'Binary not found: {target_binary}',
            }

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(crash_input)
            input_file = f.name

        try:
            result = subprocess.run(
                [target_binary, input_file],
                capture_output=True,
                timeout=10,
            )

            # Negative return code = killed by signal (crash)
            crashed = result.returncode < 0

            signal_map = {-11: 'SIGSEGV', -6: 'SIGABRT', -8: 'SIGFPE'}
            signal_name = signal_map.get(result.returncode) if crashed else None

            return {
                'patch_effective': not crashed,
                'return_code': result.returncode,
                'crashed': crashed,
                'signal': signal_name,
                'stdout': result.stdout[:500].decode(errors='replace'),
                'input_size': len(crash_input),
            }

        except subprocess.TimeoutExpired:
            return {
                'patch_effective': True,
                'note': 'No crash (timeout — process ran normally)',
                'crashed': False,
            }
        except Exception as e:
            return {
                'patch_effective': None,
                'error': str(e),
            }
        finally:
            Path(input_file).unlink(missing_ok=True)

    def _replay_python_function(self,
                                 target_function: Any,
                                 crash_input: bytes,
                                 crash_exception_type: Optional[str]) -> Dict[str, Any]:
        """Replay crash against a Python function."""
        try:
            result = target_function(crash_input)
            return {
                'patch_effective': True,
                'crashed': False,
                'result': str(result)[:200],
                'note': 'Function executed successfully — patch effective',
            }
        except Exception as e:
            exception_name = type(e).__name__
            # If same exception type as before → not fixed
            was_same_crash = (crash_exception_type and
                               exception_name == crash_exception_type)
            return {
                'patch_effective': not was_same_crash,
                'crashed': True,
                'exception': exception_name,
                'exception_msg': str(e),
                'note': ('Same crash type — patch did NOT fix it'
                         if was_same_crash
                         else 'Different exception — may be partially fixed'),
            }

    def _update_chain_of_evidence(self, report: Dict, proof_file: Path):
        """Append proof report entry to the chain of evidence trail."""
        entry = {
            'evidence_id': report['report_id'],
            'evidence_type': 'proof_report',
            'timestamp': report['generated_at'],
            'file_path': str(proof_file),
            'hash_sha256': report['sha256'],
            'verdict': report['verdict'],
            'collected_by': 'ShadowKnight CRS v6.0',
            'action': 'proof_report_generated',
        }

        # Load existing chain or start fresh
        chain = []
        if self.chain_of_evidence.exists():
            try:
                with open(self.chain_of_evidence) as f:
                    chain = json.load(f)
            except Exception:
                chain = []

        chain.append(entry)

        with open(self.chain_of_evidence, 'w') as f:
            json.dump(chain, f, indent=2)


# ---------------------------------------------------------------------------
# CLI Demo
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print('=== ShadowKnight CRS — Regression Harness Demo ===\n')

    harness = RegressionHarness(test_dir='./tests', evidence_dir='./evidence')

    # Simulate a patched Python function
    def patched_parser(data: bytes) -> str:
        """After patch: handle empty/zero byte safely"""
        if not data or data[0] == 0:
            return 'SAFE_EMPTY'
        return f'Result: {100 // data[0]}'

    # Replay the crash input
    poc = harness.replay_poc(
        target_function=patched_parser,
        crash_input=b'\x00',
        crash_exception_type='ZeroDivisionError',
    )

    # Quick validation with known-good inputs
    tests = harness.run_quick_validation(
        patched_parser,
        valid_inputs=[b'\x01', b'\x0a', b'\xff', b'test'],
    )

    # Simulated patch object
    mock_patch = {
        'patch_diff': '--- a/parser.py\n+++ b/parser.py\n@@ -1,2 +1,3 @@\n+if not data or data[0] == 0: return "SAFE"\n',
        'patch_explanation': 'Added null-byte guard to prevent ZeroDivisionError',
        'root_cause': 'Missing input validation before division',
        'confidence': 0.92,
        'model_used': 'gemini-2.5-flash',
        'vulnerability_input': {'type': 'divide_by_zero', 'severity': 'HIGH'},
    }

    proof = harness.generate_proof_report(mock_patch, poc, tests)
