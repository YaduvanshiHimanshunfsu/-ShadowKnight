"""
Fuzzer Harness — ShadowKnight CRS v6.0
=======================================
Wraps AFL++ for autonomous vulnerability discovery.

This module is the "fuzzer" leg of the AI Kavach
Cyber-Reasoning System pipeline:

  Monitor → Detect → Static Analysis → [FuzzerHarness] →
  LLM Patch Generator → Regression Harness → Report

Design:
  - Manages AFL++ fuzzing sessions as subprocess
  - Parses crash/hang output files
  - Feeds crash context to Gemini for root-cause analysis
  - Supports both network (port fuzzing) and file-based fuzzing
  - Air-gap safe: all local, no external calls

Fallback (when AFL++ not installed):
  - Lightweight Python-based mutational fuzzer
  - Sufficient for demo/proof-of-concept
  - No external binary required

Part of: ShadowKnight CRS (Cyber-Reasoning System)
DOI: 10.5281/zenodo.18524153
"""

import os
import random
import shutil
import subprocess
import tempfile
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable
import threading
import time


# ---------------------------------------------------------------------------
# FuzzerHarness
# ---------------------------------------------------------------------------

class FuzzerHarness:
    """
    Manages fuzzing sessions and crash analysis.

    Two modes:
      1. AFL++ mode: wraps the external afl-fuzz binary
      2. Python fuzzer mode: built-in mutational fuzzer (fallback)

    After each session, crashes are parsed and fed to
    LLMPatchGenerator for autonomous patch generation.

    Usage (AFL++ mode):
        harness = FuzzerHarness(mode='afl')
        result = harness.run_session(
            target_binary='/usr/local/bin/target',
            seed_corpus='./seeds/',
            timeout_seconds=300
        )
        for crash in result['crashes']:
            patch = patch_gen.generate_patch(
                harness.build_vulnerability_report(crash, '/src/target.c')
            )

    Usage (Python fallback):
        harness = FuzzerHarness(mode='python')
        result = harness.run_session(
            target_function=my_parse_function,
            seed_inputs=[b'valid_input_1', b'valid_input_2'],
            timeout_seconds=60
        )
    """

    def __init__(self,
                 mode: str = 'auto',
                 workspace: str = './fuzzer_workspace',
                 afl_path: str = 'afl-fuzz'):
        """
        Args:
            mode:      'afl' | 'python' | 'auto' (auto-detects AFL++)
            workspace: Directory for fuzzer output / crash files
            afl_path:  Path to afl-fuzz binary
        """
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.afl_path = afl_path

        if mode == 'auto':
            self.mode = 'afl' if shutil.which(afl_path) else 'python'
        else:
            self.mode = mode

        print(f'✅ [FuzzerHarness] Mode: {self.mode.upper()}')
        if self.mode == 'python':
            print('   (Install AFL++ for advanced fuzzing: apt install afl++)')

        self.sessions: List[Dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_session(self,
                    target_binary: Optional[str] = None,
                    seed_corpus: Optional[str] = None,
                    target_function: Optional[Callable] = None,
                    seed_inputs: Optional[List[bytes]] = None,
                    timeout_seconds: int = 300) -> Dict[str, Any]:
        """
        Run a fuzzing session.

        AFL++ mode: target_binary + seed_corpus required
        Python mode: target_function + seed_inputs required (or target_binary)

        Returns:
            session_result dict with crashes, hangs, stats
        """
        session_id = f"FUZZ-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        print(f'⚡ [FuzzerHarness] Starting session: {session_id}')

        if self.mode == 'afl' and target_binary and seed_corpus:
            result = self._run_afl_session(
                session_id, target_binary, seed_corpus, timeout_seconds
            )
        elif self.mode == 'python' and target_function:
            result = self._run_python_fuzzer(
                session_id, target_function,
                seed_inputs or [b'test', b'A' * 100, b'\x00' * 64],
                timeout_seconds
            )
        elif target_binary and self.mode == 'python':
            # Fuzz a binary using Python subprocess
            result = self._run_binary_python_fuzzer(
                session_id, target_binary,
                seed_inputs or [b'test', b'A' * 256, b'\xff' * 64],
                timeout_seconds
            )
        else:
            return {
                'session_id': session_id,
                'error': 'Invalid configuration: provide target_binary+seed_corpus or target_function',
                'crashes': [],
            }

        self.sessions.append(result)
        return result

    def build_vulnerability_report(self,
                                    crash: Dict,
                                    source_file: str = '') -> Dict[str, Any]:
        """
        Build a vulnerability report from a crash dict for LLMPatchGenerator.

        Args:
            crash:       Crash dict from session results
            source_file: Path to the source file of the target binary

        Returns:
            Vulnerability dict compatible with LLMPatchGenerator.generate_patch()
        """
        code_snippet = ''
        if source_file and Path(source_file).exists():
            try:
                with open(source_file, 'r', errors='replace') as f:
                    code_snippet = f.read()[:3000]  # First 3KB
            except Exception:
                pass

        return {
            'file': source_file or crash.get('target', 'unknown'),
            'type': crash.get('crash_type', 'crash_or_buffer_overflow'),
            'severity': 'CRITICAL' if crash.get('signal') == 'SIGSEGV' else 'HIGH',
            'description': (
                f"Fuzzer discovered crash. Signal: {crash.get('signal', 'unknown')}. "
                f"Input size: {crash.get('size', 'unknown')} bytes. "
                f"Input hex preview: {crash.get('hex_preview', '')}. "
                f"Iterations: {crash.get('iteration', 'N/A')}"
            ),
            'cwe': 'CWE-121' if 'overflow' in crash.get('crash_type', '') else 'CWE-125',
            'tool_source': f'fuzzer_{self.mode}',
            'code': code_snippet,
            'crash_input_hex': crash.get('hex_preview', ''),
        }

    def get_all_crashes(self) -> List[Dict]:
        """Return all crashes from all sessions."""
        crashes = []
        for session in self.sessions:
            crashes.extend(session.get('crashes', []))
        return crashes

    # ------------------------------------------------------------------
    # AFL++ Mode
    # ------------------------------------------------------------------

    def _run_afl_session(self, session_id: str,
                          target_binary: str,
                          seed_corpus: str,
                          timeout_seconds: int) -> Dict[str, Any]:
        """Run AFL++ fuzzing session."""
        output_dir = self.workspace / session_id

        cmd = [
            self.afl_path,
            '-i', seed_corpus,
            '-o', str(output_dir),
            '-t', '1000',          # 1s per test case
            '-m', 'none',          # No memory limit
            '--',
            target_binary, '@@'    # @@ = input file placeholder
        ]

        try:
            process = subprocess.run(
                cmd,
                timeout=timeout_seconds,
                capture_output=True,
                text=True,
            )
            completed = True
        except subprocess.TimeoutExpired:
            completed = False  # Normal — fuzzer was stopped by timeout

        crashes = self._parse_afl_crashes(output_dir / 'default' / 'crashes')
        hangs = self._parse_afl_crashes(output_dir / 'default' / 'hangs')
        stats = self._parse_afl_stats(output_dir / 'default' / 'fuzzer_stats')

        result = {
            'session_id': session_id,
            'mode': 'afl',
            'target': target_binary,
            'crashes_found': len(crashes),
            'hangs_found': len(hangs),
            'crashes': crashes,
            'hangs': hangs,
            'stats': stats,
            'completed': completed,
            'output_dir': str(output_dir),
        }

        print(f'✅ [AFL++] Session done: {len(crashes)} crashes, {len(hangs)} hangs')
        return result

    def _parse_afl_crashes(self, crashes_dir: Path) -> List[Dict]:
        """Parse AFL++ crash output files."""
        crashes = []
        if not crashes_dir or not crashes_dir.exists():
            return crashes

        for crash_file in sorted(crashes_dir.iterdir()):
            name = crash_file.name
            if not name.startswith('id:'):
                continue

            try:
                data = crash_file.read_bytes()
                # Extract signal info from filename: id:000000,sig:11,...
                sig_num = None
                for part in name.split(','):
                    if part.startswith('sig:'):
                        sig_num = int(part.split(':')[1])
                        break

                signal_name = {
                    11: 'SIGSEGV',
                    6: 'SIGABRT',
                    8: 'SIGFPE',
                    4: 'SIGILL',
                }.get(sig_num, f'SIG{sig_num}' if sig_num else 'UNKNOWN')

                crashes.append({
                    'crash_id': name,
                    'signal': signal_name,
                    'signal_num': sig_num,
                    'size': len(data),
                    'hex_preview': data[:32].hex(),
                    'crash_type': (
                        'buffer_overflow' if signal_name == 'SIGSEGV'
                        else 'assertion_failure' if signal_name == 'SIGABRT'
                        else 'divide_by_zero' if signal_name == 'SIGFPE'
                        else 'crash'
                    ),
                    'input_data': data[:512],  # First 512 bytes for LLM
                })
            except Exception:
                pass

        return crashes

    def _parse_afl_stats(self, stats_file: Path) -> Dict:
        """Parse AFL++ fuzzer_stats file."""
        stats = {}
        if not stats_file or not stats_file.exists():
            return stats

        try:
            content = stats_file.read_text()
            for line in content.splitlines():
                if ':' in line:
                    key, _, value = line.partition(':')
                    stats[key.strip()] = value.strip()
        except Exception:
            pass

        return {
            'execs_per_sec': stats.get('execs_per_sec', 'N/A'),
            'total_execs': stats.get('execs_done', 'N/A'),
            'total_crashes': stats.get('unique_crashes', 'N/A'),
            'total_hangs': stats.get('unique_hangs', 'N/A'),
            'run_time': stats.get('run_time', 'N/A'),
        }

    # ------------------------------------------------------------------
    # Python Built-in Fuzzer (No AFL++ required)
    # ------------------------------------------------------------------

    def _run_python_fuzzer(self, session_id: str,
                            target_function: Callable,
                            seed_inputs: List[bytes],
                            timeout_seconds: int) -> Dict[str, Any]:
        """
        Lightweight mutational fuzzer in pure Python.
        Suitable for fuzzing Python functions directly.
        """
        crashes = []
        iterations = 0
        start_time = time.time()

        corpus = list(seed_inputs)

        while time.time() - start_time < timeout_seconds:
            # Pick a random seed and mutate it
            seed = random.choice(corpus)
            mutated = self._mutate(seed)

            try:
                result = target_function(mutated)
                # If function returns without crash, add to corpus
                if random.random() < 0.1:  # 10% add-to-corpus rate
                    corpus.append(mutated)
            except (Exception, SystemExit) as e:
                crash_type = type(e).__name__
                crashes.append({
                    'crash_id': f'crash-{iterations}',
                    'signal': crash_type,
                    'signal_num': None,
                    'size': len(mutated),
                    'hex_preview': mutated[:32].hex(),
                    'crash_type': crash_type.lower(),
                    'input_data': mutated[:512],
                    'exception': str(e)[:200],
                    'iteration': iterations,
                })
                print(f'🔴 [PyFuzzer] Crash at iteration {iterations}: {crash_type}')

            iterations += 1

        elapsed = time.time() - start_time
        return {
            'session_id': session_id,
            'mode': 'python_fuzzer',
            'crashes_found': len(crashes),
            'hangs_found': 0,
            'crashes': crashes,
            'hangs': [],
            'stats': {
                'total_execs': iterations,
                'execs_per_sec': f'{iterations / elapsed:.0f}',
                'run_time': f'{elapsed:.0f}s',
                'corpus_size': len(corpus),
            },
            'completed': True,
        }

    def _run_binary_python_fuzzer(self, session_id: str,
                                   target_binary: str,
                                   seed_inputs: List[bytes],
                                   timeout_seconds: int) -> Dict[str, Any]:
        """Fuzz a binary executable using Python subprocess + mutations."""
        crashes = []
        iterations = 0
        start_time = time.time()
        corpus = list(seed_inputs)

        while time.time() - start_time < timeout_seconds:
            seed = random.choice(corpus)
            mutated = self._mutate(seed)

            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(mutated)
                input_path = f.name

            try:
                result = subprocess.run(
                    [target_binary, input_path],
                    capture_output=True,
                    timeout=5
                )

                if result.returncode < 0:  # Killed by signal
                    import signal as sig_module
                    signal_name = {
                        -11: 'SIGSEGV',
                        -6: 'SIGABRT',
                        -8: 'SIGFPE',
                    }.get(result.returncode, f'SIG{abs(result.returncode)}')

                    crashes.append({
                        'crash_id': f'crash-{iterations}',
                        'signal': signal_name,
                        'signal_num': abs(result.returncode),
                        'size': len(mutated),
                        'hex_preview': mutated[:32].hex(),
                        'crash_type': 'memory_corruption',
                        'input_data': mutated[:512],
                        'iteration': iterations,
                    })
                    print(f'🔴 [PyFuzzer] Crash: {signal_name} at iter {iterations}')
                elif random.random() < 0.05:
                    corpus.append(mutated)

            except subprocess.TimeoutExpired:
                # Potential hang — record it
                pass
            except Exception:
                pass
            finally:
                Path(input_path).unlink(missing_ok=True)

            iterations += 1

        elapsed = time.time() - start_time
        return {
            'session_id': session_id,
            'mode': 'python_binary_fuzzer',
            'target': target_binary,
            'crashes_found': len(crashes),
            'hangs_found': 0,
            'crashes': crashes,
            'hangs': [],
            'stats': {
                'total_execs': iterations,
                'execs_per_sec': f'{iterations / elapsed:.0f}',
                'run_time': f'{elapsed:.0f}s',
            },
            'completed': True,
        }

    # ------------------------------------------------------------------
    # Mutation Strategies
    # ------------------------------------------------------------------

    def _mutate(self, data: bytes) -> bytes:
        """Apply random mutation to input bytes."""
        if not data:
            return b'\x00' * random.randint(1, 64)

        strategy = random.choice([
            'bit_flip', 'byte_flip', 'insert', 'delete',
            'repeat', 'boundary', 'format_string'
        ])

        data = bytearray(data)

        if strategy == 'bit_flip' and data:
            idx = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[idx] ^= (1 << bit)

        elif strategy == 'byte_flip' and data:
            idx = random.randint(0, len(data) - 1)
            data[idx] = random.randint(0, 255)

        elif strategy == 'insert':
            idx = random.randint(0, len(data))
            insert_data = bytes([random.randint(0, 255)
                                 for _ in range(random.randint(1, 16))])
            data = data[:idx] + bytearray(insert_data) + data[idx:]

        elif strategy == 'delete' and len(data) > 1:
            idx = random.randint(0, len(data) - 1)
            del data[idx]

        elif strategy == 'repeat':
            data = data * random.randint(2, 8)

        elif strategy == 'boundary':
            # Insert common boundary values
            boundary = random.choice([
                b'\xff' * 4, b'\x00' * 4,
                struct.pack('>I', 0xffffffff),
                struct.pack('>I', 0x7fffffff),
                b'A' * 256,
            ])
            data = bytearray(boundary) + data

        elif strategy == 'format_string':
            data = bytearray(b'%s%p%x%d' * 10) + data

        return bytes(data)


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    import sys

    print('=== ShadowKnight CRS — Fuzzer Harness Demo ===\n')

    # Demo: fuzz a Python function
    def vulnerable_parser(data: bytes) -> str:
        """Simulates a vulnerable parser (division by zero on empty input)"""
        if len(data) == 0:
            return ''
        result = 100 // data[0]  # ZeroDivisionError if data[0] == 0
        return f'Result: {result}'

    harness = FuzzerHarness(mode='python')
    result = harness.run_session(
        target_function=vulnerable_parser,
        seed_inputs=[b'A', b'\x01\x02', b'test'],
        timeout_seconds=10,
    )

    print(f'\n📊 Session: {result["session_id"]}')
    print(f'   Crashes:    {result["crashes_found"]}')
    print(f'   Iterations: {result["stats"]["total_execs"]}')
    print(f'   Speed:      {result["stats"]["execs_per_sec"]} exec/s')

    for crash in result['crashes'][:3]:
        print(f'\n🔴 Crash: {crash["crash_type"]} at iter {crash["iteration"]}')
        print(f'   Input: {crash["hex_preview"]}')
