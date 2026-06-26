# core/entropy_engine.py

import os
import math
import numpy as np
from scipy.stats import kstest, chisquare


class EntropyEngine:
    """
    Entropy Analysis Engine
    -----------------------
    Detects statistically high-entropy data regions
    that may indicate:
        • Encrypted containers
        • Hidden volumes
        • Packed malware
        • Random overwrite wiping

    Supports:
        1. Block-level deep scan
        2. Sampled fast scan (real-time mode)
    """

    def __init__(self, block_size=4096, entropy_threshold=7.8):
        self.block_size = block_size
        self.entropy_threshold = entropy_threshold

    # ============================================================
    # 1️⃣ Shannon Entropy Calculation (Core Mathematical Logic)
    # ============================================================
    def calculate_entropy(self, data: bytes) -> float:
        """
        Computes Shannon entropy for a byte sequence.
        Range: 0.0 – 8.0
        """

        if not data:
            return 0.0

        byte_counts = [0] * 256
        length = len(data)

        for byte in data:
            byte_counts[byte] += 1

        entropy = 0.0

        for count in byte_counts:
            if count == 0:
                continue
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    # ============================================================
    # 2️⃣ Deep Block-Level Scan (Forensic Mode)
    # ============================================================
    def scan_file(self, file_path: str):
        """
        Performs full block-by-block entropy analysis.
        Use only in deep forensic mode.
        """

        suspicious_blocks = []
        high_entropy_count = 0
        total_blocks = 0

        try:
            with open(file_path, "rb") as f:
                block_index = 0

                while True:
                    data = f.read(self.block_size)
                    if not data:
                        break

                    entropy = self.calculate_entropy(data)

                    if entropy >= self.entropy_threshold:
                        suspicious_blocks.append({
                            "block_index": block_index,
                            "entropy": round(entropy, 3)
                        })
                        high_entropy_count += 1

                    block_index += 1
                    total_blocks += 1

        except Exception:
            return None

        if total_blocks == 0:
            return None

        entropy_ratio = high_entropy_count / total_blocks

        return {
            "file": file_path,
            "mode": "deep_scan",
            "total_blocks": total_blocks,
            "high_entropy_blocks": suspicious_blocks,
            "high_entropy_count": high_entropy_count,
            "entropy_ratio": round(entropy_ratio, 3),
            "high_entropy_detected": entropy_ratio > 0.6
        }

    # ============================================================
    # 3️⃣ Fast Sampled Entropy Scan (Real-Time Mode)
    # ============================================================
    def calculate_entropy_sampled(self, file_path: str, chunk_size=65536):
        """
        Fast entropy estimation.
        Reads:
            • Beginning
            • Middle
            • End
        Instead of full file.
        Safe for real-time detection.
        """

        try:
            file_size = os.path.getsize(file_path)

            if file_size == 0:
                return 0.0

            with open(file_path, "rb") as f:

                # Small file → full read
                if file_size <= chunk_size * 3:
                    data = f.read()

                else:
                    # First chunk
                    first = f.read(chunk_size)

                    # Middle chunk
                    f.seek(file_size // 2)
                    middle = f.read(chunk_size)

                    # Last chunk
                    f.seek(-chunk_size, os.SEEK_END)
                    last = f.read(chunk_size)

                    data = first + middle + last

            entropy = self.calculate_entropy(data)
            return round(entropy, 4)

        except Exception:
            return 0.0

    # ============================================================
    # 4️⃣ Lightweight Real-Time Scan Wrapper
    # ============================================================
    def fast_scan_file(self, file_path: str):
        """
        Lightweight wrapper for real-time scoring.
        """

        entropy_value = self.calculate_entropy_sampled(file_path)

        return {
            "file": file_path,
            "mode": "fast_scan",
            "entropy_value": entropy_value,
            "high_entropy_detected": entropy_value >= self.entropy_threshold
        }

    # ============================================================
    # 5️⃣ Statistical Tests (Phase 1 Upgrades)
    # ============================================================
    def run_ks_test(self, data: bytes) -> dict:
        """
        Kolmogorov-Smirnov test against uniform distribution.
        Checks if the byte distribution perfectly matches a uniform distribution (typical of AES encryption).
        """
        if not data:
            return {"ks_statistic": 0.0, "p_value": 1.0, "is_uniform": False}
        
        # Normalize bytes to [0, 1] range
        normalized_data = np.frombuffer(data, dtype=np.uint8) / 255.0
        
        # Test against uniform distribution
        ks_stat, p_value = kstest(normalized_data, 'uniform')
        
        # If p-value > 0.05, it matches uniform distribution (encrypted)
        return {
             "ks_statistic": float(ks_stat),
             "p_value": float(p_value),
             "is_uniform": float(p_value) > 0.05
        }

    def run_chi_square_test(self, data: bytes) -> dict:
        """
        Chi-Squared test on byte frequencies.
        Checks for packed/compressed malware by seeing if frequencies match expected uniform distribution.
        """
        if not data or len(data) < 256:
             return {"chi_statistic": 0.0, "p_value": 1.0, "is_suspicious": False}
             
        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        
        # Expected counts if perfectly uniform
        expected = np.full(256, len(data) / 256.0)
        
        chi_stat, p_value = chisquare(byte_counts, f_exp=expected)
        
        return {
             "chi_statistic": float(chi_stat),
             "p_value": float(p_value),
             "is_suspicious": float(p_value) > 0.05
        }

    # ============================================================
    # 6️⃣ Entropy Heat Score (Used for Weighted Forensics)
    # ============================================================
    def compute_entropy_score(self, entropy_value: float):
        """
        Converts entropy value into 0–100 forensic score.
        """

        if entropy_value <= 6:
            return 0

        if entropy_value >= 8:
            return 100

        # Linear scaling between 6 and 8
        return int((entropy_value - 6) / 2 * 100)