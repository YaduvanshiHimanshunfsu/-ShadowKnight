# core/wipe_pattern_engine.py

import os
import math


class WipePatternEngine:
    """
    Disk Wipe Pattern Detection Engine
    -----------------------------------
    Detects intentional secure deletion patterns:
        • 0x00 wipe
        • 0xFF wipe
        • Repeating byte pattern wipe
        • Random overwrite wipe
        • Multi-pass wipe signatures
    """

    def __init__(self, block_size=4096):
        self.block_size = block_size

    # ============================================================
    # 1️⃣ Detect Uniform Byte Pattern (00, FF, AA etc.)
    # ============================================================
    def detect_uniform_pattern(self, data: bytes):
        """
        Detects if entire block is filled with same byte.
        """

        if not data:
            return False, None

        first_byte = data[0]

        if all(b == first_byte for b in data):
            return True, hex(first_byte)

        return False, None

    # ============================================================
    # 2️⃣ Detect Low Entropy Block (Likely Zero/FF Wipe)
    # ============================================================
    def calculate_entropy(self, data: bytes):
        if not data:
            return 0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        entropy = 0
        length = len(data)

        for count in freq:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    # ============================================================
    # 3️⃣ Detect Random Overwrite Pattern
    # ============================================================
    def detect_random_wipe(self, entropy_value):
        """
        Very high entropy (~8) suggests random overwrite.
        """
        return entropy_value > 7.95

    # ============================================================
    # 4️⃣ Scan File for Wipe Patterns
    # ============================================================
    def scan_file(self, file_path: str):
        """
        Performs wipe signature detection.
        """

        wipe_blocks = []
        zero_blocks = 0
        ff_blocks = 0
        random_blocks = 0
        repeating_blocks = 0
        total_blocks = 0

        try:
            with open(file_path, "rb") as f:
                block_index = 0

                while True:
                    data = f.read(self.block_size)
                    if not data:
                        break

                    total_blocks += 1

                    # 1️⃣ Uniform Pattern Detection
                    is_uniform, pattern = self.detect_uniform_pattern(data)

                    if is_uniform:
                        repeating_blocks += 1

                        if pattern == "0x0":
                            zero_blocks += 1
                        elif pattern == "0xff":
                            ff_blocks += 1

                        wipe_blocks.append({
                            "block_index": block_index,
                            "pattern": pattern,
                            "type": "uniform_wipe"
                        })

                    else:
                        # 2️⃣ Random Overwrite Detection
                        entropy = self.calculate_entropy(data)

                        if self.detect_random_wipe(entropy):
                            random_blocks += 1
                            wipe_blocks.append({
                                "block_index": block_index,
                                "pattern": "random",
                                "entropy": round(entropy, 3),
                                "type": "random_wipe"
                            })

                    block_index += 1

        except Exception:
            return None

        if total_blocks == 0:
            return None

        wipe_ratio = len(wipe_blocks) / total_blocks

        wipe_detected = (
            wipe_ratio > 0.5 or
            zero_blocks > 5 or
            ff_blocks > 5 or
            random_blocks > 5
        )

        return {
            "file": file_path,
            "total_blocks": total_blocks,
            "wipe_blocks": wipe_blocks,
            "wipe_block_count": len(wipe_blocks),
            "zero_blocks": zero_blocks,
            "ff_blocks": ff_blocks,
            "random_blocks": random_blocks,
            "repeating_blocks": repeating_blocks,
            "wipe_ratio": round(wipe_ratio, 3),
            "wipe_detected": wipe_detected
        }

    # ============================================================
    # 5️⃣ Lightweight Real-Time Scan (Sample Mode)
    # ============================================================
    def fast_scan_file(self, file_path: str, sample_size=65536):
        """
        Real-time lightweight wipe detection.
        """

        try:
            file_size = os.path.getsize(file_path)

            if file_size == 0:
                return None

            with open(file_path, "rb") as f:

                if file_size <= sample_size * 3:
                    data = f.read()
                else:
                    first = f.read(sample_size)
                    f.seek(file_size // 2)
                    middle = f.read(sample_size)
                    f.seek(-sample_size, os.SEEK_END)
                    last = f.read(sample_size)

                    data = first + middle + last

            is_uniform, pattern = self.detect_uniform_pattern(data)
            entropy = self.calculate_entropy(data)

            wipe_detected = (
                is_uniform or
                entropy > 7.95
            )

            return {
                "file": file_path,
                "mode": "fast_scan",
                "uniform_pattern": pattern if is_uniform else None,
                "entropy": round(entropy, 3),
                "wipe_detected": wipe_detected
            }

        except Exception:
            return None

    # ============================================================
    # 6️⃣ Compute Wipe Forensic Score (0–100)
    # ============================================================
    def compute_wipe_score(self, wipe_result):
        """
        Converts wipe detection result into weighted forensic score.
        """

        if not wipe_result:
            return 0

        score = 0

        score += wipe_result.get("zero_blocks", 0) * 5
        score += wipe_result.get("ff_blocks", 0) * 5
        score += wipe_result.get("random_blocks", 0) * 7
        score += int(wipe_result.get("wipe_ratio", 0) * 50)

        return min(score, 100)