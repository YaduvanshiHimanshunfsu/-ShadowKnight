"""
core/prefetch_analyzer.py

Role: Analyzes Windows Prefetch (.pf) files to detect if an executable was run.
Libraries used: os, struct, glob, platform
Function in project: Proves execution of anti-forensics tools (like sdelete or wevtutil)
even if the attacker securely wiped the tool from the disk afterward.
"""

import os
import struct
import glob
import platform
from datetime import datetime

class PrefetchAnalyzer:
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'
        self.prefetch_dir = r"C:\Windows\Prefetch"

    def check_execution(self, executable_name: str) -> dict:
        """
        Checks if a specific executable has a prefetch file, indicating it was run.
        Requires Administrator privileges to access C:\Windows\Prefetch.
        """
        result = {
            "executable": executable_name,
            "was_executed": False,
            "prefetch_file": None,
            "error": None
        }

        if not self.is_windows:
            result["error"] = "Prefetch is a Windows-only feature."
            return result

        if not os.access(self.prefetch_dir, os.R_OK):
            result["error"] = "Permission denied. Must run as Administrator to read Prefetch."
            return result

        try:
            # Prefetch files are typically named: EXECUTABLE_NAME-HASH.pf
            search_pattern = os.path.join(self.prefetch_dir, f"{executable_name.upper()}*.pf")
            matches = glob.glob(search_pattern)

            if matches:
                # Get the most recently modified prefetch file for this executable
                latest_pf = max(matches, key=os.path.getmtime)
                result["was_executed"] = True
                result["prefetch_file"] = latest_pf
                
                # In a full implementation (Phase 3), we would parse the MAM compressed 
                # header to extract exact run times and run counts using a library like
                # windowsprefetch or python-lzxpress. For Phase 2, finding the file
                # is sufficient proof of execution.

        except Exception as e:
            result["error"] = str(e)

        return result
