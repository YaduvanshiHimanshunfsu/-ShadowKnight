"""
core/ads_detector.py

Role: Detects NTFS Alternate Data Streams (ADS) which are often used by malware
to hide payloads or by attackers to conceal stolen data.
Libraries used: subprocess, platform, os
Function in project: Adds a deep forensic capability to detect hidden data 
that normal file scans (like standard 'dir' or 'os.stat') completely ignore.
"""

import subprocess
import platform
import os

class ADSDetector:
    def __init__(self):
        self.is_windows = platform.system().lower() == 'windows'

    def scan_file(self, file_path: str) -> dict:
        """
        Scans a specific file for Alternate Data Streams.
        Returns a dictionary containing the streams found and their sizes.
        """
        result = {
            "path": file_path,
            "has_ads": False,
            "streams": [],
            "error": None
        }

        if not self.is_windows:
            result["error"] = "ADS is an NTFS-specific feature (Windows only)."
            return result

        if not os.path.exists(file_path):
            result["error"] = "File does not exist."
            return result

        try:
            # Using 'dir /R' which is a built-in Windows command to list ADS
            proc = subprocess.run(
                ["cmd", "/c", f"dir /R \"{file_path}\""],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            lines = proc.stdout.split('\n')
            
            # Typical output of 'dir /R' for a file with ADS:
            # 12/28/2023  10:00 AM                14 test.txt
            #                                     25 test.txt:hidden_stream.exe:$DATA
            
            for line in lines:
                if ':$DATA' in line:
                    # Ignore the default unnamed stream if it gets matched strangely, 
                    # but usually dir /R only prints :$DATA for named streams.
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        try:
                            # The stream size is usually the second to last element
                            # and the name is the last element
                            stream_name = parts[-1]
                            stream_size = int(parts[-2].replace(',', ''))
                            
                            # Filter out legitimate common streams like Zone.Identifier
                            if "Zone.Identifier" not in stream_name:
                                result["streams"].append({
                                    "name": stream_name,
                                    "size_bytes": stream_size
                                })
                        except (ValueError, IndexError):
                            pass
                            
            if result["streams"]:
                result["has_ads"] = True
                
        except Exception as e:
            result["error"] = str(e)
            
        return result
