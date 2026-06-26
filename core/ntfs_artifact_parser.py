"""
core/ntfs_artifact_parser.py

Role: Extracts Master File Table (MFT) attributes, specifically $STANDARD_INFORMATION (SI)
and $FILE_NAME (FN) timestamps, to detect timestomping.
Libraries used: os, ctypes, platform, datetime
Function in project: Provides deterministic forensic proof of file manipulation.
"""

import os
import ctypes
from ctypes import wintypes
import datetime
import platform

# --- Windows API Definitions (For advanced NTFS parsing) ---
if platform.system() == 'Windows':
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    
    # Define FILETIME struct
    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD),
                    ("dwHighDateTime", wintypes.DWORD)]

    # Define WIN32_FIND_DATAW for $FILE_NAME layer extraction
    class WIN32_FIND_DATAW(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FILETIME),
            ("ftLastAccessTime", FILETIME),
            ("ftLastWriteTime", FILETIME),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("dwReserved0", wintypes.DWORD),
            ("dwReserved1", wintypes.DWORD),
            ("cFileName", wintypes.WCHAR * 260),
            ("cAlternateFileName", wintypes.WCHAR * 14)
        ]
        
    FindFirstFileW = kernel32.FindFirstFileW
    FindFirstFileW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(WIN32_FIND_DATAW)]
    FindFirstFileW.restype = wintypes.HANDLE
    FindClose = kernel32.FindClose
    FindClose.argtypes = [wintypes.HANDLE]
    FindClose.restype = wintypes.BOOL

def _filetime_to_dt(ft: FILETIME) -> datetime.datetime:
    """Convert Windows FILETIME to datetime"""
    # 100-nanosecond intervals since Jan 1, 1601
    timestamp = (ft.dwHighDateTime << 32) + ft.dwLowDateTime
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp / 10)

class NTFSArtifactParser:
    def __init__(self):
        self.is_windows = (os.name == 'nt')
        
    def extract_mft_timestamps(self, file_path: str) -> dict:
        """
        Extracts SI and FN timestamps.
        Implements an ON-DEMAND extraction approach for performance,
        with a safe fallback if admin rights/MFT access is blocked.
        """
        result = {
            "path": file_path,
            "si_creation": None,
            "fn_creation": None,
            "mismatch_detected": False,
            "fallback_used": False
        }
        
        try:
            # $STANDARD_INFORMATION (SI) - Easily spoofed by APIs (SetFileTime)
            stat_info = os.stat(file_path)
            result["si_creation"] = datetime.datetime.fromtimestamp(stat_info.st_ctime)
            
            if not self.is_windows:
                # Linux/Mac don't have $FILE_NAME MFT attributes.
                result["fallback_used"] = True
                result["fn_creation"] = result["si_creation"]
                return result
                
            # $FILE_NAME (FN) - Only modified by kernel. Extracted via FindFirstFile API 
            # which queries the directory index entry (which stores FN timestamps).
            wfd = WIN32_FIND_DATAW()
            handle = FindFirstFileW(file_path, ctypes.byref(wfd))
            
            if handle != -1:  # INVALID_HANDLE_VALUE
                result["fn_creation"] = _filetime_to_dt(wfd.ftCreationTime)
                FindClose(handle)
                
                # Compare SI vs FN (allow 1 second tolerance for precision differences)
                diff = abs((result["si_creation"] - result["fn_creation"]).total_seconds())
                if diff > 1.0:
                    result["mismatch_detected"] = True
            else:
                # Fallback if API fails
                raise OSError("FindFirstFileW failed")
                
        except Exception as e:
            # FALLBACK MECHANISM: If advanced extraction fails (e.g., file locked),
            # fallback to basic OS stat to ensure the program never crashes.
            result["fallback_used"] = True
            try:
                stat_info = os.stat(file_path)
                result["si_creation"] = datetime.datetime.fromtimestamp(stat_info.st_ctime)
                result["fn_creation"] = result["si_creation"]  # Spoof FN to prevent crash
            except:
                pass
                
        return result
