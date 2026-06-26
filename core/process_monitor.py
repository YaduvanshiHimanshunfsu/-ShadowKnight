"""
ShadowKnight - Cross-Platform Process Monitor
Supports Windows (WMI + Polling), Linux (Polling), and Mac (Polling)
"""

import os
import sys
import threading
import time
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List
from collections import deque
import platform
import subprocess
import ctypes
from .behavior_chain import BehaviorChainTracker

# --- Constants (Bug 14) ---
WMI_TIMEOUT_MS = 500       # Improved stability (Bug 5)
POLLING_INTERVAL = 0.01    # 10ms (Windows fallback)
UNIX_POLLING_INTERVAL = 0.005 # 5ms (Unix primary)
WMI_PULSE_INTERVAL = 20    # seconds
MAX_HISTORY = 100
WMI_DELAY_SECS = 1

def is_admin():
    try:
        if platform.system().lower() == 'windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        return os.getuid() == 0
    except Exception:
        return False

# Conditional imports
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    if platform.system().lower() == 'windows':
        import wmi
        import pythoncom
        HAS_WMI = True
    else:
        HAS_WMI = False
except ImportError:
    HAS_WMI = False


class BaseProcessMonitor:
    """Base class for platform-specific process monitors"""
    def __init__(self, callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
        self.callback = callback
        self.suspicious_keywords = suspicious_keywords or []
        self.monitoring = False
        self.processes_detected = 0
        self.suspicious_detected = 0
        self.command_history = deque(maxlen=MAX_HISTORY)
        self.os_type = platform.system().lower()
        self.chain_tracker = BehaviorChainTracker()

    def start_monitoring(self):
        raise NotImplementedError

    def stop_monitoring(self):
        self.monitoring = False

    def _is_suspicious(self, command: str) -> bool:
        if not command:
            return False
        cmd_lower = command.lower()
        for keyword in self.suspicious_keywords:
            if keyword.lower() in cmd_lower:
                return True
        return False

    def _handle_suspicious_command(self, command: str, process_info: Dict[str, Any], method: str):
        self.suspicious_detected += 1
        
        # Analyze behavioral chain
        user = process_info.get('user', 'SYSTEM')
        chain_analysis = self.chain_tracker.analyze_chain(user, command)
        process_info['chain_analysis'] = chain_analysis
        
        # Call callback if provided
        if self.callback:
            try:
                self.callback(command, process_info)
            except Exception as e:
                print(f"⚠️  [WARN] Callback error: {e}")

        self.command_history.append({
            'timestamp': datetime.now().isoformat(),
            'command': command,
            'process': process_info,
            'method': method
        })

    def get_statistics(self) -> Dict[str, Any]:
        return {
            'monitoring': self.monitoring,
            'processes_detected': self.processes_detected,
            'suspicious_detected': self.suspicious_detected,
            'os': self.os_type
        }


class WindowsProcessMonitor(BaseProcessMonitor):
    """Windows-specific monitor using WMI events and Fast Polling"""
    def __init__(self, callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
        super().__init__(callback, suspicious_keywords)
        self.wmi_thread = None
        self.polling_thread = None

    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        
        # 1. WMI Thread (Event-driven)
        if HAS_WMI:
            self.wmi_thread = threading.Thread(target=self._wmi_monitor_loop, daemon=True)
            self.wmi_thread.start()
        
        # 2. Polling Thread (Backup)
        if HAS_PSUTIL:
            self.polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
            self.polling_thread.start()
            
        print(f"⚡ Windows Process Monitor: ACTIVE (WMI: {'YES' if HAS_WMI else 'NO'}, Polling: {'YES' if HAS_PSUTIL else 'NO'})")

    def _wmi_monitor_loop(self):
        pythoncom.CoInitialize()
        wmi_working = False
        try:
            w = wmi.WMI()
            # 1. WMI Event Watcher initialization with delay fallback
            print("   [WMI] Attempting to initialize event watcher...")
            try:
                # FIXED: Use delay_secs for more stable WMI event delivery
                watcher = w.Win32_Process.watch_for(
                    notification_type="creation",
                    delay_secs=1
                )
            except Exception as e:
                print(f"   [ERROR] WMI event watcher failed: {e}")
                print("   [FALLBACK] Using polling-only mode")
                wmi_working = False
                return

            wmi_working = True
            print("   [WMI] ✅ Event watcher initialized successfully")
            
            last_pulse = time.time()
            while self.monitoring:
                try:
                    # Self-Pulse: Verify monitor is hearing things
                    if time.time() - last_pulse > WMI_PULSE_INTERVAL:
                        subprocess.Popen(['cmd.exe', '/c', 'echo ShadowKnightPulse'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        last_pulse = time.time()

                    # Use stable timeout to avoid blocking (Bug 5)
                    new_process = watcher(timeout_ms=WMI_TIMEOUT_MS)
                    if new_process:
                        name = str(new_process.Name)
                        pid = new_process.ProcessId
                        
                        # Diagnostic: Show EVERY discovery instantly
                        if "ShadowKnightPulse" not in name:
                            sys.stdout.write(f" [WMI-DISCOVERED: {name}] ")
                            sys.stdout.flush()

                        # FIXED: Better fallback chain for command line
                        try:
                            cmdline = getattr(new_process, 'CommandLine', None)
                            if not cmdline or str(cmdline).strip() == "":
                                cmdline = getattr(new_process, 'ExecutablePath', name)
                            if not cmdline:
                                cmdline = name
                            cmd = str(cmdline)
                        except Exception as e:
                            cmd = name

                        # Aggressive forensic check
                        is_suspicious_exe = any(kw.lower() in name.lower() for kw in self.suspicious_keywords)
                        
                        if self._is_suspicious(cmd) or is_suspicious_exe:
                            self.processes_detected += 1
                            owner = "Unknown"
                            try:
                                owner_info = new_process.GetOwner()
                                if owner_info and owner_info[0]:
                                    owner = f"{owner_info[0]}\\{owner_info[2]}"
                            except Exception: pass
                            
                            p_info = {
                                'pid': pid,
                                'name': name,
                                'cmdline': [cmd],
                                'username': owner,
                                'parent_pid': new_process.ParentProcessId
                            }
                            self._handle_suspicious_command(cmd, p_info, "WMI")
                except wmi.x_wmi_timed_out:
                    # Normal timeout, continue silently
                    continue
                except Exception as e:
                    if self.monitoring:
                        print(f"\n⚠️  [WARN] WMI Error: {e}")
                        time.sleep(1) # Prevent tight error loop
                    continue
        except Exception as e:
            print(f"⚠️  [ERROR] WMI initialization failed: {e}")
            print("   [FALLBACK] Switching to polling-only mode...")
        finally:
            pythoncom.CoUninitialize()
            
        if not wmi_working:
            print("   [INFO] WMI not available, relying on polling fallback")

    def _polling_loop(self):
        seen_pids = set(p.info['pid'] for p in psutil.process_iter(['pid']))
        print("   [POLLING] Ultra-fast differential polling active (10ms interval)")
        while self.monitoring:
            try:
                # 1. Fetch current PIDs once (extremely fast)
                current_pids = set(psutil.pids())
                new_pids = current_pids - seen_pids
                
                # 2. Update baseline for next loop
                seen_pids = current_pids

                # 3. Only inspect new PIDs directly (avoids full process-list iteration)
                for pid in new_pids:
                    try:
                        proc = psutil.Process(pid)
                        with proc.oneshot():
                            name = proc.name()
                            cmdline = proc.cmdline()
                            full_cmd = " ".join(cmdline) if cmdline else name
                            username = proc.username()
                            parent_pid = proc.ppid()
                        
                        # Detect by Command Line OR by Binary Name (Fast-kill fallback)
                        is_suspicious_exe = any(kw.lower() in name.lower() for kw in self.suspicious_keywords)
                        is_suspicious_cmd = self._is_suspicious(full_cmd)
                        
                        if is_suspicious_cmd or is_suspicious_exe:
                            self._handle_suspicious_command(full_cmd, {
                                'pid': pid,
                                'name': name,
                                'cmdline': cmdline or [name],
                                'username': username,
                                'parent_pid': parent_pid
                            }, "Polling")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception as e:
                if self.monitoring:
                    print(f"⚠️  [ERROR] Windows Polling Error: {e}")
            
            time.sleep(POLLING_INTERVAL)


class UnixProcessMonitor(BaseProcessMonitor):
    """Linux/Mac monitor using Optimized Polling"""
    def __init__(self, callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
        super().__init__(callback, suspicious_keywords)
        self.polling_thread = None

    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        
        if HAS_PSUTIL:
            self.polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
            self.polling_thread.start()
            print(f"⚡ {self.os_type.upper()} Process Monitor: ACTIVE (Polling-Based)")
        else:
            print(f"❌ [ERROR] {self.os_type.upper()} Monitor Failed: psutil not installed")
            self.monitoring = False # Properly set to False (Bug 12)
            return

    def _polling_loop(self):
        """
        High-Performance Differential Polling (Linux/Mac)
        Strategy: Only fetch full details for NEW PIDs to minimize I/O overhead.
        Target Latency: ~5ms
        """
        # FIXED: Initialize empty to catch ALL processes on first run (Bug 6)
        known_pids = set()
        
        while self.monitoring:
            try:
                # 1. Light scan: Get current PIDs only
                current_pids = set(psutil.pids())
                
                # 2. find new processes (Differential)
                new_pids = current_pids - known_pids
                
                if new_pids:
                    for pid in new_pids:
                        try:
                            # 3. Deep interaction only for NEW targets
                            proc = psutil.Process(pid)
                            
                            # Fast-fail checks
                            try:
                                cmdline = proc.cmdline()
                            except (psutil.ZombieProcess, psutil.AccessDenied, psutil.NoSuchProcess):
                                continue
                                
                            if not cmdline: continue
                            
                            full_cmd = " ".join(cmdline)
                            
                            if self._is_suspicious(full_cmd):
                                p_info = {
                                    'pid': pid,
                                    'name': proc.name(),
                                    'cmdline': cmdline,
                                    'username': proc.username(),
                                    'parent_pid': proc.ppid()
                                }
                                self._handle_suspicious_command(full_cmd, p_info, "Fast-Poll")
                                
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            pass
                
                # Update baseline
                known_pids = current_pids
                
                # 4. Cleanup dead PIDs from set to prevent memory growth (optional but good)
                # (handled by reassignment above)
                
            except Exception as e:
                if self.monitoring:
                    print(f"⚠️  [ERROR] Unix Polling Error: {e}")
            
            # Adaptive High-Speed Sleep
            time.sleep(UNIX_POLLING_INTERVAL)


def get_process_monitor(callback: Optional[Callable] = None, suspicious_keywords: List[str] = None):
    """Factory function to return the correct monitor for the platform"""
    os_type = platform.system().lower()
    if os_type == 'windows':
        print(f"   [WMI] Initializing Kernel Watcher with {len(suspicious_keywords)} triggers...")
        return WindowsProcessMonitor(callback, suspicious_keywords)
    else:
        # Linux and Darwin (Mac) share psutil logic
        return UnixProcessMonitor(callback, suspicious_keywords)
