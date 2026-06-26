"""
OS Detection and Platform-Specific Utilities
Automatically detects OS and provides appropriate methods
"""

import platform
import sys
from typing import Dict, Any


class OSDetector:
    """
    Detect operating system and provide platform-specific capabilities
    """
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.os_version = platform.version()
        self.is_windows = self.os_type == 'windows'
        self.is_linux = self.os_type == 'linux'
        self.is_mac = self.os_type == 'darwin'
        self.hostname = platform.node()
        self.is_admin = self._check_admin_privileges()
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with admin/root privileges"""
        try:
            if self.is_windows:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                import os
                return os.geteuid() == 0
        except Exception:
            return False
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get platform-specific capabilities"""
        capabilities = {
            'os_type': self.os_type,
            'os_version': self.os_version,
            'is_admin': self.is_admin,
            'proactive_capture': False,
            'command_interception': False,
            'memory_snapshot': False,
            'log_snapshot': False,
            'vss_snapshot': False
        }
        
        if self.is_windows:
            capabilities.update({
                'proactive_capture': self.is_admin,
                'command_interception': self.is_admin,
                'memory_snapshot': True,
                'log_snapshot': True,
                'vss_snapshot': self.is_admin
            })
        elif self.is_linux:
            capabilities.update({
                'proactive_capture': self.is_admin,
                'command_interception': self.is_admin,
                'memory_snapshot': self.is_admin,
                'log_snapshot': True,
                'vss_snapshot': False  # Linux uses LVM snapshots
            })
        elif self.is_mac:
            capabilities.update({
                'proactive_capture': self.is_admin,
                'command_interception': self.is_admin,
                'memory_snapshot': self.is_admin,
                'log_snapshot': True,
                'vss_snapshot': False  # Mac uses Time Machine
            })
        
        return capabilities
    
    def get_anti_forensics_commands(self) -> list:
        """Get OS-specific anti-forensics commands to monitor"""
        if self.is_windows:
            return [
                'wevtutil', 'vssadmin', 'cipher', 'bcdedit',
                'Clear-EventLog', 'sdelete', 'timestomp',
                'mimikatz', 'procdump', 'psexec'
            ]
        elif self.is_linux:
            return [
                'shred', 'wipe', 'srm', 'dd',
                'history -c', 'unset HISTFILE',
                'rm -rf /var/log', 'journalctl --vacuum',
                'auditctl -D', 'logrotate'
            ]
        elif self.is_mac:
            return [
                'srm', 'rm -P', 'diskutil secureErase',
                'log erase', 'rm -rf /var/log',
                'history -c', 'unset HISTFILE'
            ]
        else:
            return []
    
    def get_log_paths(self) -> list:
        """Get OS-specific log file paths"""
        if self.is_windows:
            return [
                'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
                'C:\\Windows\\System32\\winevt\\Logs\\System.evtx',
                'C:\\Windows\\System32\\winevt\\Logs\\Application.evtx'
            ]
        elif self.is_linux:
            return [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/kern.log',
                '/var/log/audit/audit.log'
            ]
        elif self.is_mac:
            return [
                '/var/log/system.log',
                '/var/log/secure.log',
                '/Library/Logs'
            ]
        else:
            return []
    
    def print_status(self):
        """Print OS detection status"""
        print(f"\n{'='*60}")
        print(f"🖥️  PLATFORM DETECTION")
        print(f"{'='*60}")
        print(f"Operating System: {self.os_type.upper()}")
        print(f"Version: {self.os_version}")
        print(f"Admin/Root: {'✅ YES' if self.is_admin else '❌ NO'}")
        
        caps = self.get_capabilities()
        print(f"\n📊 CAPABILITIES:")
        print(f"   Proactive Capture: {'✅' if caps['proactive_capture'] else '❌'}")
        print(f"   Command Interception: {'✅' if caps['command_interception'] else '❌'}")
        print(f"   Memory Snapshot: {'✅' if caps['memory_snapshot'] else '❌'}")
        print(f"   Log Snapshot: {'✅' if caps['log_snapshot'] else '❌'}")
        
        if not self.is_admin:
            print(f"\n⚠️  WARNING: Running without admin/root privileges")
            print(f"   Some features will be limited. Run as admin for full capabilities.")
        
        print(f"{'='*60}\n")


# Global OS detector instance
os_detector = OSDetector()
