"""
Emergency Snapshot Engine
Ultra-fast evidence capture before deletion (<100ms)
Cross-platform support for Windows, Linux, and Mac
"""

import os
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import platform


class EmergencySnapshotEngine:
    """
    Captures evidence in <100ms before anti-forensics commands execute
    Automatically adapts to Windows, Linux, or Mac
    """
    
    def __init__(self, evidence_vault_path: str = "./evidence", capture_network: bool = True):
        self.vault_path = Path(evidence_vault_path)
        self.capture_network = capture_network
        self.os_type = platform.system().lower()
        self.snapshots_dir = self.vault_path / "emergency_snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        
    def emergency_snapshot(self, threat_type: str, command: str, process_info: Dict) -> str:
        """
        Execute emergency snapshot based on threat type
        
        Args:
            threat_type: Type of threat (log_clearing, vss_deletion, etc.)
            command: The command being executed
            process_info: Process metadata
        
        Returns:
            Snapshot ID (always returns valid ID, even if some captures fail)
        """
        snapshot_id = f"SNAP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        snapshot_dir = self.snapshots_dir / snapshot_id
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n⚡ EMERGENCY SNAPSHOT TRIGGERED!")
        print(f"   Snapshot ID: {snapshot_id}")
        print(f"   Threat Type: {threat_type}")
        print(f"   Command: {command}")
        
        start_time = time.time()
        
        # Create incident metadata file FIRST (always succeeds)
        metadata_file = snapshot_dir / "incident_metadata.json"
        import json
        metadata = {
            'snapshot_id': snapshot_id,
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat_type,
            'command': command,
            'process_info': process_info,
            'os_type': self.os_type,
            'evidence_collected': []
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Execute parallel snapshots based on threat type
        threads = []
        evidence_types = []
        
        # ALWAYS capture event logs for ALL threats (critical forensic evidence)
        threads.append(threading.Thread(
            target=self._snapshot_event_logs,
            args=(snapshot_dir,)
        ))
        evidence_types.append('event_logs')
        
        if threat_type == 'vss_deletion' or threat_type == 'vss_manipulation':
            threads.append(threading.Thread(
                target=self._snapshot_vss_state,
                args=(snapshot_dir,)
            ))
            evidence_types.append('vss_state')
        
        if threat_type == 'file_wiping':
            threads.append(threading.Thread(
                target=self._snapshot_filesystem_metadata,
                args=(snapshot_dir,)
            ))
            evidence_types.append('filesystem_metadata')
        
        # Always capture process state and memory info
        threads.append(threading.Thread(
            target=self._snapshot_process_state,
            args=(snapshot_dir, process_info)
        ))
        evidence_types.append('process_state')
        
        # Capture network state if enabled
        if self.capture_network:
            threads.append(threading.Thread(
                target=self._snapshot_network_state,
                args=(snapshot_dir,)
            ))
            evidence_types.append('network_state')
        
        # Start all threads (parallel execution)
        for thread in threads:
            thread.daemon = True  # Don't block if thread hangs
            thread.start()
        
        # Wait for all to complete (with timeout)
        for thread in threads:
            thread.join(timeout=10)  # Max 10s per thread
        
        # Update metadata with what was collected
        metadata['evidence_collected'] = evidence_types
        metadata['capture_duration_ms'] = (time.time() - start_time) * 1000
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        elapsed = (time.time() - start_time) * 1000  # Convert to ms
        
        print(f"   ✅ Snapshot completed in {elapsed:.1f}ms")
        print(f"   📁 Saved to: {snapshot_dir}\n")
        
        return snapshot_id
    
    def _snapshot_event_logs(self, snapshot_dir: Path):
        """Snapshot event logs (OS-specific)"""
        try:
            if self.os_type == 'windows':
                self._snapshot_windows_event_logs(snapshot_dir)
            elif self.os_type == 'linux':
                self._snapshot_linux_logs(snapshot_dir)
            elif self.os_type == 'darwin':  # Mac
                self._snapshot_mac_logs(snapshot_dir)
        except Exception as e:
            print(f"   ⚠️  [WARN] Log snapshot failed: {e}")
    
    def _snapshot_windows_event_logs(self, snapshot_dir: Path):
        """Snapshot Windows event logs - ONLY .evtx files"""
        logs_dir = snapshot_dir / "event_logs"
        logs_dir.mkdir(exist_ok=True)
        
        log_types = ['Security', 'System', 'Application']
        
        for log_type in log_types:
            try:
                output_file = logs_dir / f"{log_type}.evtx"
                # Export event log (requires admin)
                subprocess.run([
                    'wevtutil', 'epl', log_type, str(output_file)
                ], capture_output=True, timeout=5, text=True, check=False)
                
            except Exception as e:
                print(f"   ⚠️  [WARN] Failed to export {log_type}: {e}")
    
    def _capture_log_metadata(self, log_type: str, logs_dir: Path):
        """Capture event log metadata when full export isn't available"""
        try:
            metadata_file = logs_dir / f"{log_type}_metadata.txt"
            
            # Get log info using wevtutil (doesn't require admin)
            result = subprocess.run([
                'wevtutil', 'gli', log_type
            ], capture_output=True, timeout=5, text=True)
            
            if result.returncode == 0:
                with open(metadata_file, 'w') as f:
                    f.write(f"Event Log Metadata: {log_type}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(result.stdout)
                    f.write("\n\nNote: Full log export requires admin privileges\n")
            
            # Also try to get recent event count
            count_result = subprocess.run([
                'wevtutil', 'qe', log_type, '/c:10', '/rd:true', '/f:text'
            ], capture_output=True, timeout=5, text=True)
            
            if count_result.returncode == 0:
                recent_file = logs_dir / f"{log_type}_recent_events.txt"
                with open(recent_file, 'w') as f:
                    f.write(f"Recent Events from {log_type} Log\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(count_result.stdout)
                    
        except Exception as e:
            print(f"   ⚠️  [WARN] Failed to capture metadata for {log_type}: {e}")
    
    def _snapshot_linux_logs(self, snapshot_dir: Path):
        """Snapshot Linux system logs"""
        logs_dir = snapshot_dir / "system_logs"
        logs_dir.mkdir(exist_ok=True)
        
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/kern.log',
            '/var/log/audit/audit.log'
        ]
        
        for log_file in log_files:
            try:
                if os.path.exists(log_file):
                    dest = logs_dir / Path(log_file).name
                    shutil.copy2(log_file, dest)
            except Exception as e:
                print(f"   ⚠️  [WARN] Failed to copy {log_file}: {e}")
    
    def _snapshot_mac_logs(self, snapshot_dir: Path):
        """Snapshot Mac system logs"""
        logs_dir = snapshot_dir / "system_logs"
        logs_dir.mkdir(exist_ok=True)
        
        try:
            # Export unified log
            output_file = logs_dir / "system.log"
            # Bug 2 Fix: use context manager so file handle is always properly closed
            with open(output_file, 'w') as log_out:
                subprocess.run(
                    ['log', 'show', '--last', '1h'],
                    stdout=log_out,
                    timeout=5
                )
        except Exception as e:
            print(f"   ⚠️  [WARN] Mac log snapshot failed: {e}")
    
    def _snapshot_vss_state(self, snapshot_dir: Path):
        """Snapshot Volume Shadow Copy state (Windows only)"""
        if self.os_type != 'windows':
            return
        
        try:
            vss_file = snapshot_dir / "vss_state.txt"
            result = subprocess.run([
                'vssadmin', 'list', 'shadows'
            ], capture_output=True, text=True, timeout=5)
            
            with open(vss_file, 'w') as f:
                f.write(result.stdout)
        except Exception as e:
            print(f"   ⚠️  [WARN] VSS snapshot failed: {e}")
    
    def _snapshot_filesystem_metadata(self, snapshot_dir: Path):
        """Snapshot filesystem metadata"""
        try:
            metadata_file = snapshot_dir / "filesystem_metadata.txt"
            
            if self.os_type == 'windows':
                # FIXED: Avoid shell=True for security (Bug 2)
                result = subprocess.run([
                    'cmd', '/c', 'dir', '/s', '/a', 'C:\\'
                ], capture_output=True, text=True, timeout=10, shell=False)
            else:
                # Linux/Mac: use find
                result = subprocess.run([
                    'find', '/', '-type', 'f', '-ls'
                ], capture_output=True, text=True, timeout=10)
            
            with open(metadata_file, 'w') as f:
                f.write(result.stdout[:100000])  # Limit to 100KB
        except Exception as e:
            print(f"   ⚠️  [WARN] Filesystem snapshot failed: {e}")
    
    def _snapshot_process_state(self, snapshot_dir: Path, process_info: Dict):
        """Snapshot current process state"""
        try:
            import psutil
            import json
            
            state_file = snapshot_dir / "process_state.json"
            
            # Capture all running processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'create_time']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            state = {
                'timestamp': datetime.now().isoformat(),
                'trigger_process': process_info,
                'all_processes': processes[:100],  # Limit to 100 processes
                'system_info': {
                    'hostname': platform.node(),
                    'os': platform.system(),
                    'version': platform.version()
                }
            }
            
            with open(state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            print(f"   ⚠️  [WARN] Process state snapshot failed: {e}")

    def _snapshot_network_state(self, snapshot_dir: Path):
        """Snapshot current network state"""
        try:
            import psutil
            import json
            
            network_file = snapshot_dir / "network_state.json"
            
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                try:
                    connections.append({
                        'fd': conn.fd,
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
                except Exception as e:
                    print(f"   ⚠️  [WARN] Failed to capture connection metadata: {e}")
            
            with open(network_file, 'w') as f:
                json.dump(connections, f, indent=2)
                
        except Exception as e:
            print(f"   ⚠️  [WARN] Network state snapshot failed: {e}")
    
    def get_snapshot_info(self, snapshot_id: str) -> Dict[str, Any]:
        """Get information about a snapshot"""
        snapshot_dir = self.snapshots_dir / snapshot_id
        
        if not snapshot_dir.exists():
            return {'error': 'Snapshot not found'}
        
        # Calculate total size
        total_size = sum(f.stat().st_size for f in snapshot_dir.rglob('*') if f.is_file())
        
        # Count files
        file_count = len(list(snapshot_dir.rglob('*')))
        
        return {
            'snapshot_id': snapshot_id,
            'path': str(snapshot_dir),
            'total_size_bytes': total_size,
            'total_size_mb': total_size / (1024 * 1024),
            'file_count': file_count,
            'created': datetime.fromtimestamp(snapshot_dir.stat().st_ctime).isoformat()
        }
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all emergency snapshots"""
        snapshots = []
        
        for snapshot_dir in self.snapshots_dir.iterdir():
            if snapshot_dir.is_dir() and snapshot_dir.name.startswith('SNAP-'):
                snapshots.append(self.get_snapshot_info(snapshot_dir.name))
        
        return sorted(snapshots, key=lambda x: x['created'], reverse=True)
