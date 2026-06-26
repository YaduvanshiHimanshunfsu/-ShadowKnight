"""
Proactive Evidence Collector
Captures evidence BEFORE anti-forensics commands execute
Cross-platform support with automatic OS detection
"""

import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

from utils.os_detector import os_detector

# Bug 3 Fix: single conditional import — removed the unconditional top-level
# import that bypassed the HAS_DEPENDENCIES guard.
try:
    import psutil
    from .emergency_snapshot import EmergencySnapshotEngine
    HAS_DEPENDENCIES = True
except ImportError as e:
    HAS_DEPENDENCIES = False
    print(f"⚠️  [WARN] Missing dependencies in ProactiveEvidenceCollector: {e}")


class ProactiveEvidenceCollector:
    """
    Captures evidence BEFORE anti-forensics commands can destroy it
    The "security camera backup" feature
    """
    
    def __init__(self, evidence_vault_path: str = "./evidence", enabled: bool = True, capture_network: bool = True, suspicious_keywords: List[str] = None):
        """
        Initialize Proactive Evidence Collector
        
        Args:
            evidence_vault_path: Path to evidence vault
            enabled: Enable proactive collection (requires admin/root)
            capture_network: Whether to capture network connections during a snapshot
            suspicious_keywords: List of keywords from config.yaml to monitor
        """
        self.evidence_vault_path = evidence_vault_path
        self.suspicious_keywords = suspicious_keywords or []

        # Initialize dependencies
        if not HAS_DEPENDENCIES:
            print("❌ ProactiveEvidenceCollector: Missing OS dependencies")

        # Allow evidence collection even without admin, but with limited capabilities
        self.has_admin = os_detector.is_admin
        self.enabled = enabled  # Always enabled if requested
        
        self.snapshot_engine = EmergencySnapshotEngine(evidence_vault_path, capture_network=capture_network)
        self.os_type = os_detector.os_type
        self.capabilities = os_detector.get_capabilities()
        
        # Threat type mapping - NOW DYNAMIC FROM CONFIG
        self.threat_patterns = self._build_threat_patterns()
        
        # Statistics
        self.snapshots_taken = 0
        self.evidence_preserved_mb = 0.0
        
        if not self.enabled:
            print("⚠️  Proactive Evidence Collector: DISABLED")
        elif not self.has_admin:
            print(f"⚠️  Proactive Evidence Collector: ENABLED ({self.os_type.upper()}) - LIMITED MODE (no admin)")
            print("   Some evidence types may not be accessible without admin/root privileges")
        else:
            print(f"✅ Proactive Evidence Collector: ENABLED ({self.os_type.upper()}) - FULL MODE")
        
        print(f"   📋 Monitoring {len(self.threat_patterns)} threat patterns from config.yaml")
    
    def _build_threat_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Build threat patterns dynamically from config.yaml keywords"""
        patterns = {}
        
        # Automatically create patterns for ALL keywords from config
        for keyword in self.suspicious_keywords:
            keyword_lower = keyword.lower()
            
            # Classify threat type based on keyword
            if any(x in keyword_lower for x in ['wevtutil', 'clear-eventlog', 'log', 'history', 'journal']):
                threat_type = 'log_clearing'
                severity = 'CRITICAL'
            elif any(x in keyword_lower for x in ['vss', 'shadow']):
                threat_type = 'vss_manipulation'
                severity = 'CRITICAL'
            elif any(x in keyword_lower for x in ['cipher', 'sdelete', 'shred', 'wipe', 'bleach', 'ccleaner']):
                threat_type = 'file_wiping'
                severity = 'HIGH'
            elif any(x in keyword_lower for x in ['mimikatz', 'procdump', 'dumpert', 'lsass', 'ntds', 'samlib']):
                threat_type = 'credential_theft'
                severity = 'CRITICAL'
            elif any(x in keyword_lower for x in ['encoded', '-enc', 'invoke', 'iex', 'certutil', 'mshta', 'regsvr32']):
                threat_type = 'obfuscation'
                severity = 'HIGH'
            elif any(x in keyword_lower for x in ['schtasks', 'wmic', 'persistence']):
                threat_type = 'persistence'
                severity = 'HIGH'
            elif any(x in keyword_lower for x in ['nc', 'netcat', 'bash -i', '/dev/tcp', 'reverse']):
                threat_type = 'reverse_shell'
                severity = 'CRITICAL'
            elif any(x in keyword_lower for x in ['curl', 'wget', 'bitsadmin', 'download']):
                threat_type = 'download_execute'
                severity = 'MEDIUM'
            elif any(x in keyword_lower for x in ['bcdedit', 'mountvol', 'fsutil']):
                threat_type = 'system_manipulation'
                severity = 'HIGH'
            elif any(x in keyword_lower for x in ['timestomp']):
                threat_type = 'timestamp_manipulation'
                severity = 'HIGH'
            else:
                # Default for any other suspicious keyword
                threat_type = 'suspicious_activity'
                severity = 'MEDIUM'
            
            patterns[keyword] = {
                'threat_type': threat_type,
                'severity': severity,
                'description': f'Suspicious keyword detected: {keyword}'
            }
        
        return patterns
    
    def should_capture(self, command: str) -> Optional[Dict[str, Any]]:
        """
        Determine if command requires proactive evidence capture
        
        Args:
            command: Command being executed
        
        Returns:
            Threat info if capture needed, None otherwise
        """
        if not self.enabled:
            print(f"   ⚠️  Proactive capture DISABLED")
            return None
        
        # Decode command if obfuscated (Base64, etc.)
        from utils.command_decoder import CommandDecoder
        decoded_command, obfuscation_techniques = CommandDecoder.decode_if_encoded(command)
        
        # Check both original and decoded command
        commands_to_check = [command.lower(), decoded_command.lower()]
        
        print(f"   🔍 Checking if proactive capture needed...")
        print(f"   Command: {command[:100]}...")
        
        for cmd_to_check in commands_to_check:
            for pattern, threat_info in self.threat_patterns.items():
                if pattern.lower() in cmd_to_check:
                    print(f"   ✅ MATCH! Pattern: '{pattern}' found in command")
                    
                    # If obfuscation was detected, increase severity
                    if obfuscation_techniques and threat_info['severity'] != 'CRITICAL':
                        threat_info = threat_info.copy()
                        threat_info['description'] += f" (Obfuscated: {', '.join(obfuscation_techniques)})"
                        # Upgrade severity if obfuscated
                        severity_upgrade = {'LOW': 'MEDIUM', 'MEDIUM': 'HIGH', 'HIGH': 'CRITICAL'}
                        threat_info['severity'] = severity_upgrade.get(threat_info['severity'], 'CRITICAL')
                    return threat_info
        
        print(f"   ⏸️  No proactive capture pattern matched")
        return None
    
    def capture_threat_context(self, threat_type: str, details: Dict[str, Any]) -> Optional[str]:
        """
        Force a forensic capture based on a detected threat context
        
        Args:
            threat_type: Type of threat (e.g., 'network_c2', 'ransomware')
            details: Threat details for inclusion in the report
        
        Returns:
            Snapshot ID if captured, None otherwise
        """
        if not self.enabled:
            return None
            
        print(f"\n🚨 FORENSIC CAPTURE: {threat_type.upper()}")
        
        try:
            snapshot_id = self.snapshot_engine.emergency_snapshot(
                threat_type=threat_type,
                command="REAL_TIME_MONITORING",
                process_info=details
            )
            
            self.snapshots_taken += 1
            snapshot_info = self.snapshot_engine.get_snapshot_info(snapshot_id)
            self.evidence_preserved_mb += snapshot_info.get('total_size_mb', 0)
            
            return snapshot_id
        except Exception as e:
            print(f"   ❌ Forensic capture failed: {str(e)}")
            return None

    def capture_before_execution(self, command: str, process_info: Dict[str, Any]) -> Optional[str]:
        """
        Capture evidence BEFORE anti-forensics command executes
        
        Args:
            command: Command to be executed
            process_info: Process metadata
        
        Returns:
            Snapshot ID if captured, None otherwise
        """
        threat_info = self.should_capture(command)

        if not threat_info:
            return None
        
        print(f"\n🚨 PROACTIVE CAPTURE TRIGGERED!")
        print(f"   Threat: {threat_info['description']}")
        print(f"   Severity: {threat_info['severity']}")
        print(f"   Command: {command}")
        
        try:
            # Execute emergency snapshot
            snapshot_id = self.snapshot_engine.emergency_snapshot(
                threat_type=threat_info['threat_type'],
                command=command,
                process_info=process_info
            )
            
            # Update statistics
            self.snapshots_taken += 1
            snapshot_info = self.snapshot_engine.get_snapshot_info(snapshot_id)
            self.evidence_preserved_mb += snapshot_info.get('total_size_mb', 0)
            
            print(f"   ✅ Evidence preserved BEFORE deletion!")
            print(f"   📊 Total snapshots: {self.snapshots_taken}")
            print(f"   💾 Evidence preserved: {self.evidence_preserved_mb:.2f} MB\n")
            
            return snapshot_id
            
        except Exception as e:
            print(f"   ❌ Proactive capture failed: {str(e)}\n")
            import traceback
            traceback.print_exc()
            return None
    
    def on_threat_detected(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle threat detection and trigger evidence preservation
        
        Args:
            threat_info: Threat information including command, category, severity, process_info
        
        Returns:
            Dictionary with preservation results
        """
        if not self.enabled:
            return {
                'snapshot_taken': False,
                'reason': 'Proactive collector disabled (requires admin/root privileges)'
            }
        
        command = threat_info.get('command', '')
        category = threat_info.get('category', 'unknown')
        severity = threat_info.get('severity', 'MEDIUM')
        process_info = threat_info.get('process_info', {})
        
        # Capture evidence before the threat executes
        snapshot_id = self.capture_before_execution(command, process_info)
        
        if snapshot_id:
            return {
                'snapshot_taken': True,
                'snapshot_id': snapshot_id,
                'collected_evidence': [
                    'Memory dump',
                    'Event logs',
                    'Process list',
                    'Network connections',
                    'File system snapshot'
                ],
                'threat_category': category,
                'severity': severity,
                'preservation_time': datetime.now().isoformat()
            }
        else:
            return {
                'snapshot_taken': False,
                'reason': 'Evidence preservation triggered but may require elevated privileges',
                'threat_category': category,
                'severity': severity
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get proactive collection statistics"""
        return {
            'enabled': self.enabled,
            'os_type': self.os_type,
            'snapshots_taken': self.snapshots_taken,
            'evidence_preserved_mb': self.evidence_preserved_mb,
            'capabilities': self.capabilities,
            'threat_patterns_count': len(self.threat_patterns)
        }
    
    def list_preserved_evidence(self) -> list:
        """List all proactively preserved evidence"""
        return self.snapshot_engine.list_snapshots()
    
    def get_preserved_evidence(self, snapshot_id: str) -> Dict[str, Any]:
        """Get details of preserved evidence"""
        return self.snapshot_engine.get_snapshot_info(snapshot_id)
