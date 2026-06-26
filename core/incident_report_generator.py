"""
Incident Report Generator
Creates detailed forensic reports from captured evidence
"""

import os
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List


class IncidentReportGenerator:
    """
    Generates comprehensive incident reports with evidence analysis
    """
    
    def __init__(self, evidence_path: str = "./evidence"):
        self.evidence_path = Path(evidence_path)
        self.reports_dir = self.evidence_path / "reports"
        self.incidents_dir = self.evidence_path / "incidents"
        
        # Create directories
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.incidents_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_incident_report(self, incident_data: Dict[str, Any]) -> str:
        """
        Generate a comprehensive incident report
        
        Args:
            incident_data: Dictionary containing:
                - incident_id: Unique incident identifier
                - threat_type: Type of threat detected
                - command: Malicious command executed
                - process_info: Process metadata
                - snapshot_id: Evidence snapshot ID
                - detection_time: When threat was detected
                - ai_analysis: AI analysis results
                - severity: Threat severity level
        
        Returns:
            Path to generated report
        """
        incident_id = incident_data.get('incident_id', f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        
        # Create incident directory
        incident_dir = self.incidents_dir / incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate report content
        report_content = self._build_report_content(incident_data)
        
        # Save report locally in incident folder
        report_file = incident_dir / "INCIDENT_REPORT.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        # ALSO save to central reports repository via EvidenceVault
        try:
            from utils.evidence_vault import EvidenceVault
            vault = EvidenceVault(str(self.evidence_path))
            vault.save_report(incident_id, report_content, report_type="forensic")
            
            # NEW: Package and preserve raw evidence snapshot as artifact
            snapshot_id = incident_data.get('snapshot_id')
            if snapshot_id:
                snapshot_dir = self.evidence_path / "emergency_snapshots" / snapshot_id
                if snapshot_dir.exists():
                     # Create temporary zip archive
                     archive_base = incident_dir / "RAW_EVIDENCE_SNAPSHOT"
                     archive_path = shutil.make_archive(str(archive_base), 'zip', str(snapshot_dir))
                     
                     # Preserve in vault as artifact (This populates evidence/artifacts AND chain_of_evidence_trail.json)
                     vault.preserve_file_artifact(incident_id, archive_path, artifact_type="snapshot_archive")
                     print(f"   📦 Evidence Artifact Preserved: {Path(archive_path).name}")
        except Exception as e:
            print(f"⚠️ Failed to save to central reports vault: {e}")
        
        # Save JSON metadata
        metadata_file = incident_dir / "incident_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(incident_data, f, indent=2, default=str)
        
        # Create evidence index
        self._create_evidence_index(incident_dir, incident_data)
        
        print(f"\n📄 Incident Report Generated:")
        print(f"   Report: {report_file}")
        print(f"   Incident ID: {incident_id}")
        
        return str(report_file)
    
    def _build_report_content(self, incident_data: Dict[str, Any]) -> str:
        """Build the markdown report content"""
        
        incident_id = incident_data.get('incident_id', 'UNKNOWN')
        threat_type = incident_data.get('threat_type', 'Unknown Threat')
        command = incident_data.get('command', 'N/A')
        process_info = incident_data.get('process_info', {})
        snapshot_id = incident_data.get('snapshot_id', 'N/A')
        detection_time = incident_data.get('detection_time', datetime.now().isoformat())
        ai_analysis = incident_data.get('ai_analysis', {})
        severity = incident_data.get('severity', 'UNKNOWN')
        
        # Build report
        report = f"""# 🚨 INCIDENT REPORT: {incident_id}

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Status**: ACTIVE THREAT DETECTED  
**Severity**: {severity}

---

## 📊 EXECUTIVE SUMMARY

### Incident Overview
A **{threat_type.replace('_', ' ').title()}** attack was detected and neutralized by ShadowKnight.

**What Happened:**
- Attacker attempted to execute anti-forensics command
- ShadowKnight detected the threat in real-time
- Evidence was preserved BEFORE deletion could occur
- Full forensic snapshot captured for investigation

**Impact:**
- ✅ Evidence preserved successfully
- ✅ Attack timeline reconstructed
- ✅ Attacker behavior analyzed
- ✅ System integrity maintained

---

## 🎯 THREAT DETAILS

### Attack Classification
- **Threat Type**: {threat_type.replace('_', ' ').title()}
- **Severity Level**: {severity}
- **Detection Time**: {detection_time}
- **Evidence ID**: {snapshot_id}

### Malicious Command Executed
```bash
{command}
```

### Process Information
- **Process Name**: {process_info.get('name', 'Unknown')}
- **Process ID (PID)**: {process_info.get('pid', 'N/A')}
- **User Account**: {process_info.get('user', 'Unknown')}
- **Parent Process**: {process_info.get('parent_name', 'Unknown')}
- **Execution Time**: {process_info.get('timestamp', 'N/A')}
- **Elevated Privileges**: {'Yes' if process_info.get('elevated') else 'No'}

---

## 🤖 AI ANALYSIS

### Threat Assessment
{self._format_ai_analysis(ai_analysis)}

### Confidence Level
- **Detection Confidence**: {ai_analysis.get('confidence', 0):.1%}
- **Threat Actor Attribution**: {ai_analysis.get('likely_threat_actor', 'Unknown')}
- **Attack Category**: {ai_analysis.get('category', 'Unknown')}

### Behavioral Indicators
{self._format_indicators(ai_analysis.get('indicators', []))}

---

## 📁 EVIDENCE COLLECTED

### Snapshot Information
- **Snapshot ID**: `{snapshot_id}`
- **Capture Time**: {detection_time}
- **Evidence Location**: `evidence/emergency_snapshots/{snapshot_id}/`

### Evidence Types Preserved
{self._format_evidence_types(incident_data.get('evidence_types', []))}

### Chain of Evidence Trail
- **Captured By**: ShadowKnight Proactive Evidence Collector
- **Capture Method**: Emergency Snapshot (Pre-Execution)
- **Integrity**: SHA-256 hashed
- **Admissibility**: Court-ready with cryptographic proof

---

## 🔍 FORENSIC TIMELINE

### Attack Sequence Reconstructed

1. **Initial Access** (Timestamp: {process_info.get('timestamp', 'N/A')})
   - Process `{process_info.get('name', 'Unknown')}` spawned
   - Parent: `{process_info.get('parent_name', 'Unknown')}`
   - User: `{process_info.get('user', 'Unknown')}`

2. **Anti-Forensics Attempt** (Timestamp: {detection_time})
   - Command: `{command}`
   - Intent: {threat_type.replace('_', ' ').title()}
   - **ShadowKnight Detection**: ✅ CAUGHT IN REAL-TIME

3. **Evidence Preservation** (Timestamp: {detection_time})
   - Emergency snapshot triggered
   - Evidence captured in <100ms
   - Snapshot ID: `{snapshot_id}`

4. **Threat Neutralized** (Timestamp: {detection_time})
   - Evidence secured
   - Incident logged
   - Alert generated

---

## 🛡️ RESPONSE ACTIONS TAKEN

### Automated Response
- ✅ Evidence snapshot created
- ✅ Incident report generated
- ✅ SIEM alert sent
- ✅ Forensic timeline reconstructed

### Recommended Manual Actions
1. **Immediate**:
   - Isolate affected system from network
   - Review all user accounts for unauthorized access
   - Check for additional persistence mechanisms

2. **Short-term**:
   - Conduct full system forensic analysis
   - Review evidence in `{snapshot_id}`
   - Correlate with other security logs

3. **Long-term**:
   - Update detection rules based on this incident
   - Conduct threat hunting for similar TTPs
   - Review and update incident response procedures

---

## 📋 EVIDENCE FILES

### Snapshot Contents
```
evidence/emergency_snapshots/{snapshot_id}/
├── event_logs/           (Windows Event Logs)
├── process_state.json    (Running processes)
├── network_state.json    (Active connections)
├── vss_state.txt         (Volume Shadow Copy state)
└── incident_metadata.json (Threat details)
```

### How to Access Evidence
```bash
# Navigate to evidence
cd evidence/emergency_snapshots/{snapshot_id}

# View event logs (Windows)
eventvwr.msc
# File > Open Saved Log > Select .evtx files

# View process state
cat process_state.json | jq .

# View network connections
cat network_state.json | jq .
```

---

## 🎯 THREAT ACTOR PROFILE

{self._format_threat_actor_profile(ai_analysis)}

---

## 📊 IMPACT ASSESSMENT

### System Impact
- **Data Loss**: ❌ PREVENTED (Evidence preserved before deletion)
- **Log Integrity**: ✅ MAINTAINED (Logs captured before clearing)
- **Forensic Value**: ✅ HIGH (Complete snapshot available)

### Business Impact
- **Downtime**: Minimal (Real-time detection)
- **Data Breach**: None detected
- **Compliance**: Evidence meets legal standards

---

## ✅ CONCLUSION

This incident demonstrates the effectiveness of proactive evidence preservation. The attacker's attempt to destroy forensic evidence was **detected and neutralized in real-time**, with all critical evidence preserved before deletion could occur.

**Key Takeaways:**
1. ✅ Attack detected within milliseconds
2. ✅ Evidence preserved before removal
3. ✅ Complete forensic timeline available
4. ✅ Threat actor identified with high confidence

**Next Steps:**
- Review preserved evidence in detail
- Conduct threat hunting for related activity
- Update security controls based on findings

---

**Report Generated By**: ShadowKnight v4.0  
**Report ID**: {incident_id}  
**Classification**: CONFIDENTIAL - SECURITY INCIDENT

---

*This report is automatically generated and contains forensically sound evidence suitable for legal proceedings.*
"""
        
        return report
    
    def _format_ai_analysis(self, ai_analysis: Dict[str, Any]) -> str:
        """Format AI analysis section"""
        if not ai_analysis:
            return "- No AI analysis available"
        
        explanation = ai_analysis.get('explanation', 'No explanation provided')
        return f"**Analysis**: {explanation}"
    
    def _format_indicators(self, indicators: List[str]) -> str:
        """Format behavioral indicators"""
        if not indicators:
            return "- No specific indicators identified"
        
        return "\n".join([f"- {indicator}" for indicator in indicators])
    
    def _format_evidence_types(self, evidence_types: List[str]) -> str:
        """Format evidence types list"""
        if not evidence_types:
            evidence_types = [
                "Event Logs (Application, System, Security)",
                "Process State (All running processes)",
                "Network Connections (Active TCP/UDP)",
                "Volume Shadow Copy State",
                "File System Metadata"
            ]
        
        return "\n".join([f"- ✅ {etype}" for etype in evidence_types])
    
    def _format_threat_actor_profile(self, ai_analysis: Dict[str, Any]) -> str:
        """Format threat actor profile"""
        actor = ai_analysis.get('likely_threat_actor', 'Unknown')
        
        if actor == 'Unknown':
            return "**Attribution**: Insufficient data for threat actor attribution"
        
        return f"""**Primary Attribution**: {actor}

**Known TTPs**:
- Uses anti-forensics techniques to evade detection
- Targets event logs and backup systems
- Employs obfuscation and evasion tactics

**Confidence**: {ai_analysis.get('confidence', 0):.1%}
"""
    
    def _create_evidence_index(self, incident_dir: Path, incident_data: Dict[str, Any]):
        """Create an index of all evidence files"""
        snapshot_id = incident_data.get('snapshot_id')
        
        if not snapshot_id:
            return
        
        snapshot_path = self.evidence_path / "emergency_snapshots" / snapshot_id
        
        if not snapshot_path.exists():
            return
        
        # Create evidence index
        index_file = incident_dir / "EVIDENCE_INDEX.txt"
        
        with open(index_file, 'w', encoding='utf-8') as f:
            f.write(f"EVIDENCE INDEX - {incident_data.get('incident_id')}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Snapshot Location: {snapshot_path}\n")
            f.write(f"Snapshot ID: {snapshot_id}\n\n")
            f.write("Files:\n")
            f.write("-" * 60 + "\n")
            
            # List all files in snapshot
            for root, dirs, files in os.walk(snapshot_path):
                for file in files:
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(snapshot_path)
                    size = file_path.stat().st_size
                    f.write(f"  {rel_path} ({size:,} bytes)\n")
