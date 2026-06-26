"""
Evidence Vault
Secure evidence preservation and chain of evidence trail management
"""

import os
import json
import hashlib
import shutil
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import rfc3161ng
import requests


class EvidenceVault:
    """
    Secure evidence storage with chain of evidence trail tracking
    """
    
    def __init__(self, vault_path: str = "./evidence"):
        """
        Initialize Evidence Vault
        
        Args:
            vault_path: Path to evidence storage directory
        """
        self.vault_path = Path(vault_path)
        self.vault_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (self.vault_path / "incidents").mkdir(exist_ok=True)
        (self.vault_path / "artifacts").mkdir(exist_ok=True)
        (self.vault_path / "reports").mkdir(exist_ok=True)
        (self.vault_path / "logs").mkdir(exist_ok=True)
        
        self.chain_of_evidence_trail_file = self.vault_path / "chain_of_evidence_trail.json"
        self._trail_lock = threading.Lock()  # Bug 6 Fix: protect concurrent writes
        self._init_chain_of_evidence_trail()
    
    def _init_chain_of_evidence_trail(self):
        """Initialize chain of evidence trail log"""
        if not self.chain_of_evidence_trail_file.exists():
            with open(self.chain_of_evidence_trail_file, 'w') as f:
                json.dump([], f, indent=2)
    
    def preserve_evidence(self, incident_id: str, evidence_data: Dict[str, Any], 
                         evidence_type: str = "general") -> str:
        """
        Preserve evidence with chain of evidence trail
        
        Args:
            incident_id: Incident identifier
            evidence_data: Evidence to preserve
            evidence_type: Type of evidence
        
        Returns:
            Evidence ID
        """
        timestamp = datetime.now()
        evidence_id = f"EVD-{timestamp.strftime('%Y%m%d-%H%M%S')}-{evidence_type}"
        
        # Create incident directory
        incident_dir = self.vault_path / "incidents" / incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)
        
        # Save evidence
        evidence_file = incident_dir / f"{evidence_id}.json"
        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2)
        
        # Calculate hash for integrity
        evidence_hash = self._calculate_file_hash(evidence_file)
        
        # Record in chain of evidence trail
        tsa_token = self._get_rfc3161_timestamp(evidence_hash)
        
        evidence_trail_entry = {
            'evidence_id': evidence_id,
            'incident_id': incident_id,
            'evidence_type': evidence_type,
            'timestamp': timestamp.isoformat(),
            'file_path': str(evidence_file),
            'hash_sha256': evidence_hash,
            'tsa_rfc3161_token': tsa_token,
            'collected_by': 'ShadowKnight',
            'action': 'evidence_preserved'
        }
        
        self._add_evidence_trail_entry(evidence_trail_entry)
        
        return evidence_id
    
    def preserve_file_artifact(self, incident_id: str, source_file: str, 
                              artifact_type: str = "file") -> str:
        """
        Preserve a file artifact
        
        Args:
            incident_id: Incident identifier
            source_file: Path to source file
            artifact_type: Type of artifact
        
        Returns:
            Artifact ID
        """
        timestamp = datetime.now()
        artifact_id = f"ART-{timestamp.strftime('%Y%m%d-%H%M%S')}-{artifact_type}"
        
        # Create artifact directory
        artifact_dir = self.vault_path / "artifacts" / incident_id
        artifact_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy file
        source_path = Path(source_file)
        dest_file = artifact_dir / f"{artifact_id}_{source_path.name}"
        
        try:
            shutil.copy2(source_file, dest_file)
            
            # Calculate hash
            artifact_hash = self._calculate_file_hash(dest_file)
            
            # Record in chain of evidence trail
            tsa_token = self._get_rfc3161_timestamp(artifact_hash)
            
            evidence_trail_entry = {
                'artifact_id': artifact_id,
                'incident_id': incident_id,
                'artifact_type': artifact_type,
                'timestamp': timestamp.isoformat(),
                'source_path': str(source_file),
                'preserved_path': str(dest_file),
                'hash_sha256': artifact_hash,
                'tsa_rfc3161_token': tsa_token,
                'collected_by': 'ShadowKnight',
                'action': 'artifact_preserved'
            }
            
            self._add_evidence_trail_entry(evidence_trail_entry)
            
            return artifact_id
            
        except Exception as e:
            print(f"Failed to preserve artifact: {str(e)}")
            return ""
    
    def get_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve evidence by ID
        
        Args:
            evidence_id: Evidence identifier
        
        Returns:
            Evidence data or None
        """
        # Search for evidence file
        for incident_dir in (self.vault_path / "incidents").iterdir():
            if incident_dir.is_dir():
                evidence_file = incident_dir / f"{evidence_id}.json"
                if evidence_file.exists():
                    with open(evidence_file, 'r') as f:
                        return json.load(f)
        
        return None
    
    def get_incident_evidence(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Get all evidence for an incident
        
        Args:
            incident_id: Incident identifier
        
        Returns:
            List of evidence items
        """
        incident_dir = self.vault_path / "incidents" / incident_id
        
        if not incident_dir.exists():
            return []
        
        evidence_list = []
        for evidence_file in incident_dir.glob("*.json"):
            with open(evidence_file, 'r') as f:
                evidence_list.append(json.load(f))
        
        return evidence_list
    
    def get_chain_of_evidence_trail(self, incident_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get chain of evidence trail records library
        
        Args:
            incident_id: Optional incident filter
        
        Returns:
            Chain of evidence trail entries
        """
        with open(self.chain_of_evidence_trail_file, 'r') as f:
            all_entries = json.load(f)
        
        if incident_id:
            return [e for e in all_entries if e.get('incident_id') == incident_id]
        
        return all_entries
    
    def verify_evidence_integrity(self, evidence_id: str) -> bool:
        """
        Verify evidence has not been tampered with
        
        Args:
            evidence_id: Evidence identifier
        
        Returns:
            True if integrity verified
        """
        # Find evidence file
        for incident_dir in (self.vault_path / "incidents").iterdir():
            if incident_dir.is_dir():
                evidence_file = incident_dir / f"{evidence_id}.json"
                if evidence_file.exists():
                    # Calculate current hash
                    current_hash = self._calculate_file_hash(evidence_file)
                    
                    # Get original hash from chain of evidence trail
                    evidence_trail = self.get_chain_of_evidence_trail()
                    for entry in evidence_trail:
                        if entry.get('evidence_id') == evidence_id:
                            original_hash = entry.get('hash_sha256')
                            return current_hash == original_hash
        
        return False
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _add_evidence_trail_entry(self, entry: Dict[str, Any]):
        """Add entry to chain of evidence trail (thread-safe)"""
        # Bug 6 Fix: Lock ensures only one thread reads/writes the file at a time
        with self._trail_lock:
            with open(self.chain_of_evidence_trail_file, 'r') as f:
                evidence_trail = json.load(f)

            evidence_trail.append(entry)

            with open(self.chain_of_evidence_trail_file, 'w') as f:
                json.dump(evidence_trail, f, indent=2)

    def _get_rfc3161_timestamp(self, file_hash: str) -> Optional[str]:
        """
        Request cryptographic timestamp from a public TSA for BSA compliance.
        Uses a Free TSA (e.g. freetsa.org).
        """
        try:
            hash_bytes = bytes.fromhex(file_hash)
            req_obj = rfc3161ng.make_timestamp_request(hash_bytes, hashname='sha256')
            req_data = rfc3161ng.encode_timestamp_request(req_obj)
            
            headers = {'Content-Type': 'application/timestamp-query'}
            response = requests.post(
                'https://freetsa.org/tsr', 
                data=req_data, 
                headers=headers,
                timeout=(2.0, 2.0)
            )
            
            if response.status_code == 200:
                tst = rfc3161ng.decode_timestamp_response(response.content)
                if rfc3161ng.check_timestamp(tst, hashname='sha256', data_hash=hash_bytes):
                    import base64
                    return base64.b64encode(response.content).decode('utf-8')
        except Exception as e:
            print(f"⚠️  [TSA ERROR] Failed to acquire RFC 3161 timestamp: {e}")
            
        return None
    
    def save_report(self, incident_id: str, report_content: str, 
                   report_type: str = "technical") -> str:
        """
        Save generated report
        
        Args:
            incident_id: Incident identifier
            report_content: Report text
            report_type: Type of report
        
        Returns:
            Report file path
        """
        timestamp = datetime.now()
        report_file = self.vault_path / "reports" / f"{incident_id}_{report_type}_{timestamp.strftime('%Y%m%d-%H%M%S')}.md"
        
        # Write report first
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
            
        with open(report_file, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        tsa_token = self._get_rfc3161_timestamp(file_hash)

        self._add_evidence_trail_entry({
            'evidence_id': f"REP-{timestamp.strftime('%Y%m%d-%H%M%S')}",
            'incident_id': incident_id,
            'evidence_type': report_type,
            'timestamp': timestamp.isoformat(),
            'file_path': str(report_file),
            'hash_sha256': file_hash,
            'tsa_rfc3161_token': tsa_token,
            'collected_by': 'ShadowKnight',
            'action': 'report_generated'
        })
        
        return str(report_file)
    
    def get_vault_stats(self) -> Dict[str, Any]:
        """Get evidence vault statistics"""
        incidents = list((self.vault_path / "incidents").iterdir())
        artifacts = list((self.vault_path / "artifacts").iterdir())
        reports = list((self.vault_path / "reports").iterdir())
        
        return {
            'total_incidents': len(incidents),
            'total_artifacts': len(artifacts),
            'total_reports': len(reports),
            'vault_path': str(self.vault_path),
            'chain_of_evidence_trail_entries': len(self.get_chain_of_evidence_trail())
        }
