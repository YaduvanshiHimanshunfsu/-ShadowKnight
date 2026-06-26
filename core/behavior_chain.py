"""
core/behavior_chain.py

Role: Tracks sequences of user commands over time to identify MITRE ATT&CK attack chains.
Libraries used: collections.deque, datetime
Function in project: Reduces false positives by looking at the broader context of an attack
(e.g., Reconnaissance followed by Defense Evasion) rather than single isolated commands.
"""

from collections import deque
from datetime import datetime, timedelta
import re

# MITRE ATT&CK Chain Signatures
CHAIN_PATTERNS = {
    "Ransomware_Preparation": {
        "stages": ["vssadmin", "wevtutil", "bcdedit"],
        "min_stages_required": 2,
        "multiplier": 2.0,
        "description": "Volume Shadow Copy deletion followed by log clearing or boot modification."
    },
    "Credential_Theft_Chain": {
        "stages": ["whoami", "procdump", "reg save"],
        "min_stages_required": 2,
        "multiplier": 1.8,
        "description": "Reconnaissance followed by LSASS dumping or SAM registry export."
    },
    "Defense_Evasion_Chain": {
        "stages": ["powershell -enc", "sdelete", "cipher"],
        "min_stages_required": 2,
        "multiplier": 1.5,
        "description": "Obfuscated execution followed by secure file wiping."
    }
}

class BehaviorChainTracker:
    def __init__(self, time_window_minutes=30):
        self.time_window = timedelta(minutes=time_window_minutes)
        # Dictionary mapping username to a deque of (timestamp, command_line)
        self.user_history = {}
        
    def add_event(self, username: str, command: str):
        """Records a command for a specific user and prunes old events."""
        if not username:
            username = "SYSTEM"
            
        now = datetime.now()
        
        if username not in self.user_history:
            self.user_history[username] = deque()
            
        self.user_history[username].append((now, command.lower()))
        self._prune_history(username, now)
        
    def _prune_history(self, username: str, current_time: datetime):
        """Removes events older than the time window."""
        history = self.user_history[username]
        while history and (current_time - history[0][0]) > self.time_window:
            history.popleft()
            
    def analyze_chain(self, username: str, current_command: str) -> dict:
        """
        Analyzes the user's recent history to see if the current command
        completes a known attack chain.
        """
        self.add_event(username, current_command)
        history = self.user_history[username]
        
        # Extract just the command strings from the history
        recent_commands = [cmd for _, cmd in history]
        
        result = {
            "chain_detected": False,
            "chain_name": None,
            "multiplier": 1.0,
            "matched_commands": []
        }
        
        for chain_name, pattern in CHAIN_PATTERNS.items():
            matches_found = []
            
            for stage_keyword in pattern["stages"]:
                # Check if this stage exists anywhere in the recent commands
                if any(stage_keyword in cmd for cmd in recent_commands):
                    matches_found.append(stage_keyword)
                    
            if len(matches_found) >= pattern["min_stages_required"]:
                result["chain_detected"] = True
                result["chain_name"] = chain_name
                result["multiplier"] = pattern["multiplier"]
                result["matched_commands"] = matches_found
                
                # If multiple chains match, we take the highest multiplier
                break
                
        return result
