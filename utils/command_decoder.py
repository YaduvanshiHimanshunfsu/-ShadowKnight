"""
Command Decoding and Obfuscation Detection Utilities
Detects and decodes Base64, hex, and other encoding schemes
"""

import base64
import re
from typing import Dict, List, Tuple


class CommandDecoder:
    """Decode obfuscated commands before AI analysis"""
    
    @staticmethod
    def decode_if_encoded(command: str) -> Tuple[str, List[str]]:
        """
        Decode Base64/hex if present
        
        Args:
            command: Raw command string
            
        Returns:
            Tuple of (decoded_command, list_of_obfuscation_techniques)
        """
        obfuscation_techniques = []
        decoded_command = command
        
        # Check for PowerShell Base64
        if '-enc' in command.lower() or '-encodedcommand' in command.lower():
            match = re.search(r'-enc(?:odedcommand)?\s+([A-Za-z0-9+/=]+)', command, re.IGNORECASE)
            if match:
                try:
                    encoded_part = match.group(1)
                    decoded = base64.b64decode(encoded_part).decode('utf-16-le', errors='ignore')
                    decoded_command = f"{command} [DECODED: {decoded}]"
                    obfuscation_techniques.append("powershell_base64")
                except Exception:
                    pass
        
        # Check for Base64 in general
        base64_pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
        potential_base64 = re.findall(base64_pattern, command)
        for b64_str in potential_base64:
            if len(b64_str) > 20:  # Ignore short matches
                try:
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                    if decoded.isprintable() and len(decoded) > 5:
                        decoded_command += f" [POSSIBLE_BASE64: {decoded}]"
                        obfuscation_techniques.append("base64_encoding")
                        break
                except Exception:
                    pass
        
        # Check for string concatenation obfuscation
        if re.search(r'["\'][\s]*\+[\s]*["\']', command):
            obfuscation_techniques.append("string_concatenation")
            # Try to reconstruct
            reconstructed = re.sub(r'["\'][\s]*\+[\s]*["\']', '', command)
            decoded_command += f" [RECONSTRUCTED: {reconstructed}]"
        
        # Check for hex encoding
        hex_pattern = r'0x[0-9a-fA-F]+'
        if re.search(hex_pattern, command):
            obfuscation_techniques.append("hex_encoding")
        
        # Check for unusual whitespace/casing
        if re.search(r'[A-Z]{2,}[a-z]{2,}[A-Z]{2,}', command):
            obfuscation_techniques.append("mixed_case_evasion")
        
        # Check for special character insertion
        if re.search(r'[a-z][\^`]', command):
            obfuscation_techniques.append("special_char_insertion")
        
        return decoded_command, obfuscation_techniques
    
    @staticmethod
    def detect_renamed_binary(process_name: str, command: str) -> bool:
        """
        Detect if a binary has been renamed to evade detection
        
        Args:
            process_name: Name of the executing process
            command: Command being executed
            
        Returns:
            True if binary appears renamed
        """
        # Common system binaries
        system_binaries = ['svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe']
        
        # Suspicious: system binary name but unusual command
        if process_name.lower() in system_binaries:
            suspicious_commands = ['mimikatz', 'procdump', 'invoke-', 'download']
            if any(cmd in command.lower() for cmd in suspicious_commands):
                return True
        
        return False


class CommandHistory:
    """Track command history per user for behavioral analysis"""
    
    def __init__(self, max_size: int = 10):
        self.history: Dict[str, List[Dict]] = {}
        self.max_size = max_size
    
    def add_command(self, user: str, command: str, process_info: Dict):
        """Add command to user's history"""
        from datetime import datetime
        
        if user not in self.history:
            self.history[user] = []
        
        self.history[user].append({
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'process': process_info.get('name', 'Unknown'),
            'pid': process_info.get('pid', 0)
        })
        
        # Keep only last N commands
        if len(self.history[user]) > self.max_size:
            self.history[user].pop(0)
    
    def get_recent(self, user: str, n: int = 10) -> List[Dict]:
        """Get recent commands for user"""
        return self.history.get(user, [])[-n:]
    
    def get_command_sequence(self, user: str) -> str:
        """Get formatted command sequence for AI analysis"""
        commands = self.get_recent(user)
        if not commands:
            return "No command history available"
        
        sequence = []
        for i, cmd in enumerate(commands, 1):
            sequence.append(f"{i}. [{cmd['timestamp']}] {cmd['process']}: {cmd['command']}")
        
        return "\n".join(sequence)
    
    def detect_attack_pattern(self, user: str) -> Dict:
        """Detect if command sequence matches known attack patterns"""
        commands = self.get_recent(user)
        if len(commands) < 3:
            return {"pattern_detected": False}
        
        command_text = " ".join([cmd['command'].lower() for cmd in commands])
        
        patterns = {
            "ransomware_prep": ["vssadmin", "wevtutil", "bcdedit"],
            "credential_theft": ["mimikatz", "lsass", "procdump"],
            "lateral_movement": ["psexec", "wmic", "net use"],
            "reconnaissance": ["net view", "nltest", "whoami", "ipconfig"]
        }
        
        detected_patterns = []
        for pattern_name, keywords in patterns.items():
            if sum(1 for kw in keywords if kw in command_text) >= 2:
                detected_patterns.append(pattern_name)
        
        if detected_patterns:
            return {
                "pattern_detected": True,
                "patterns": detected_patterns,
                "confidence": 0.8 if len(detected_patterns) > 1 else 0.6
            }
        
        return {"pattern_detected": False}


# Global instance for easy access
command_history = CommandHistory()
