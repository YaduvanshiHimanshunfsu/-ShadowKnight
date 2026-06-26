"""
ShadowKnight - Enhanced Prompt Library
Centralized storage for complex AI prompts
"""

IMPROVED_COMMAND_ANALYSIS_PROMPT = """
You are an expert Cyber Forensics AI specializing in Anti-Forensics detection.
Analyze the following command execution context to determine if it represents an attempt to destroy evidence, hide tracks, or impede a forensic investigation.

CONTEXT:
- Command: {command_line}
- Process Name: {process_name} (PID: {pid})
- Parent Process: {parent_name} (PID: {parent_pid})
- User: {user}
- Time: {timestamp}
- Working Directory: {cwd}
- Elevated Privileges: {is_elevated}

Your task is to identify anti-forensics techniques such as:
1. Log Clearing (wevtutil, Clear-EventLog, rm -rf /var/log, etc.)
2. Artifact Deletion (sdelete, cipher /w, vssadmin delete shadows, etc.)
3. Timestamp Manipulation (timestomp, touch -t, etc.)
4. Obfuscated Execution (Base64 PowerShell, encoded bash, etc.)
5. Renamed System Binaries (mimikatz.exe renamed to notepad.exe, etc.)

Analyze the INTENT and SEVERITY. 

Respond ONLY with a valid JSON object in the following format:
{{
  "is_anti_forensics": boolean,
  "confidence": float (0.0 to 1.0),
  "category": "log_clearing|artifact_deletion|timestamp_manipulation|obfuscation|renamed_binary|credential_theft|persistence|benign|unknown",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|NONE",
  "explanation": "Brief, clear explanation of your reasoning",
  "threat_indicators": ["list", "of", "trigger", "words", "or", "patterns"],
  "recommended_action": "immediate_containment|monitor|investigate|none",
  "likely_threat_actor": "Briefly mention if TTPs match known groups, or 'Unknown'",
  "mitre_attack_ttps": ["T1070.001", "..."],
  "context_notes": "Any other relevant forensic observations"
}}
"""
