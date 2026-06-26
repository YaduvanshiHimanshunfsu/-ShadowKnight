"""
Gemini Behavior Analyzer
Detect anomalous user behavior and automated/bot activity
"""

import google.generativeai as genai
import json
from datetime import datetime
from typing import Dict, Any, List

from utils.model_selector import model_selector


class GeminiBehaviorAnalyzer:
    """
    Use Gemini to analyze user behavior patterns and detect anomalies
    No ML training required - Gemini learns patterns on the fly
    """
    
    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        genai.configure(api_key=api_key)
        # Validate model or pick best fast/intelligent one
        self.model_name = model_selector.validate_model(model_name)
        self.model = genai.GenerativeModel(self.model_name)
        self.user_baselines = {}  # Store user behavior baselines
    
    def analyze_keystroke_pattern(self, keystroke_timings: List[int]) -> Dict[str, Any]:
        """
        Analyze if keystrokes are human or automated
        
        Args:
            keystroke_timings: List of milliseconds between keystrokes
        
        Returns:
            Analysis of input type (human vs bot)
        """
        prompt = f"""
You are analyzing keystroke timing data to detect if input is from a human or automated script/bot.

KEYSTROKE INTERVALS (milliseconds): {keystroke_timings}

Human typing characteristics:
- Variable timing (100-250ms range with variance)
- Natural rhythm with occasional pauses
- Errors and corrections
- Fatigue effects over time

Bot/script characteristics:
- Extremely consistent timing (<10ms variance)
- Perfect regularity
- No pauses or corrections
- Sustained high speed

TASK: Determine if this is human or automated input.

Respond in JSON format:
{{
  "input_type": "human|bot|uncertain",
  "is_human": boolean,
  "confidence": 0.0-1.0,
  "evidence": ["list of specific patterns that support conclusion"],
  "statistical_summary": {{
    "mean_interval": number,
    "std_deviation": number,
    "min_interval": number,
    "max_interval": number
  }},
  "assessment": "Brief explanation"
}}

Calculate the statistical properties and explain your reasoning.
IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['analysis_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"Keystroke analysis failed: {str(e)}")
    
    def analyze_user_activity_sequence(self, user_id: str, recent_activities: List[Dict]) -> Dict[str, Any]:
        """
        Detect if user's current activities match their normal behavior
        
        Args:
            user_id: User identifier
            recent_activities: List of recent user activities
        
        Returns:
            Anomaly detection result
        """
        baseline = self.user_baselines.get(user_id, "No baseline available")
        
        prompt = f"""
You are analyzing user activity for anomalous behavior that might indicate account compromise or malicious insider.

USER ID: {user_id}

NORMAL BASELINE BEHAVIOR:
{baseline}

RECENT ACTIVITIES (last 30 minutes):
{json.dumps(recent_activities, indent=2)}

TASK: Determine if recent activities are consistent with this user's normal behavior.

Consider:
1. Time of day (does user normally work at this hour?)
2. Applications used (are these typical for this user?)
3. Data access patterns (accessing sensitive files they don't normally use?)
4. Command executions (running admin tools they've never used?)
5. Network connections (connecting to unusual systems?)
6. Volume and velocity of activities

Respond in JSON:
{{
  "anomaly_detected": true/false,
  "confidence": 0.0-1.0,
  "anomalous_activities": ["list specific unusual activities"],
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "possible_explanation": "compromised_account|insider_threat|legitimate_change|normal_behavior",
  "recommended_action": "immediate_investigation|monitor_closely|no_action",
  "reasoning": "Explain why this is/isn't anomalous",
  "risk_score": 0-100
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['user_id'] = user_id
            result['analysis_timestamp'] = datetime.now().isoformat()
            return result
        except Exception as e:
            return self._error_response(f"User activity analysis failed: {str(e)}")
    
    def build_user_baseline(self, user_id: str, historical_activities: List[Dict]) -> str:
        """
        Let Gemini create a behavioral baseline for a user
        
        Args:
            user_id: User identifier
            historical_activities: Historical activity data
        
        Returns:
            Baseline profile text
        """
        prompt = f"""
Analyze this user's historical activity and create a behavioral baseline profile.

USER ID: {user_id}

HISTORICAL ACTIVITIES (past 30 days):
{json.dumps(historical_activities[:100], indent=2)}

TASK: Create a behavioral profile summarizing:
1. Normal working hours
2. Typical applications/tools used
3. Common file access patterns
4. Usual network/system connections
5. Administrative activity frequency
6. Any notable patterns or routines
7. Typical activity volume per day

Provide a concise baseline profile (200-300 words) that can be used to detect future anomalies.
Focus on patterns, not individual events.
"""
        
        try:
            response = self.model.generate_content(prompt)
            baseline = response.text.strip()
            
            # Store baseline
            self.user_baselines[user_id] = baseline
            
            return baseline
        except Exception as e:
            return f"Failed to build baseline: {str(e)}"
    
    def analyze_command_sequence(self, command_sequence: List[str]) -> Dict[str, Any]:
        """
        Analyze sequence of commands for attack patterns
        
        Args:
            command_sequence: List of commands in chronological order
        
        Returns:
            Analysis of command sequence
        """
        prompt = f"""
Analyze this sequence of commands for attack patterns.

COMMAND SEQUENCE:
{json.dumps(command_sequence, indent=2)}

TASK: Identify if this sequence represents an attack pattern.

Look for:
1. Reconnaissance commands (whoami, net user, ipconfig)
2. Privilege escalation attempts
3. Lateral movement (PsExec, WMI, RDP)
4. Credential dumping (mimikatz, procdump)
5. Anti-forensics (log clearing, timestomping)
6. Data exfiltration preparation
7. Ransomware preparation (shadow copy deletion, backup deletion)

Respond in JSON:
{{
  "is_attack_sequence": true/false,
  "confidence": 0.0-1.0,
  "attack_phase": "reconnaissance|initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|exfiltration|impact",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "explanation": "What this sequence indicates",
  "next_likely_steps": ["predicted next attacker actions"],
  "mitre_attack_ttps": ["T1078", "T1003"],
  "recommended_response": "immediate_containment|monitor|investigate"
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            result = self._parse_json_response(response.text)
            result['analysis_timestamp'] = datetime.now().isoformat()
            result['command_count'] = len(command_sequence)
            return result
        except Exception as e:
            return self._error_response(f"Command sequence analysis failed: {str(e)}")
    
    def _parse_json_response(self, response_text: str) -> Dict[str, Any]:
        """Parse JSON from Gemini response"""
        response_text = response_text.strip()
        
        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.startswith('```'):
            response_text = response_text[3:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            return {
                'error': 'JSON parsing failed',
                'raw_response': response_text[:500]
            }
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Generate standardized error response"""
        return {
            'error': error_message,
            'confidence': 0.0,
            'analysis_timestamp': datetime.now().isoformat()
        }
