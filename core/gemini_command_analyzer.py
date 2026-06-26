"""
Gemini Command Analyzer
Intelligent command-line analysis for anti-forensics detection
"""

import google.generativeai as genai
import json
from datetime import datetime
from typing import Dict, Any

from utils.model_selector import model_selector


class GeminiCommandAnalyzer:
    """
    Use Gemini to analyze if command is anti-forensics activity
    Understands CONTEXT and INTENT, not just keyword matching
    """
    
    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        """
        Initialize Gemini Command Analyzer
        
        Args:
            api_key: Gemini API key
            model_name: Model to use (flash for speed, pro for accuracy)
        """
        genai.configure(api_key=api_key)
        # Validate model or pick best fast/intelligent one
        self.model_name = model_selector.validate_model(model_name)
        self.model = genai.GenerativeModel(self.model_name)
    
    def analyze_command(self, command_line: str, process_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use Gemini to analyze if command is anti-forensics activity
        
        Args:
            command_line: The command being executed
            process_info: Process metadata (PID, parent, user, etc.)
        
        Returns:
            Analysis result with threat assessment
        """
        from utils.command_decoder import CommandDecoder, command_history
        from prompts.enhanced_prompts import IMPROVED_COMMAND_ANALYSIS_PROMPT
        from datetime import datetime
        
        # Decode if obfuscated
        decoded_command, obfuscation_techniques = CommandDecoder.decode_if_encoded(command_line)
        
        # Check for renamed binary
        is_renamed = CommandDecoder.detect_renamed_binary(
            process_info.get('name', ''),
            command_line
        )
        
        # Add to command history for behavioral analysis
        user = process_info.get('user', 'Unknown')
        command_history.add_command(user, command_line, process_info)
        
        # Build enhanced prompt with all context
        prompt = IMPROVED_COMMAND_ANALYSIS_PROMPT.format(
            command_line=decoded_command,
            process_name=process_info.get('name', 'Unknown'),
            pid=process_info.get('pid', 'N/A'),
            parent_name=process_info.get('parent_name', 'Unknown'),
            parent_pid=process_info.get('parent_pid', 'N/A'),
            user=user,
            timestamp=process_info.get('timestamp', datetime.now().isoformat()),
            cwd=process_info.get('cwd', 'Unknown'),
            is_elevated='YES' if process_info.get('elevated') else 'NO'
        )
        
        try:
            response = self.model.generate_content(prompt)
            
            # Extract JSON from response
            response_text = response.text.strip()
            
            # Remove markdown code blocks if present
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            
            response_text = response_text.strip()
            
            result = json.loads(response_text)
            
            # Add metadata
            result['analysis_timestamp'] = datetime.now().isoformat()
            result['model_used'] = self.model_name
            result['command_analyzed'] = command_line
            result['decoded_command'] = decoded_command if decoded_command != command_line else None
            result['obfuscation_detected'] = obfuscation_techniques
            result['renamed_binary_suspected'] = is_renamed
            
            return result
            
        except json.JSONDecodeError as e:
            # Fallback if JSON parsing fails
            return {
                'is_anti_forensics': True,
                'confidence': 0.5,
                'category': 'unknown',
                'severity': 'MEDIUM',
                'explanation': f'Failed to parse Gemini response: {str(e)}',
                'threat_indicators': ['parsing_error'],
                'recommended_action': 'monitor',
                'likely_threat_actor': 'Unknown',
                'context_notes': f'Raw response: {response.text[:200]}',
                'mitre_attack_ttps': [],
                'analysis_timestamp': datetime.now().isoformat(),
                'model_used': self.model_name,
                'command_analyzed': command_line,
                'error': str(e)
            }
        
        except Exception as e:
            # General error handling
            error_msg = str(e)
            
            # Check if API quota exceeded (429 error)
            if "429" in error_msg or "quota" in error_msg.lower():
                return {
                    'is_anti_forensics': True,  # Flag as threat as a safety fallback
                    'confidence': 0.6,          # Medium confidence (keyword match only)
                    'category': 'keyword_match_fallback',
                    'severity': 'MEDIUM',
                    'explanation': f'API quota exceeded. Flagging as suspicious based on keyword match. Error: {error_msg[:100]}',
                    'threat_indicators': ['quota_exceeded', 'keyword_fallback'],
                    'recommended_action': 'review_manually',
                    'api_quota_exceeded': True,
                    'analysis_timestamp': datetime.now().isoformat(),
                    'model_used': self.model_name,
                    'command_analyzed': command_line,
                    'error': error_msg
                }

            return {
                'is_anti_forensics': False,
                'confidence': 0.0,
                'category': 'error',
                'severity': 'LOW',
                'explanation': f'Analysis failed: {str(e)}',
                'threat_indicators': [],
                'recommended_action': 'ignore',
                'likely_threat_actor': 'None',
                'context_notes': 'Error during analysis',
                'mitre_attack_ttps': [],
                'analysis_timestamp': datetime.now().isoformat(),
                'model_used': self.model_name,
                'command_analyzed': command_line,
                'error': str(e)
            }
    
    def batch_analyze_commands(self, commands: list) -> list:
        """
        Analyze multiple commands in a single API call (cost optimization)
        
        Args:
            commands: List of (command_line, process_info) tuples
        
        Returns:
            List of analysis results
        """
        if not commands:
            return []
        
        # Build batch prompt
        commands_text = "\n\n".join([
            f"COMMAND {i+1}:\n{cmd}\nPROCESS INFO: {json.dumps(info)}"
            for i, (cmd, info) in enumerate(commands)
        ])
        
        prompt = f"""
Analyze these {len(commands)} commands for anti-forensics activity.

{commands_text}

For each command, provide analysis in JSON array format.
Respond with a JSON array of objects, one per command.
"""
        
        try:
            response = self.model.generate_content(prompt)
            # Bug 8 Fix: strip markdown code fences before parsing
            response_text = response.text.strip()
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            results = json.loads(response_text.strip())
            return results
        except Exception as e:
            # Fallback to individual analysis
            return [self.analyze_command(cmd, info) for cmd, info in commands]
