"""
Gemini Report Generator
Generate professional forensic reports automatically
"""

import google.generativeai as genai
import json
from datetime import datetime
from typing import Dict, Any

from utils.model_selector import model_selector


class GeminiReportGenerator:
    """
    Let Gemini write professional, tamper-evident forensic reports
    """
    
    def __init__(self, api_key: str, model_name: str = 'gemini-2.5-flash'):
        """Use Pro model for high-quality report generation"""
        genai.configure(api_key=api_key)
        # Validate model or pick best intelligent one
        self.model_name = model_selector.validate_model(model_name)
        self.model = genai.GenerativeModel(self.model_name)
    
    def generate_executive_summary(self, incident_data: Dict[str, Any]) -> str:
        """
        Generate executive-level incident report
        
        Args:
            incident_data: Incident details
        
        Returns:
            Executive summary text
        """
        prompt = f"""
You are a senior cybersecurity consultant writing an executive summary for a board of directors.

INCIDENT DATA:
{json.dumps(incident_data, indent=2)}

Write a professional executive summary that:
1. Explains WHAT happened in non-technical terms
2. States WHO was responsible (threat actor attribution)
3. Describes IMPACT (what was affected, potential damage)
4. Summarizes RESPONSE (what was done to contain and remediate)
5. Provides RECOMMENDATIONS (how to prevent future incidents)

Format:
- 1-2 pages maximum
- Non-technical language (avoid jargon)
- Bullet points for key findings
- Clear action items
- Professional tone suitable for C-level executives

Include sections:
- Incident Overview
- Timeline of Events
- Impact Assessment
- Threat Actor Profile
- Response Actions
- Recommendations
- Financial Implications (if applicable)

Write in clear, professional markdown format.
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"# Executive Summary Generation Failed\n\nError: {str(e)}"
    
    def generate_technical_report(self, incident_data: Dict[str, Any], 
                                  evidence_inventory: Dict[str, Any]) -> str:
        """
        Generate detailed technical forensic report
        
        Args:
            incident_data: Incident details
            evidence_inventory: Evidence collected
        
        Returns:
            Technical report text
        """
        prompt = f"""
You are a digital forensics expert writing a technical analysis report.

INCIDENT DATA:
{json.dumps(incident_data, indent=2)}

EVIDENCE INVENTORY:
{json.dumps(evidence_inventory, indent=2)}

Write a comprehensive technical forensic report including:

1. **Executive Summary**
   - Brief technical overview

2. **Evidence Summary**
   - Chain of evidence trail
   - Evidence integrity verification
   - List of artifacts collected

3. **Attack Timeline**
   - Detailed chronological sequence
   - Evidence supporting each event
   - Confidence levels

4. **Technical Analysis**
   - Initial access vector
   - Privilege escalation methods
   - Lateral movement techniques
   - Anti-forensics techniques employed
   - Data exfiltration (if any)
   - Tools and malware used

5. **Indicators of Compromise (IOCs)**
   - File hashes
   - IP addresses
   - Domain names
   - Registry keys
   - Process names

6. **Threat Actor Attribution**
   - Primary attribution with confidence level
   - Evidence supporting attribution
   - Known TTPs of attributed actor

7. **Recommendations**
   - Immediate containment actions
   - Short-term remediation
   - Long-term security improvements
   - Detection rule deployment

Format as a professional forensic report suitable for:
- Internal security teams
- Legal proceedings
- Insurance claims
- Regulatory compliance

Use proper forensic report structure and terminology.
Write in markdown format with clear sections.
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"# Technical Report Generation Failed\n\nError: {str(e)}"
    
    def generate_ioc_feed(self, incident_data: Dict[str, Any]) -> str:
        """
        Generate STIX/machine-readable IOC feed
        
        Args:
            incident_data: Incident details
        
        Returns:
            STIX 2.1 JSON
        """
        prompt = f"""
You are generating a threat intelligence feed in STIX 2.1 format.

INCIDENT DATA:
{json.dumps(incident_data, indent=2)}

Extract all Indicators of Compromise (IOCs) and format as STIX 2.1 JSON.

Include:
- Indicator objects (file hashes, IPs, domains, URLs)
- Malware objects (if malware identified)
- Attack Pattern objects (TTPs used)
- Threat Actor object (attributed actor)
- Relationship objects (linking indicators to actors and patterns)

Generate valid STIX 2.1 JSON that can be:
1. Imported into threat intelligence platforms
2. Shared via TAXII servers
3. Used to update detection rules

Ensure all STIX objects have:
- Unique IDs
- Timestamps
- Confidence scores
- Descriptions
- Proper relationships

Output valid STIX 2.1 JSON only.
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return json.dumps({'error': f'IOC feed generation failed: {str(e)}'}, indent=2)
    
    def generate_incident_summary(self, incident_data: Dict[str, Any]) -> str:
        """
        Generate concise incident summary for alerts/notifications
        
        Args:
            incident_data: Incident details
        
        Returns:
            Brief summary text
        """
        prompt = f"""
Generate a concise incident summary (3-5 sentences) for security team notification.

INCIDENT DATA:
{json.dumps(incident_data, indent=2)}

Include:
- What happened
- Severity
- Threat actor (if known)
- Current status
- Immediate action required

Keep it brief and actionable. Use clear, direct language.
"""
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            return f"Incident summary generation failed: {str(e)}"
    
    def generate_timeline_visualization_data(self, timeline: list) -> Dict[str, Any]:
        """
        Generate data structure for timeline visualization
        
        Args:
            timeline: Attack timeline
        
        Returns:
            Visualization-ready data
        """
        prompt = f"""
Convert this attack timeline into a visualization-ready format.

TIMELINE:
{json.dumps(timeline, indent=2)}

Generate JSON for timeline visualization with:
- Events grouped by attack phase
- Color coding by severity
- Icons for event types
- Tooltips with details

Respond in JSON:
{{
  "events": [
    {{
      "timestamp": "ISO timestamp",
      "title": "brief title",
      "description": "details",
      "phase": "reconnaissance|initial_access|execution|persistence|etc.",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "icon": "icon name",
      "color": "hex color code"
    }}
  ],
  "phases": ["ordered list of attack phases"],
  "summary": "overall timeline summary"
}}

IMPORTANT: Respond ONLY with valid JSON.
"""
        
        try:
            response = self.model.generate_content(prompt)
            response_text = response.text.strip()
            
            # Parse JSON
            if response_text.startswith('```json'):
                response_text = response_text[7:]
            if response_text.startswith('```'):
                response_text = response_text[3:]
            if response_text.endswith('```'):
                response_text = response_text[:-3]
            
            return json.loads(response_text.strip())
        except Exception as e:
            return {'error': f'Timeline visualization generation failed: {str(e)}'}
