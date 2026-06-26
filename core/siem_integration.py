"""
SIEM Integration Module
Sends events to Splunk, QRadar, Elastic Stack, and other SIEM platforms
"""

import requests
import json
import socket
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum


class SIEMPlatform(str, Enum):
    """Supported SIEM platforms"""
    SPLUNK = "splunk"
    QRADAR = "qradar"
    ELASTIC = "elastic"
    ARCSIGHT = "arcsight"
    LOGRHYTHM = "logrhythm"
    SYSLOG = "syslog"


class SIEMIntegration:
    """
    Universal SIEM integration for sending security events
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize SIEM integration
        
        Args:
            config: SIEM configuration dictionary
        """
        self.config = config or {}
        
        # Statistics
        self.total_events_sent = 0
        self.events_by_platform: Dict[str, int] = {
            platform.value: 0 for platform in SIEMPlatform
        }
        self.failed_events = 0
    
    def send_event(
        self,
        event_data: Dict[str, Any],
        platforms: Optional[List[SIEMPlatform]] = None
    ) -> Dict[str, bool]:
        """
        Send security event to SIEM platforms
        
        Args:
            event_data: Event data dictionary
            platforms: List of SIEM platforms (None = all configured)
        
        Returns:
            Dictionary of platform: success status
        """
        if platforms is None:
            platforms = self._get_configured_platforms()
        
        # Enrich event with standard fields
        enriched_event = self._enrich_event(event_data)
        
        results = {}
        
        for platform in platforms:
            try:
                if platform == SIEMPlatform.SPLUNK:
                    success = self._send_to_splunk(enriched_event)
                elif platform == SIEMPlatform.QRADAR:
                    success = self._send_to_qradar(enriched_event)
                elif platform == SIEMPlatform.ELASTIC:
                    success = self._send_to_elastic(enriched_event)
                elif platform == SIEMPlatform.ARCSIGHT:
                    success = self._send_to_arcsight(enriched_event)
                elif platform == SIEMPlatform.LOGRHYTHM:
                    success = self._send_to_logrhythm(enriched_event)
                elif platform == SIEMPlatform.SYSLOG:
                    success = self._send_to_syslog(enriched_event)
                else:
                    success = False
                
                results[platform.value] = success
                
                if success:
                    self.events_by_platform[platform.value] += 1
                else:
                    self.failed_events += 1
            
            except Exception as e:
                print(f"Error sending to {platform.value}: {e}")
                results[platform.value] = False
                self.failed_events += 1
        
        self.total_events_sent += 1
        
        return results
    
    def _get_configured_platforms(self) -> List[SIEMPlatform]:
        """Get list of configured SIEM platforms"""
        platforms = []
        
        if self.config.get('splunk_hec_url'):
            platforms.append(SIEMPlatform.SPLUNK)
        
        if self.config.get('qradar_api_url'):
            platforms.append(SIEMPlatform.QRADAR)
        
        if self.config.get('elastic_url'):
            platforms.append(SIEMPlatform.ELASTIC)
        
        if self.config.get('syslog_server'):
            platforms.append(SIEMPlatform.SYSLOG)
        
        return platforms
    
    def _enrich_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich event with standard fields
        
        Args:
            event_data: Original event data
        
        Returns:
            Enriched event data
        """
        enriched = {
            'timestamp': event_data.get('timestamp', datetime.now().isoformat()),
            'source': 'ShadowKnight',
            'source_version': '4.0.0',
            'event_type': event_data.get('type', 'unknown'),
            'severity': event_data.get('severity', 'INFO'),
            'hostname': socket.gethostname(),
            **event_data
        }
        
        return enriched
    
    def _send_to_splunk(self, event_data: Dict[str, Any]) -> bool:
        """Send event to Splunk via HEC (HTTP Event Collector)"""
        hec_url = self.config.get('splunk_hec_url')
        hec_token = self.config.get('splunk_hec_token')
        
        if not hec_url or not hec_token:
            return False
        
        try:
            # Splunk HEC format
            payload = {
                'time': int(time.time()),
                'host': socket.gethostname(),
                'source': 'shadow_knight_nexus',
                'sourcetype': 'shadow_knight:security',
                'event': event_data
            }
            
            headers = {
                'Authorization': f'Splunk {hec_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{hec_url}/services/collector/event",
                json=payload,
                headers=headers,
                verify=self.config.get('splunk_verify_ssl', True),
                timeout=10
            )
            
            return response.status_code == 200
        
        except Exception as e:
            print(f"Splunk error: {e}")
            return False
    
    def _send_to_qradar(self, event_data: Dict[str, Any]) -> bool:
        """Send event to IBM QRadar via LEEF format"""
        api_url = self.config.get('qradar_api_url')
        api_token = self.config.get('qradar_api_token')
        
        if not api_url or not api_token:
            return False
        
        try:
            # LEEF (Log Event Extended Format) for QRadar
            leef_event = self._format_as_leef(event_data)
            
            headers = {
                'SEC': api_token,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{api_url}/api/ariel/events",
                json={'events': [leef_event]},
                headers=headers,
                verify=self.config.get('qradar_verify_ssl', True),
                timeout=10
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"QRadar error: {e}")
            return False
    
    def _send_to_elastic(self, event_data: Dict[str, Any]) -> bool:
        """Send event to Elastic Stack (Elasticsearch)"""
        elastic_url = self.config.get('elastic_url')
        elastic_index = self.config.get('elastic_index', 'shadow_knight-security')
        elastic_api_key = self.config.get('elastic_api_key')
        
        if not elastic_url:
            return False
        
        try:
            headers = {
                'Content-Type': 'application/json'
            }
            
            if elastic_api_key:
                headers['Authorization'] = f'ApiKey {elastic_api_key}'
            
            # ECS (Elastic Common Schema) format
            ecs_event = self._format_as_ecs(event_data)
            
            response = requests.post(
                f"{elastic_url}/{elastic_index}/_doc",
                json=ecs_event,
                headers=headers,
                verify=self.config.get('elastic_verify_ssl', True),
                timeout=10
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"Elastic error: {e}")
            return False
    
    def _send_to_arcsight(self, event_data: Dict[str, Any]) -> bool:
        """Send event to ArcSight via CEF format"""
        arcsight_url = self.config.get('arcsight_url')
        
        if not arcsight_url:
            return False
        
        try:
            # CEF (Common Event Format) for ArcSight
            cef_event = self._format_as_cef(event_data)
            
            response = requests.post(
                arcsight_url,
                data=cef_event,
                headers={'Content-Type': 'text/plain'},
                timeout=10
            )
            
            return response.status_code == 200
        
        except Exception as e:
            print(f"ArcSight error: {e}")
            return False
    
    def _send_to_logrhythm(self, event_data: Dict[str, Any]) -> bool:
        """Send event to LogRhythm"""
        logrhythm_url = self.config.get('logrhythm_url')
        logrhythm_token = self.config.get('logrhythm_token')
        
        if not logrhythm_url or not logrhythm_token:
            return False
        
        try:
            headers = {
                'Authorization': f'Bearer {logrhythm_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{logrhythm_url}/lr-admin-api/logs",
                json=event_data,
                headers=headers,
                timeout=10
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"LogRhythm error: {e}")
            return False
    
    def _send_to_syslog(self, event_data: Dict[str, Any]) -> bool:
        """Send event via Syslog (RFC 5424)"""
        syslog_server = self.config.get('syslog_server')
        syslog_port = self.config.get('syslog_port', 514)
        
        if not syslog_server:
            return False
        
        try:
            # RFC 5424 Syslog format
            severity_map = {
                'CRITICAL': 2,  # Critical
                'HIGH': 3,      # Error
                'MEDIUM': 4,    # Warning
                'LOW': 5,       # Notice
                'INFO': 6       # Informational
            }
            
            severity = severity_map.get(event_data.get('severity', 'INFO'), 6)
            facility = 16  # Local0
            priority = (facility * 8) + severity
            
            message = json.dumps(event_data)
            syslog_message = f"<{priority}>1 {event_data.get('timestamp')} {socket.gethostname()} ShadowKnightNexus - - - {message}\n"
            
            # Send via UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(syslog_message.encode('utf-8'), (syslog_server, syslog_port))
            sock.close()
            
            return True
        
        except Exception as e:
            print(f"Syslog error: {e}")
            return False
    
    def _format_as_leef(self, event_data: Dict[str, Any]) -> str:
        """Format event as LEEF (Log Event Extended Format) for QRadar"""
        # LEEF:Version|Vendor|Product|Version|EventID|
        leef = f"LEEF:2.0|ShadowKnight|Nexus|4.0|{event_data.get('type', 'unknown')}|"
        
        # Add key-value pairs
        fields = []
        for key, value in event_data.items():
            if key not in ['type']:
                fields.append(f"{key}={value}")
        
        leef += '\t'.join(fields)
        return leef
    
    def _format_as_ecs(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format event as ECS (Elastic Common Schema)"""
        return {
            '@timestamp': event_data.get('timestamp'),
            'event': {
                'kind': 'alert',
                'category': ['threat'],
                'type': [event_data.get('type', 'unknown')],
                'severity': self._map_severity_to_ecs(event_data.get('severity', 'INFO'))
            },
            'host': {
                'name': socket.gethostname()
            },
            'observer': {
                'name': 'ShadowKnight',
                'version': '4.0.0'
            },
            'threat': {
                'indicator': event_data.get('threat_indicators', [])
            },
            'shadow_knight': event_data  # Original data
        }
    
    def _format_as_cef(self, event_data: Dict[str, Any]) -> str:
        """Format event as CEF (Common Event Format) for ArcSight"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        severity = self._map_severity_to_cef(event_data.get('severity', 'INFO'))
        
        cef = f"CEF:0|ShadowKnight|Nexus|4.0|{event_data.get('type', 'unknown')}|{event_data.get('title', 'Security Event')}|{severity}|"
        
        # Add extensions
        extensions = []
        for key, value in event_data.items():
            if key not in ['type', 'title', 'severity']:
                extensions.append(f"{key}={value}")
        
        cef += ' '.join(extensions)
        return cef
    
    def _map_severity_to_ecs(self, severity: str) -> int:
        """Map severity to ECS numeric value"""
        mapping = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'INFO': 0
        }
        return mapping.get(severity, 0)
    
    def _map_severity_to_cef(self, severity: str) -> int:
        """Map severity to CEF numeric value (0-10)"""
        mapping = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 5,
            'LOW': 3,
            'INFO': 1
        }
        return mapping.get(severity, 1)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get SIEM integration statistics"""
        return {
            'total_events_sent': self.total_events_sent,
            'failed_events': self.failed_events,
            'success_rate': (
                f"{((self.total_events_sent - self.failed_events) / self.total_events_sent * 100) if self.total_events_sent > 0 else 0:.1f}%"
            ),
            'events_by_platform': self.events_by_platform,
            'configured_platforms': [p.value for p in self._get_configured_platforms()]
        }
