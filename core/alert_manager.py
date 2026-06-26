"""
Real-time Alert System
Sends instant notifications via Slack, Email, SMS, Discord, and more
"""

import requests
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class AlertChannel(str, Enum):
    """Alert delivery channels"""
    SLACK = "slack"
    EMAIL = "email"
    SMS = "sms"
    DISCORD = "discord"
    WEBHOOK = "webhook"
    CONSOLE = "console"


class AlertSeverity(str, Enum):
    """Alert severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertManager:
    """
    Multi-channel alert management system
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize alert manager
        
        Args:
            config: Alert configuration dictionary
        """
        self.config = config or {}
        
        # Statistics
        self.total_alerts_sent = 0
        self.alerts_by_channel: Dict[str, int] = {
            channel.value: 0 for channel in AlertChannel
        }
        self.alerts_by_severity: Dict[str, int] = {
            severity.value: 0 for severity in AlertSeverity
        }
    
    def send_alert(
        self,
        title: str,
        message: str,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        channels: Optional[List[AlertChannel]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, bool]:
        """
        Send alert through specified channels
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity level
            channels: List of channels to use (None = all configured)
            metadata: Additional alert metadata
        
        Returns:
            Dictionary of channel: success status
        """
        if channels is None:
            channels = self._get_configured_channels()
        
        results = {}
        
        for channel in channels:
            try:
                if channel == AlertChannel.SLACK:
                    success = self._send_slack(title, message, severity, metadata)
                elif channel == AlertChannel.EMAIL:
                    success = self._send_email(title, message, severity, metadata)
                elif channel == AlertChannel.SMS:
                    success = self._send_sms(title, message, severity, metadata)
                elif channel == AlertChannel.DISCORD:
                    success = self._send_discord(title, message, severity, metadata)
                elif channel == AlertChannel.WEBHOOK:
                    success = self._send_webhook(title, message, severity, metadata)
                elif channel == AlertChannel.CONSOLE:
                    success = self._send_console(title, message, severity, metadata)
                else:
                    success = False
                
                results[channel.value] = success
                
                if success:
                    self.alerts_by_channel[channel.value] += 1
            
            except Exception as e:
                print(f"Error sending alert via {channel.value}: {e}")
                results[channel.value] = False
        
        self.total_alerts_sent += 1
        self.alerts_by_severity[severity.value] += 1
        
        return results
    
    def _get_configured_channels(self) -> List[AlertChannel]:
        """Get list of configured alert channels"""
        channels = [AlertChannel.CONSOLE]  # Always include console
        
        if self.config.get('slack_webhook_url'):
            channels.append(AlertChannel.SLACK)
        
        if self.config.get('email_smtp_server'):
            channels.append(AlertChannel.EMAIL)
        
        if self.config.get('sms_api_key'):
            channels.append(AlertChannel.SMS)
        
        if self.config.get('discord_webhook_url'):
            channels.append(AlertChannel.DISCORD)
        
        if self.config.get('custom_webhook_url'):
            channels.append(AlertChannel.WEBHOOK)
        
        return channels
    
    def _send_slack(
        self, 
        title: str, 
        message: str, 
        severity: AlertSeverity,
        metadata: Optional[Dict[str, Any]]
    ) -> bool:
        """Send alert to Slack"""
        webhook_url = self.config.get('slack_webhook_url')
        if not webhook_url:
            return False
        
        # Color coding by severity
        color_map = {
            AlertSeverity.CRITICAL: "#FF0000",  # Red
            AlertSeverity.HIGH: "#FF6600",      # Orange
            AlertSeverity.MEDIUM: "#FFCC00",    # Yellow
            AlertSeverity.LOW: "#3366FF",       # Blue
            AlertSeverity.INFO: "#00CC66"       # Green
        }
        
        # Build Slack message
        slack_message = {
            "username": "ShadowKnight",
            "icon_emoji": ":shield:",
            "attachments": [{
                "color": color_map.get(severity, "#808080"),
                "title": f"🚨 {title}",
                "text": message,
                "fields": [
                    {
                        "title": "Severity",
                        "value": severity.value,
                        "short": True
                    },
                    {
                        "title": "Time",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "short": True
                    }
                ],
                "footer": "ShadowKnight Alert System",
                "ts": int(datetime.now().timestamp())
            }]
        }
        
        # Add metadata fields
        if metadata:
            for key, value in metadata.items():
                slack_message["attachments"][0]["fields"].append({
                    "title": key.replace('_', ' ').title(),
                    "value": str(value),
                    "short": True
                })
        
        try:
            response = requests.post(
                webhook_url,
                json=slack_message,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Slack error: {e}")
            return False
    
    def _send_email(
        self, 
        title: str, 
        message: str, 
        severity: AlertSeverity,
        metadata: Optional[Dict[str, Any]]
    ) -> bool:
        """Send alert via email"""
        smtp_server = self.config.get('email_smtp_server')
        smtp_port = self.config.get('email_smtp_port', 587)
        smtp_user = self.config.get('email_smtp_user')
        smtp_password = self.config.get('email_smtp_password')
        recipients = self.config.get('email_recipients', [])
        
        if not all([smtp_server, smtp_user, smtp_password, recipients]):
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{severity.value}] ShadowKnight: {title}"
            msg['From'] = smtp_user
            msg['To'] = ', '.join(recipients)
            
            # HTML email body
            html_body = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; }}
                    .alert-box {{
                        border-left: 4px solid {'#FF0000' if severity == AlertSeverity.CRITICAL else '#FF6600'};
                        padding: 15px;
                        background-color: #f9f9f9;
                    }}
                    .severity {{ 
                        font-weight: bold; 
                        color: {'#FF0000' if severity == AlertSeverity.CRITICAL else '#FF6600'};
                    }}
                    .metadata {{ 
                        background-color: #f0f0f0; 
                        padding: 10px; 
                        margin-top: 10px;
                    }}
                </style>
            </head>
            <body>
                <div class="alert-box">
                    <h2>🚨 {title}</h2>
                    <p><span class="severity">Severity:</span> {severity.value}</p>
                    <p><strong>Time:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <p>{message}</p>
                    
                    {self._format_metadata_html(metadata) if metadata else ''}
                </div>
                
                <p style="color: #888; font-size: 12px; margin-top: 20px;">
                    This alert was generated by ShadowKnight Alert System
                </p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
            return True
        
        except Exception as e:
            print(f"Email error: {e}")
            return False
    
    def _send_sms(
        self, 
        title: str, 
        message: str, 
        severity: AlertSeverity,
        metadata: Optional[Dict[str, Any]]
    ) -> bool:
        """Send alert via SMS (Twilio)"""
        # Twilio configuration
        account_sid = self.config.get('twilio_account_sid')
        auth_token = self.config.get('twilio_auth_token')
        from_number = self.config.get('twilio_from_number')
        to_numbers = self.config.get('sms_recipients', [])
        
        if not all([account_sid, auth_token, from_number, to_numbers]):
            return False
        
        try:
            # Shortened message for SMS
            sms_text = f"[{severity.value}] ShadowKnight: {title}\n{message[:100]}"
            
            # Send via Twilio API
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            
            for to_number in to_numbers:
                response = requests.post(
                    url,
                    auth=(account_sid, auth_token),
                    data={
                        'From': from_number,
                        'To': to_number,
                        'Body': sms_text
                    },
                    timeout=10
                )
                
                if response.status_code != 201:
                    return False
            
            return True
        
        except Exception as e:
            print(f"SMS error: {e}")
            return False
    
    def _send_discord(
        self, 
        title: str, 
        message: str, 
        severity: AlertSeverity,
        metadata: Optional[Dict[str, Any]]
    ) -> bool:
        """Send alert to Discord"""
        webhook_url = self.config.get('discord_webhook_url')
        if not webhook_url:
            return False
        
        # Color coding by severity
        color_map = {
            AlertSeverity.CRITICAL: 16711680,  # Red
            AlertSeverity.HIGH: 16737792,      # Orange
            AlertSeverity.MEDIUM: 16776960,    # Yellow
            AlertSeverity.LOW: 3447003,        # Blue
            AlertSeverity.INFO: 52224          # Green
        }
        
        discord_message = {
            "username": "ShadowKnight",
            "avatar_url": "https://example.com/shield-icon.png",
            "embeds": [{
                "title": f"🚨 {title}",
                "description": message,
                "color": color_map.get(severity, 8421504),
                "fields": [
                    {
                        "name": "Severity",
                        "value": severity.value,
                        "inline": True
                    },
                    {
                        "name": "Time",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "inline": True
                    }
                ],
                "footer": {
                    "text": "ShadowKnight Alert System"
                },
                "timestamp": datetime.now().isoformat()
            }]
        }
        
        # Add metadata
        if metadata:
            for key, value in metadata.items():
                discord_message["embeds"][0]["fields"].append({
                    "name": key.replace('_', ' ').title(),
                    "value": str(value),
                    "inline": True
                })
        
        try:
            response = requests.post(
                webhook_url,
                json=discord_message,
                timeout=10
            )
            return response.status_code == 204
        except Exception as e:
            print(f"Discord error: {e}")
            return False
    
    def _send_webhook(
        self, 
        title: str, 
        message: str, 
        severity: AlertSeverity,
        metadata: Optional[Dict[str, Any]]
    ) -> bool:
        """Send alert to custom webhook"""
        webhook_url = self.config.get('custom_webhook_url')
        if not webhook_url:
            return False
        
        payload = {
            "title": title,
            "message": message,
            "severity": severity.value,
            "timestamp": datetime.now().isoformat(),
            "source": "ShadowKnight",
            "metadata": metadata or {}
        }
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            return response.status_code in [200, 201, 204]
        except Exception as e:
            print(f"Webhook error: {e}")
            return False
    
    def _send_console(
        self, 
        title: str, 
        message: str, 
        severity: AlertSeverity,
        metadata: Optional[Dict[str, Any]]
    ) -> bool:
        """Print alert to console"""
        # Color codes for terminal
        color_map = {
            AlertSeverity.CRITICAL: "\033[91m",  # Red
            AlertSeverity.HIGH: "\033[93m",      # Yellow
            AlertSeverity.MEDIUM: "\033[94m",    # Blue
            AlertSeverity.LOW: "\033[96m",       # Cyan
            AlertSeverity.INFO: "\033[92m"       # Green
        }
        reset = "\033[0m"
        
        color = color_map.get(severity, "")
        
        print(f"\n{color}{'='*60}")
        print(f"🚨 ALERT: {title}")
        print(f"{'='*60}{reset}")
        print(f"{color}Severity: {severity.value}{reset}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{message}\n")
        
        if metadata:
            print("Additional Information:")
            for key, value in metadata.items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
        
        print(f"{color}{'='*60}{reset}\n")
        
        return True
    
    def _format_metadata_html(self, metadata: Dict[str, Any]) -> str:
        """Format metadata as HTML"""
        html = '<div class="metadata"><h3>Additional Information:</h3><ul>'
        for key, value in metadata.items():
            html += f'<li><strong>{key.replace("_", " ").title()}:</strong> {value}</li>'
        html += '</ul></div>'
        return html
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alert statistics"""
        return {
            'total_alerts_sent': self.total_alerts_sent,
            'alerts_by_channel': self.alerts_by_channel,
            'alerts_by_severity': self.alerts_by_severity,
            'configured_channels': [ch.value for ch in self._get_configured_channels()]
        }
