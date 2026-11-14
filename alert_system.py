import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertSystem:
    def __init__(self, config):
        self.config = config

    def send_email_alert(self, alert_data):
        """Send email alert"""
        try:
            if not all([self.config['MAIL_USERNAME'], self.config['MAIL_PASSWORD']]):
                logger.warning("Email credentials not configured")
                return False

            msg = MIMEMultipart()
            msg['From'] = self.config['MAIL_USERNAME']
            msg['To'] = self.config['ADMIN_EMAIL']
            msg['Subject'] = f"🚨 HoneyToken Alert: {alert_data['risk_category'].upper()} Activity Detected"

            # Email body
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: {'#d63031' if alert_data['risk_category'] == 'malicious' else '#f39c12'}">
                    🔥 SECURITY ALERT - HoneyToken Triggered
                </h2>

                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <h3>📊 Alert Details:</h3>
                    <p><strong>Risk Level:</strong> <span style="color: {'#d63031' if alert_data['risk_category'] == 'malicious' else '#f39c12'}">{alert_data['risk_category'].upper()}</span></p>
                    <p><strong>Risk Score:</strong> {alert_data['risk_score']:.2%}</p>
                    <p><strong>Time:</strong> {alert_data['access_time']}</p>
                    <p><strong>Source IP:</strong> {alert_data['source_ip']}</p>
                    <p><strong>Location:</strong> {alert_data.get('country', 'Unknown')}, {alert_data.get('city', 'Unknown')}</p>
                    <p><strong>Token Type:</strong> {alert_data['token_type']}</p>
                    <p><strong>Token Value:</strong> <code>{alert_data['token_value'][:50]}...</code></p>
                </div>

                <div style="background-color: #e8f4fd; padding: 15px; border-radius: 5px; margin: 15px 0;">
                    <h3>🎯 AI Analysis:</h3>
                    <p><strong>Confidence:</strong> {alert_data['confidence']:.2%}</p>
                    <p><strong>Anomaly Score:</strong> {alert_data.get('anomaly_score', 'N/A')}</p>
                    <p><strong>Triggered Patterns:</strong> {', '.join(alert_data.get('triggered_patterns', ['Multiple access attempts']))}</p>
                </div>

                <div style="margin-top: 20px; padding: 10px; background-color: #2d3436; color: white; border-radius: 5px;">
                    <p><strong>⚠️ Recommended Actions:</strong></p>
                    <ul>
                        <li>Review access logs in dashboard</li>
                        <li>Check related systems for compromise</li>
                        <li>Consider blocking source IP if malicious</li>
                        <li>Update firewall rules if needed</li>
                    </ul>
                </div>

                <hr>
                <p style="color: #7f8c8d; font-size: 12px;">
                    This is an automated alert from HoneyToken Security System.<br>
                    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </p>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            # Send email
            with smtplib.SMTP(self.config['MAIL_SERVER'], self.config['MAIL_PORT']) as server:
                server.starttls()
                server.login(self.config['MAIL_USERNAME'], self.config['MAIL_PASSWORD'])
                server.send_message(msg)

            logger.info(f"Email alert sent to {self.config['ADMIN_EMAIL']}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def send_telegram_alert(self, alert_data):
        """Send Telegram alert"""
        try:
            if not all([self.config['TELEGRAM_BOT_TOKEN'], self.config['TELEGRAM_CHAT_ID']]):
                logger.warning("Telegram credentials not configured")
                return False

            # Format message
            risk_emoji = {
                'safe': '✅',
                'suspicious': '⚠️',
                'malicious': '🚨'
            }.get(alert_data['risk_category'], '⚠️')

            message = f"""
{risk_emoji} *HONEYTOKEN ALERT* {risk_emoji}

*Risk Level:* {alert_data['risk_category'].upper()}
*Score:* {alert_data['risk_score']:.2%}
*Time:* {alert_data['access_time']}
*IP:* `{alert_data['source_ip']}`
*Location:* {alert_data.get('country', 'Unknown')}
*Token:* {alert_data['token_type']}

*AI Confidence:* {alert_data['confidence']:.2%}
*Action Required:* {'IMMEDIATE' if alert_data['risk_category'] == 'malicious' else 'Review'}
"""

            url = f"https://api.telegram.org/bot{self.config['TELEGRAM_BOT_TOKEN']}/sendMessage"
            payload = {
                'chat_id': self.config['TELEGRAM_CHAT_ID'],
                'text': message,
                'parse_mode': 'Markdown'
            }

            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                logger.info("Telegram alert sent successfully")
                return True
            else:
                logger.error(f"Telegram API error: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False

    def send_alert(self, alert_data, alert_type='all'):
        """Send alert based on type"""
        results = {}

        if alert_type in ['email', 'all']:
            results['email'] = self.send_email_alert(alert_data)

        if alert_type in ['telegram', 'all']:
            results['telegram'] = self.send_telegram_alert(alert_data)

        return results