# app2.py
import os
import json
import random
import string
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['DATABASE'] = 'honeytoken.db'

# Email Configuration
app.config['EMAIL_HOST'] = 'smtp.gmail.com'
app.config['EMAIL_PORT'] = 587
app.config['EMAIL_USER'] = 'mysecretid1996@gmail.com'  # Change this
app.config['EMAIL_PASSWORD'] = 'feqeokahfkmqhidg'  # Change this (use App Password for Gmail)
app.config['ADMIN_EMAIL'] = 'mysecretid1996@gmail.com'  # Change this

# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Database setup
def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    ''')

    # Honeytokens table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS honeytokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token_type TEXT NOT NULL,
        token_value TEXT UNIQUE NOT NULL,
        token_name TEXT NOT NULL,
        description TEXT,
        created_by INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        deployment_location TEXT,
        access_count INTEGER DEFAULT 0,
        last_accessed TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )
    ''')

    # Access logs table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        honeytoken_id INTEGER,
        source_ip TEXT,
        user_agent TEXT,
        country TEXT DEFAULT 'Unknown',
        city TEXT DEFAULT 'Unknown',
        action_type TEXT DEFAULT 'ACCESS',
        payload TEXT,
        risk_score REAL DEFAULT 0.0,
        classification TEXT DEFAULT 'normal',
        access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        http_method TEXT,
        request_path TEXT,
        token_status TEXT,
        FOREIGN KEY (honeytoken_id) REFERENCES honeytokens(id)
    )
    ''')

    # Alerts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        log_id INTEGER,
        alert_type TEXT,
        alert_message TEXT,
        severity TEXT DEFAULT 'medium',
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        acknowledged BOOLEAN DEFAULT 0,
        acknowledged_by INTEGER,
        acknowledged_at TIMESTAMP,
        FOREIGN KEY (log_id) REFERENCES access_logs(id),
        FOREIGN KEY (acknowledged_by) REFERENCES users(id)
    )
    ''')

    # Settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_key TEXT UNIQUE NOT NULL,
        setting_value TEXT,
        description TEXT,
        category TEXT DEFAULT 'general'
    )
    ''')

    # Insert default settings
    default_settings = [
        ('email_alerts_enabled', 'true', 'Enable email alerts', 'email'),
        ('email_recipients', app.config['ADMIN_EMAIL'], 'Comma-separated list of email recipients', 'email'),
        ('alert_on_malicious', 'true', 'Send alert on malicious access', 'alerts'),
        ('alert_on_suspicious', 'false', 'Send alert on suspicious access', 'alerts'),
        ('auto_block_ips', 'false', 'Auto-block malicious IPs', 'security'),
        ('block_duration_days', '7', 'Days to block IPs', 'security')
    ]

    for key, value, desc, category in default_settings:
        cursor.execute('''
            INSERT OR IGNORE INTO settings (setting_key, setting_value, description, category)
            VALUES (?, ?, ?, ?)
        ''', (key, value, desc, category))

    # Create default admin if not exists
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        hashed = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', app.config['ADMIN_EMAIL'], hashed, 'Administrator', 'admin'))

    conn.commit()
    conn.close()


def get_db():
    """Get database connection"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn


def get_setting(key, default=None):
    """Get setting from database"""
    conn = get_db()
    setting = conn.execute('SELECT setting_value FROM settings WHERE setting_key = ?', (key,)).fetchone()
    conn.close()
    return setting['setting_value'] if setting else default


# User class for Flask-Login - FIXED VERSION
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data['email']
        self.full_name = user_data['full_name']
        self.role = user_data['role']
        self._is_active = bool(user_data['is_active'])  # Use different name

    @property
    def is_active(self):
        """Required by Flask-Login"""
        return self._is_active


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user)
    return None


# Email Functions
def send_email_alert(subject, message, to_emails=None):
    """Send email alert"""
    if not app.config['EMAIL_USER'] or not app.config['EMAIL_PASSWORD']:
        print("Email credentials not configured")
        return False

    if not to_emails:
        # Get recipients from settings or use admin email
        recipients = get_setting('email_recipients', app.config['ADMIN_EMAIL'])
        to_emails = [email.strip() for email in recipients.split(',')]

    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = app.config['EMAIL_USER']
        msg['To'] = ', '.join(to_emails)
        msg['Subject'] = subject

        # Create HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #4361ee, #3a0ca3); color: white; padding: 20px; border-radius: 10px 10px 0 0; }}
                .content {{ background: #f8f9fa; padding: 20px; border-radius: 0 0 10px 10px; }}
                .alert-box {{ background: #dc3545; color: white; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                .info-box {{ background: #17a2b8; color: white; padding: 15px; border-radius: 5px; margin: 15px 0; }}
                .footer {{ text-align: center; margin-top: 20px; color: #6c757d; font-size: 12px; }}
                pre {{ background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>🚨 Honeytoken Alert</h2>
                    <p>Security Notification</p>
                </div>
                <div class="content">
                    {message.replace(chr(10), '<br>')}
                    <div class="footer">
                        <p>This is an automated alert from Honeytoken Detection System</p>
                        <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p>Do not reply to this email.</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html_content, 'html'))

        # Connect to SMTP server
        server = smtplib.SMTP(app.config['EMAIL_HOST'], app.config['EMAIL_PORT'])
        server.starttls()
        server.login(app.config['EMAIL_USER'], app.config['EMAIL_PASSWORD'])

        # Send email
        server.send_message(msg)
        server.quit()

        print(f"✅ Email alert sent to {', '.join(to_emails)}")
        return True

    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False


# Helper functions
def generate_honeytoken(token_type):
    """Generate realistic honeytokens"""
    if token_type == 'api_key':
        return f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=20))}"
    elif token_type == 'file':
        return f"secret_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    elif token_type == 'database':
        return f"Username: admin_honey, Password: {''.join(random.choices(string.ascii_letters + string.digits, k=12))}"
    elif token_type == 'url':
        return f"https://api.honeytrap.com/v1/secret/{''.join(random.choices(string.ascii_lowercase + string.digits, k=20))}"
    else:
        return ''.join(random.choices(string.ascii_letters + string.digits + '!@#$%^&*', k=16))


def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr


def admin_required(f):
    """Decorator to require admin role"""

    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        print(f"DEBUG: Login attempt - Username: {username}, Password: {password}")  # Debug

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user:
            print(f"DEBUG: User found - {user['username']}")  # Debug

            # Check if password matches
            password_matches = bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
            print(f"DEBUG: Password matches: {password_matches}")  # Debug

            if password_matches:
                # Check if user is active
                if not bool(user['is_active']):
                    flash('Your account is disabled.', 'danger')
                    return redirect(url_for('login'))

                user_obj = User(user)
                login_user(user_obj)

                # Update last login
                conn = get_db()
                conn.execute('UPDATE users SET last_login = ? WHERE id = ?',
                             (datetime.now(), user['id']))
                conn.commit()
                conn.close()

                flash(f'Welcome back, {user["username"]}!', 'success')
                print(f"DEBUG: Login successful, redirecting to dashboard")  # Debug
                return redirect(url_for('dashboard'))
            else:
                print("DEBUG: Password check failed")  # Debug
        else:
            print("DEBUG: User not found")  # Debug

        flash('Invalid username or password', 'danger')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')

        conn = get_db()

        # Check if user exists
        existing = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?',
                                (username, email)).fetchone()
        if existing:
            flash('Username or email already exists', 'danger')
            conn.close()
            return redirect(url_for('signup'))

        # Create user
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, hashed, full_name, 'user'))
        conn.commit()
        conn.close()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()

    # Get statistics
    stats = conn.execute('''
        SELECT 
            (SELECT COUNT(*) FROM honeytokens) as total_tokens,
            (SELECT COUNT(*) FROM honeytokens WHERE is_active = 1) as active_tokens,
            (SELECT COUNT(*) FROM access_logs) as total_accesses,
            (SELECT COUNT(*) FROM access_logs WHERE classification = 'malicious') as malicious_accesses,
            (SELECT COUNT(*) FROM alerts WHERE acknowledged = 0) as unread_alerts
    ''').fetchone()

    # Get recent logs
    recent_logs = conn.execute('''
        SELECT al.*, ht.token_name, ht.token_type
        FROM access_logs al
        LEFT JOIN honeytokens ht ON al.honeytoken_id = ht.id
        ORDER BY al.access_time DESC LIMIT 10
    ''').fetchall()

    # Get token distribution
    token_dist = conn.execute('''
        SELECT token_type, COUNT(*) as count
        FROM honeytokens
        WHERE is_active = 1
        GROUP BY token_type
    ''').fetchall()

    conn.close()

    return render_template('dashboard.html',
                           stats=stats,
                           recent_logs=recent_logs,
                           token_dist=token_dist,
                           now=datetime.now)


@app.route('/tokens', methods=['GET', 'POST'])
@login_required
def tokens():
    conn = get_db()

    if request.method == 'POST':
        token_type = request.form.get('token_type')
        token_name = request.form.get('token_name')
        description = request.form.get('description', '')

        if not token_type or not token_name:
            flash('Token type and name are required', 'danger')
            return redirect(url_for('tokens'))

        token_value = generate_honeytoken(token_type)
        expires_at = datetime.now() + timedelta(days=30)

        conn.execute('''
            INSERT INTO honeytokens 
            (token_type, token_value, token_name, description, created_by, expires_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (token_type, token_value, token_name, description, current_user.id, expires_at, 1))
        conn.commit()

        flash(f'Honeytoken "{token_name}" created successfully!', 'success')
        return redirect(url_for('tokens'))

    # Get all tokens
    tokens = conn.execute('''
        SELECT ht.*, u.username as created_by_name
        FROM honeytokens ht
        LEFT JOIN users u ON ht.created_by = u.id
        ORDER BY ht.created_at DESC
    ''').fetchall()

    conn.close()

    return render_template('tokens.html', tokens=tokens)


@app.route('/logs')
@login_required
def logs():
    conn = get_db()

    # Get filter parameters
    classification = request.args.get('classification', 'all')
    search = request.args.get('search', '')

    # Build query
    query = '''
        SELECT al.*, ht.token_name, ht.token_type
        FROM access_logs al
        LEFT JOIN honeytokens ht ON al.honeytoken_id = ht.id
        WHERE 1=1
    '''
    params = []

    if classification != 'all':
        query += ' AND al.classification = ?'
        params.append(classification)

    if search:
        query += ' AND (ht.token_name LIKE ? OR al.source_ip LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])

    query += ' ORDER BY al.access_time DESC'

    logs = conn.execute(query, params).fetchall()
    conn.close()

    return render_template('logs.html',
                           logs=logs,
                           classification=classification,
                           search=search)


@app.route('/alerts')
@login_required
def alerts():
    conn = get_db()

    # Get all alerts
    alerts_data = conn.execute('''
        SELECT a.*, al.source_ip, al.classification, ht.token_name
        FROM alerts a
        LEFT JOIN access_logs al ON a.log_id = al.id
        LEFT JOIN honeytokens ht ON al.honeytoken_id = ht.id
        ORDER BY a.sent_at DESC
    ''').fetchall()

    conn.close()

    return render_template('alerts.html', alerts=alerts_data)


@app.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    conn = get_db()

    if request.method == 'POST':
        # Update settings
        for key in request.form:
            if key.startswith('setting_'):
                setting_key = key.replace('setting_', '')
                setting_value = request.form[key]
                conn.execute('''
                    UPDATE settings SET setting_value = ? WHERE setting_key = ?
                ''', (setting_value, setting_key))

        conn.commit()
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))

    # Get all users
    users = conn.execute('SELECT * FROM users ORDER BY username').fetchall()

    # Get settings
    settings_data = conn.execute('SELECT * FROM settings ORDER BY category, setting_key').fetchall()

    conn.close()

    return render_template('settings.html', users=users, settings=settings_data, now=datetime.now)


@app.route('/test-token')
@login_required
def test_token():
    """Test page to simulate token access"""
    return render_template('test_token.html')


@app.route('/test-email')
@login_required
def test_email():
    """Test email functionality"""
    subject = "Honeytoken System - Test Email"
    message = f"""
    This is a test email from the Honeytoken Detection System.

    System Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    User: {current_user.username}

    If you receive this email, the email alert system is working correctly.

    You will receive similar alerts when:
    1. Honeytokens are accessed
    2. Malicious activities are detected
    3. Suspicious access attempts occur

    Best regards,
    Honeytoken Detection System
    """

    success = send_email_alert(subject, message)

    if success:
        flash('Test email sent successfully! Check your inbox.', 'success')
    else:
        flash('Failed to send test email. Check email configuration.', 'danger')

    return redirect(url_for('settings'))


# Add these imports at the top of your file
import requests  # For IP geolocation
from dateutil import parser  # For timezone handling

# Add these configurations
app.config['GEOIP_API_KEY'] = ''  # Add your API key from ipinfo.io or ipapi.com
app.config['SAFE_COUNTRIES'] = ['US', 'IN', 'GB', 'CA', 'AU', 'DE', 'FR', 'JP']  # Add your safe countries
app.config['WORK_HOURS_START'] = 9  # 9 AM
app.config['WORK_HOURS_END'] = 18  # 6 PM


def get_country_from_ip(ip_address):
    """
    Get country from IP address using ipinfo.io or ipapi.com
    Returns country code or None if failed
    """
    if ip_address in ['127.0.0.1', 'localhost', '0.0.0.0']:
        return 'LOCAL'

    try:
        # Option 1: Using ipinfo.io (free tier: 50k requests/month)
        response = requests.get(f'https://ipinfo.io/{ip_address}/json?token={app.config.get("GEOIP_API_KEY", "")}',
                                timeout=3)

        if response.status_code == 200:
            data = response.json()
            return data.get('country', 'Unknown')

        # Option 2: Using ipapi.com (free tier: 1000 requests/month)
        response = requests.get(f'https://ipapi.co/{ip_address}/country/', timeout=3)
        if response.status_code == 200:
            return response.text.strip()

    except Exception as e:
        print(f"Geolocation error for IP {ip_address}: {e}")

    return 'Unknown'


def analyze_username_password(username, password):
    """
    Analyze username and password for suspicious patterns
    Returns risk score between 0.0 and 1.0
    """
    risk_score = 0.0
    factors = []

    # Check for default/common credentials
    default_credentials = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', 'admin123'),
        ('root', 'root'),
        ('test', 'test'),
        ('user', 'password'),
        ('administrator', 'administrator')
    ]

    for default_user, default_pass in default_credentials:
        if username.lower() == default_user and password == default_pass:
            risk_score += 0.6
            factors.append("Default credentials detected: +60%")
            break

    # Check for weak passwords
    if len(password) < 6:
        risk_score += 0.3
        factors.append("Very short password (<6 chars): +30%")
    elif len(password) < 8:
        risk_score += 0.2
        factors.append("Short password (<8 chars): +20%")

    # Check if password contains username
    if username.lower() in password.lower():
        risk_score += 0.2
        factors.append("Password contains username: +20%")

    # Check for common weak passwords
    common_passwords = ['123456', 'password', 'qwerty', 'letmein', 'welcome', 'monkey']
    if password in common_passwords:
        risk_score += 0.4
        factors.append("Common/weak password: +40%")

    # Check for sequential characters
    if any(password[i:i + 3] in 'abcdefghijklmnopqrstuvwxyz' for i in range(len(password) - 2)):
        risk_score += 0.1
        factors.append("Sequential characters in password: +10%")

    return min(risk_score, 1.0), factors


def is_normal_work_hours():
    """
    Check if current time is during normal work hours
    Returns boolean and risk adjustment
    """
    now = datetime.now()
    current_hour = now.hour

    # Normal work hours (9 AM to 6 PM)
    if app.config['WORK_HOURS_START'] <= current_hour < app.config['WORK_HOURS_END']:
        return True, -0.2  # Negative risk during work hours (safer)

    # Outside work hours - higher risk
    risk_adjustment = 0.0

    if 0 <= current_hour < 5:  # Midnight to 5 AM
        risk_adjustment = 0.4
    elif current_hour < 9:  # 5 AM to 9 AM
        risk_adjustment = 0.2
    elif current_hour >= 18:  # 6 PM to midnight
        risk_adjustment = 0.3

    return False, risk_adjustment


def is_safe_country(country_code):
    """
    Check if country is in safe countries list
    """
    safe_countries = app.config.get('SAFE_COUNTRIES', ['US', 'IN', 'GB', 'CA', 'AU'])
    return country_code in safe_countries


def calculate_enhanced_risk_score(token_value, token_data, source_ip, user_agent, payload, username=None,
                                  password=None):
    """
    Enhanced risk calculation with geolocation, time analysis, and credential checks

    Returns: Risk score between 0.0 and 1.0 (0% to 100%)
    """
    risk_score = 0.0
    all_factors = []

    # Factor 1: Geolocation
    country = get_country_from_ip(source_ip)

    if country == 'Unknown':
        risk_score += 0.2
        all_factors.append("Unknown country: +20%")
    elif not is_safe_country(country):
        risk_score += 0.3
        all_factors.append(f"Non-safe country ({country}): +30%")
    else:
        risk_score -= 0.1  # Reduce risk for safe countries
        all_factors.append(f"Safe country ({country}): -10%")

    # Factor 2: Time of day analysis
    is_work_hours, time_risk = is_normal_work_hours()

    if is_work_hours:
        all_factors.append(f"Normal work hours: {time_risk * 100:.0f}%")
    else:
        all_factors.append(f"Outside work hours: +{time_risk * 100:.0f}%")

    risk_score += time_risk

    # Factor 3: Credential analysis (if provided)
    if username and password:
        cred_risk, cred_factors = analyze_username_password(username, password)
        risk_score += cred_risk
        all_factors.extend(cred_factors)

    # Factor 4: Is it a known honeytoken?
    if token_data:
        risk_score += 0.5  # Base 50% for accessing a real honeytoken
        all_factors.append("Known honeytoken accessed: +50%")

        # Different token types have different risk levels
        token_type = token_data['token_type']
        token_type_weights = {
            'api_key': 1.3,  # API keys are high value
            'database': 1.2,  # Database credentials are critical
            'file': 1.1,  # Secret files
            'url': 1.0,  # Secret URLs
            'other': 0.9  # Other types
        }

        type_multiplier = token_type_weights.get(token_type, 1.0)
        risk_score *= type_multiplier  # Multiply by type weight
        all_factors.append(f"Token type '{token_type}' weight applied: ×{type_multiplier}")

    # Factor 5: Suspicious keywords in token value
    suspicious_keywords = ['admin', 'secret', 'password', 'key', 'token', 'auth',
                           'credential', 'access', 'private', 'confidential']

    for keyword in suspicious_keywords:
        if keyword in token_value.lower():
            risk_score += 0.15
            all_factors.append(f"Suspicious keyword '{keyword}' detected: +15%")
            break

    # Factor 6: User Agent analysis
    if user_agent:
        # Suspicious/bot user agents
        bot_indicators = ['bot', 'crawler', 'spider', 'scanner', 'sqlmap', 'nmap', 'nessus']
        if any(indicator in user_agent.lower() for indicator in bot_indicators):
            risk_score += 0.3
            all_factors.append("Bot/crawler user agent detected: +30%")

        # Missing or generic user agent
        if user_agent in ['', 'Unknown', 'python-requests', 'curl', 'PostmanRuntime']:
            risk_score += 0.15
            all_factors.append("Generic/missing user agent: +15%")

    # Factor 7: Payload analysis
    if payload and isinstance(payload, dict):
        payload_str = str(payload).lower()

        # Check for SQL injection patterns
        sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', '--', ';--']
        for keyword in sql_keywords:
            if keyword in payload_str:
                risk_score += 0.4
                all_factors.append(f"SQL injection pattern '{keyword}' detected: +40%")
                break

        # Check for path traversal
        if '../' in payload_str or '..\\' in payload_str or '/etc/passwd' in payload_str:
            risk_score += 0.35
            all_factors.append("Path traversal attempt: +35%")

    # Factor 8: Access frequency from same IP
    conn = get_db()
    recent_accesses = conn.execute(
        'SELECT COUNT(*) FROM access_logs WHERE source_ip = ? AND access_time > datetime("now", "-1 hour")',
        (source_ip,)
    ).fetchone()[0]
    conn.close()

    if recent_accesses > 10:  # More than 10 accesses in last hour
        risk_score += 0.25
        all_factors.append(f"High frequency access ({recent_accesses} in last hour): +25%")
    elif recent_accesses > 5:
        risk_score += 0.15
        all_factors.append(f"Moderate frequency access ({recent_accesses} in last hour): +15%")

    # Determine if it's SAFE based on conditions
    is_safe = False
    safe_conditions = []

    # Check safe conditions
    if country != 'Unknown' and is_safe_country(country):
        safe_conditions.append(f"Safe country: {country}")

    if is_work_hours:
        safe_conditions.append("Normal work hours")

    if username and password:
        cred_risk, _ = analyze_username_password(username, password)
        if cred_risk < 0.3:  # Low credential risk
            safe_conditions.append("Strong credentials")

    # If all safe conditions are met, reduce risk significantly
    if len(safe_conditions) >= 2:
        risk_score *= 0.3  # Reduce to 30% of original
        all_factors.append(f"Safe conditions met ({len(safe_conditions)}): ×0.3")
        is_safe = True

    # Cap risk score between 0.0 and 1.0
    risk_score = max(0.0, min(risk_score, 1.0))

    # Determine classification with new logic
    if risk_score >= 0.7:
        classification = "malicious"
    elif risk_score >= 0.4:
        classification = "suspicious"
    elif risk_score >= 0.2:
        classification = "warning"
    else:
        classification = "normal"

    # Override to "safe" if all conditions are met and risk is low
    if is_safe and risk_score < 0.3:
        classification = "safe"

    return risk_score, classification, all_factors, country, is_safe


# Update your log_access function to use the enhanced risk calculation:
@app.route('/api/log_access', methods=['POST'])
def log_access():
    """API endpoint to log honeytoken access - WITH ENHANCED RISK CALCULATION"""
    try:
        data = request.json

        if not data or 'token_value' not in data:
            return jsonify({'error': 'Invalid request data'}), 400

        token_value = data.get('token_value')
        source_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        action_type = data.get('action_type', 'ACCESS')
        payload = data.get('payload', {})

        # Extract credentials if present in payload
        username = None
        password = None
        if payload and isinstance(payload, dict):
            username = payload.get('username') or payload.get('user') or payload.get('email')
            password = payload.get('password') or payload.get('pass') or payload.get('pwd')

        conn = get_db()

        # Check if token exists
        token = conn.execute(
            'SELECT * FROM honeytokens WHERE token_value = ? AND is_active = 1',
            (token_value,)
        ).fetchone()

        token_status = "unknown"
        honeytoken_id = None

        if token:
            honeytoken_id = token['id']
            token_status = "active"

        # Calculate ENHANCED risk score
        risk_score, classification, risk_factors, country, is_safe = calculate_enhanced_risk_score(
            token_value, token, source_ip, user_agent, payload, username, password
        )

        # Debug logging
        print(f"\n🔍 ENHANCED RISK ANALYSIS:")
        print(f"Token: {token_value[:30]}...")
        print(f"Source IP: {source_ip}")
        print(f"Country: {country}")
        print(f"Username: {username}")
        print(f"Risk Score: {risk_score:.1%}")
        print(f"Classification: {classification}")
        print(f"Safe Access: {is_safe}")
        print(f"Risk Factors: {risk_factors}")
        print("-" * 50)

        # Log the access with country information
        cursor = conn.execute('''
            INSERT INTO access_logs 
            (honeytoken_id, source_ip, user_agent, country, action_type, payload, 
             risk_score, classification, http_method, request_path, token_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            honeytoken_id, source_ip, user_agent, country, action_type,
            json.dumps(payload) if payload else None,
            risk_score, classification, request.method, request.path, token_status
        ))

        log_id = cursor.lastrowid

        # Update token access count if it exists
        if honeytoken_id:
            conn.execute('''
                UPDATE honeytokens 
                SET access_count = access_count + 1, last_accessed = ?
                WHERE id = ?
            ''', (datetime.now(), honeytoken_id))

        # Create alert based on classification (skip if it's "safe")
        alerted = False
        email_sent = False

        if classification in ['malicious', 'suspicious', 'warning'] and not is_safe:
            token_name = token['token_name'] if token else "Unknown Token"
            token_type = token['token_type'] if token else "Unknown"

            # Enhanced alert message with geolocation info
            alert_message = """{} access detected!

🔐 Token Details:
• Name: {}
• Type: {}
• Value: {}...

🌍 Geolocation:
• IP Address: {}
• Country: {}
• User Agent: {}
• Time: {} ({})
• Safe Access: {}

📊 Risk Assessment:
• Risk Score: {:.0%}
• Classification: {}
• Safe Country: {}
• Work Hours: {}

🎯 Risk Factors:
{}

🚨 Recommended Actions:
1. Review this access immediately
2. Check for related suspicious activities
3. Consider blocking the source IP
4. Investigate how the token was accessed""".format(
                classification.upper(),
                token_name,
                token_type,
                token_value[:50],
                source_ip,
                country,
                user_agent[:100],
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "Work Hours" if is_normal_work_hours()[0] else "Outside Hours",
                "Yes" if is_safe else "No",
                risk_score,
                classification.upper(),
                "Yes" if is_safe_country(country) else "No",
                "Yes" if is_normal_work_hours()[0] else "No",
                "\n".join([f"• {factor}" for factor in risk_factors])
            )

            # Create alert in database
            conn.execute('''
                INSERT INTO alerts (log_id, alert_type, alert_message, severity)
                VALUES (?, ?, ?, ?)
            ''', (log_id,
                  'malicious_access' if classification == 'malicious' else 'suspicious_access',
                  alert_message,
                  'critical' if classification == 'malicious' else
                                           'high' if classification == 'suspicious' else 'medium'))

            alerted = True

            # Send email alert if enabled
            email_enabled = get_setting('email_alerts_enabled', 'true').lower() == 'true'
            alert_on_malicious = get_setting('alert_on_malicious', 'true').lower() == 'true'
            alert_on_suspicious = get_setting('alert_on_suspicious', 'false').lower() == 'true'

            if email_enabled:
                if (classification == 'malicious' and alert_on_malicious) or \
                        (classification == 'suspicious' and alert_on_suspicious) or \
                        (classification == 'warning' and get_setting('alert_on_warning', 'false').lower() == 'true'):

                    email_subject = "🚨 Honeytoken Alert: {} Access from {}".format(
                        classification.upper(), country
                    )

                    # Get recipients from settings
                    recipients_setting = get_setting('email_recipients', app.config['ADMIN_EMAIL'])
                    recipients = [email.strip() for email in recipients_setting.split(',')]

                    # Also send to all admin users
                    admin_users = conn.execute(
                        "SELECT email FROM users WHERE role = 'admin' AND is_active = 1"
                    ).fetchall()

                    for admin in admin_users:
                        if admin['email'] not in recipients:
                            recipients.append(admin['email'])

                    email_sent = send_email_alert(email_subject, alert_message, recipients)

                    if email_sent:
                        print(f"✅ Email alert sent for {classification} access from {country}")

        conn.commit()
        conn.close()

        return jsonify({
            'status': 'success',
            'message': 'Access logged',
            'token_status': token_status,
            'classification': classification,
            'risk_score': risk_score,
            'country': country,
            'is_safe': is_safe,
            'risk_factors': risk_factors[:5],  # Send first 5 factors
            'alerted': alerted,
            'email_sent': email_sent,
            'log_id': log_id
        })

    except Exception as e:
        print(f"Error in log_access: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/alerts/<int:alert_id>/read', methods=['POST'])
@login_required
def mark_alert_read(alert_id):
    """Mark an alert as read"""
    try:
        conn = get_db()
        conn.execute('''
            UPDATE alerts 
            SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
            WHERE id = ?
        ''', (current_user.id, datetime.now(), alert_id))
        conn.commit()
        conn.close()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        conn = get_db()
        conn.execute('SELECT 1')
        conn.close()

        # Check email configuration
        email_configured = bool(app.config['EMAIL_USER'] and app.config['EMAIL_PASSWORD'])

        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'email_configured': email_configured,
            'database': 'connected'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)

    # Initialize database
    init_db()

    # Run the application
    print("=" * 60)
    print("Honeytoken System Starting...")
    print("=" * 60)
    print("Admin credentials: admin / admin123")
    print("Database file: honeytoken.db")
    print("=" * 60)

    # Check email configuration
    if app.config['EMAIL_USER'] == 'your-email@gmail.com':
        print("⚠️  WARNING: Email not configured!")
        print("   To enable email alerts, edit app.config['EMAIL_USER'] and ['EMAIL_PASSWORD']")
        print("   Use App Password for Gmail (not regular password)")
    else:
        print("✅ Email alerts: Configured")

    print("\nAccess the application at:")
    print("  http://localhost:5000")
    print("\nUseful endpoints:")
    print("  /login              - Login page")
    print("  /test-email         - Test email alerts")
    print("  /test-token         - Test honeytoken access")
    print("=" * 60)

    app.run(debug=True, host='0.0.0.0', port=5000)