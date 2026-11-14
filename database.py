import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
from config import Config


class DatabaseManager:
    def __init__(self):
        self.config = {
            'host': Config.DB_HOST,
            'user': Config.DB_USER,
            'password': Config.DB_PASSWORD,
            'database': Config.DB_NAME
        }
        self.connection = None
        self.connect()
        self.create_tables()

    def connect(self):
        """Establish database connection"""
        try:
            temp_config = self.config.copy()
            temp_config.pop('database', None)
            temp_conn = mysql.connector.connect(**temp_config)
            cursor = temp_conn.cursor()

            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS {Config.DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
            temp_conn.close()

            self.connection = mysql.connector.connect(**self.config)
            print("✅ Database connected successfully")
        except Error as e:
            print(f"❌ Error connecting to MySQL: {e}")
            raise

    def create_tables(self):
        """Create all required tables"""
        try:
            cursor = self.connection.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255),
                    role ENUM('admin', 'user') DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    is_active BOOLEAN DEFAULT TRUE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Honeytokens table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS honeytokens (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    token_type ENUM('password', 'api_key', 'file', 'database', 'url') NOT NULL,
                    token_value TEXT NOT NULL,
                    token_name VARCHAR(255) NOT NULL,
                    description TEXT,
                    created_by INT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    deployment_location VARCHAR(500),
                    access_count INT DEFAULT 0,
                    last_accessed TIMESTAMP NULL,
                    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Access logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    honeytoken_id INT,
                    access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip VARCHAR(45),
                    user_agent TEXT,
                    country VARCHAR(100),
                    city VARCHAR(100),
                    action_type VARCHAR(50),
                    payload TEXT,
                    risk_score FLOAT DEFAULT 0.0,
                    classification ENUM('safe', 'suspicious', 'malicious') DEFAULT 'safe',
                    alerted BOOLEAN DEFAULT FALSE,
                    response_time_ms INT,
                    http_method VARCHAR(10),
                    request_path VARCHAR(500),
                    FOREIGN KEY (honeytoken_id) REFERENCES honeytokens(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    log_id INT,
                    alert_type ENUM('email', 'telegram', 'dashboard', 'webhook') NOT NULL,
                    alert_message TEXT,
                    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    acknowledged_by INT NULL,
                    acknowledged_at TIMESTAMP NULL,
                    FOREIGN KEY (log_id) REFERENCES access_logs(id) ON DELETE CASCADE,
                    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # ML models table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ml_models (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    model_name VARCHAR(100),
                    model_type VARCHAR(50),
                    accuracy_score FLOAT,
                    precision_score FLOAT,
                    recall_score FLOAT,
                    f1_score FLOAT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT FALSE,
                    model_path VARCHAR(500)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Blocked IPs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    reason TEXT,
                    blocked_by INT,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    FOREIGN KEY (blocked_by) REFERENCES users(id) ON DELETE SET NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    setting_key VARCHAR(100) UNIQUE NOT NULL,
                    setting_value TEXT,
                    setting_type ENUM('string', 'integer', 'boolean', 'json') DEFAULT 'string',
                    category VARCHAR(50),
                    description TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            # Audit logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NULL,
                    action VARCHAR(100) NOT NULL,
                    table_name VARCHAR(100),
                    record_id INT,
                    old_values TEXT,
                    new_values TEXT,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)

            self.connection.commit()
            print("✅ Tables created successfully")

            self.insert_default_settings()

        except Error as e:
            print(f"❌ Error creating tables: {e}")
            raise

    def insert_default_settings(self):
        """Insert default system settings"""
        try:
            cursor = self.connection.cursor()

            default_settings = [
                ('system_name', 'Honeytoken Detection System', 'string', 'general', 'System display name'),
                ('timezone', 'UTC', 'string', 'general', 'System timezone'),
                ('default_token_expiry', '30', 'integer', 'general', 'Default token expiry in days'),
                ('log_retention_days', '90', 'integer', 'general', 'Days to keep access logs'),
                ('enable_email_alerts', 'true', 'boolean', 'notifications', 'Enable email alerts'),
                ('enable_telegram_alerts', 'false', 'boolean', 'notifications', 'Enable Telegram alerts'),
                ('alert_on_malicious', 'true', 'boolean', 'notifications', 'Alert on malicious accesses'),
                ('alert_on_suspicious', 'true', 'boolean', 'notifications', 'Alert on suspicious accesses'),
                ('ai_safe_threshold', '0.3', 'string', 'ai', 'Safe risk threshold'),
                ('ai_suspicious_threshold', '0.7', 'string', 'ai', 'Suspicious risk threshold'),
                ('ai_model_type', 'isolation_forest', 'string', 'ai', 'AI model type'),
                ('session_timeout_minutes', '60', 'integer', 'security', 'Session timeout in minutes'),
                ('max_login_attempts', '5', 'integer', 'security', 'Maximum login attempts'),
                ('auto_block_malicious_ips', 'true', 'boolean', 'security', 'Auto-block malicious IPs'),
                ('block_duration_days', '7', 'integer', 'security', 'IP block duration in days'),
            ]

            for setting in default_settings:
                cursor.execute("""
                    INSERT IGNORE INTO settings 
                    (setting_key, setting_value, setting_type, category, description)
                    VALUES (%s, %s, %s, %s, %s)
                """, setting)

            self.connection.commit()
            print("✅ Default settings inserted")

        except Error as e:
            print(f"⚠️ Warning: Could not insert default settings: {e}")

    def execute_query(self, query, params=None, fetch_one=False):
        """Execute SQL query"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            cursor.execute(query, params or ())

            if query.strip().upper().startswith('SELECT'):
                if fetch_one:
                    result = cursor.fetchone()
                else:
                    result = cursor.fetchall()
            else:
                self.connection.commit()
                result = cursor.lastrowid

            cursor.close()
            return result
        except Error as e:
            print(f"❌ Query error: {e}")
            print(f"Query: {query}")
            print(f"Params: {params}")
            return None

    def insert_user(self, username, email, password_hash, full_name=None, role='user'):
        """Insert a new user"""
        return self.execute_query(
            """INSERT INTO users (username, email, password_hash, full_name, role) 
               VALUES (%s, %s, %s, %s, %s)""",
            (username, email, password_hash, full_name, role)
        )

    def get_user_by_username(self, username):
        """Get user by username"""
        return self.execute_query(
            "SELECT * FROM users WHERE username = %s AND is_active = TRUE",
            (username,),
            fetch_one=True
        )

    def get_user_by_email(self, email):
        """Get user by email"""
        return self.execute_query(
            "SELECT * FROM users WHERE email = %s AND is_active = TRUE",
            (email,),
            fetch_one=True
        )

    def update_user_last_login(self, user_id):
        """Update user's last login timestamp"""
        return self.execute_query(
            "UPDATE users SET last_login = %s WHERE id = %s",
            (datetime.now(), user_id)
        )

    def create_honeytoken(self, token_data):
        """Create a new honeytoken"""
        query = """
            INSERT INTO honeytokens 
            (token_type, token_value, token_name, description, created_by, 
             expires_at, deployment_location, is_active, access_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0)
        """
        params = (
            token_data['token_type'],
            token_data['token_value'],
            token_data['token_name'],
            token_data.get('description'),
            token_data['created_by'],
            token_data.get('expires_at'),
            token_data.get('deployment_location'),
            token_data.get('is_active', True)
        )
        return self.execute_query(query, params)

    def log_access(self, log_data):
        """Log honeytoken access"""
        query = """
            INSERT INTO access_logs 
            (honeytoken_id, source_ip, user_agent, country, city, 
             action_type, payload, risk_score, classification, 
             response_time_ms, http_method, request_path)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            log_data['honeytoken_id'],
            log_data.get('source_ip'),
            log_data.get('user_agent'),
            log_data.get('country'),
            log_data.get('city'),
            log_data.get('action_type', 'ACCESS'),
            log_data.get('payload'),
            log_data.get('risk_score', 0.0),
            log_data.get('classification', 'safe'),
            log_data.get('response_time_ms'),
            log_data.get('http_method'),
            log_data.get('request_path')
        )

        log_id = self.execute_query(query, params)

        if log_id:
            self.execute_query("""
                UPDATE honeytokens 
                SET access_count = access_count + 1, last_accessed = %s 
                WHERE id = %s
            """, (datetime.now(), log_data['honeytoken_id']))

        return log_id

    def create_alert(self, alert_data):
        """Create a new alert"""
        query = """
            INSERT INTO alerts 
            (log_id, alert_type, alert_message, severity, sent_at)
            VALUES (%s, %s, %s, %s, %s)
        """
        params = (
            alert_data['log_id'],
            alert_data['alert_type'],
            alert_data['alert_message'],
            alert_data.get('severity', 'medium'),
            alert_data.get('sent_at', datetime.now())
        )
        return self.execute_query(query, params)

    def get_statistics(self):
        """Get system statistics"""
        stats = {}

        result = self.execute_query(
            "SELECT COUNT(*) as count FROM honeytokens WHERE is_active = TRUE",
            fetch_one=True
        )
        stats['active_tokens'] = result['count'] if result else 0

        result = self.execute_query("""
            SELECT COUNT(*) as count FROM access_logs 
            WHERE DATE(access_time) = CURDATE()
        """, fetch_one=True)
        stats['today_accesses'] = result['count'] if result else 0

        result = self.execute_query("""
            SELECT COUNT(*) as count FROM access_logs 
            WHERE classification = 'malicious'
        """, fetch_one=True)
        stats['malicious_accesses'] = result['count'] if result else 0

        result = self.execute_query("""
            SELECT COUNT(*) as count FROM alerts 
            WHERE acknowledged = FALSE
        """, fetch_one=True)
        stats['unread_alerts'] = result['count'] if result else 0

        result = self.execute_query(
            "SELECT COUNT(*) as count FROM access_logs",
            fetch_one=True
        )
        stats['total_accesses'] = result['count'] if result else 0

        return stats

    def get_daily_access_stats(self, days=7):
        """Get daily access statistics for the last N days"""
        return self.execute_query(f"""
            SELECT 
                DATE(access_time) as date,
                COUNT(*) as total,
                SUM(CASE WHEN classification = 'safe' THEN 1 ELSE 0 END) as safe,
                SUM(CASE WHEN classification = 'suspicious' THEN 1 ELSE 0 END) as suspicious,
                SUM(CASE WHEN classification = 'malicious' THEN 1 ELSE 0 END) as malicious
            FROM access_logs
            WHERE access_time >= DATE_SUB(CURDATE(), INTERVAL {days} DAY)
            GROUP BY DATE(access_time)
            ORDER BY date
        """)

    def get_recent_logs(self, limit=10):
        """Get recent access logs"""
        return self.execute_query(f"""
            SELECT al.*, ht.token_name, ht.token_type, u.username as created_by_name
            FROM access_logs al
            JOIN honeytokens ht ON al.honeytoken_id = ht.id
            LEFT JOIN users u ON ht.created_by = u.id
            ORDER BY al.access_time DESC
            LIMIT {limit}
        """)

    def get_setting(self, key):
        """Get system setting"""
        result = self.execute_query(
            "SELECT setting_value, setting_type FROM settings WHERE setting_key = %s",
            (key,),
            fetch_one=True
        )

        if not result:
            return None

        value = result['setting_value']
        type_str = result['setting_type']

        if type_str == 'integer':
            return int(value) if value else 0
        elif type_str == 'boolean':
            return value.lower() in ('true', '1', 'yes', 'on')
        elif type_str == 'json':
            try:
                import json
                return json.loads(value)
            except:
                return value
        else:
            return value

    def set_setting(self, key, value, type_str='string', category='general', description=None):
        """Set system setting"""
        if type_str == 'boolean':
            value = 'true' if value else 'false'
        elif type_str == 'json':
            import json
            value = json.dumps(value)

        return self.execute_query("""
            INSERT INTO settings (setting_key, setting_value, setting_type, category, description)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            setting_value = VALUES(setting_value),
            setting_type = VALUES(setting_type),
            category = VALUES(category),
            description = VALUES(description),
            updated_at = CURRENT_TIMESTAMP
        """, (key, str(value), type_str, category, description))

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()