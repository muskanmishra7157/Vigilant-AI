import mysql.connector
from mysql.connector import Error
from contextlib import contextmanager
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Database:
    def __init__(self, config):
        self.config = config
        self.connection = None
        self._initialize_database()
        self._create_tables()

    def _initialize_database(self):
        """Create database if it doesn't exist"""
        try:
            # First connect without database to create it
            temp_conn = mysql.connector.connect(
                host=self.config['MYSQL_HOST'],
                user=self.config['MYSQL_USER'],
                password=self.config['MYSQL_PASSWORD']
            )

            cursor = temp_conn.cursor()
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['MYSQL_DB']}")
            cursor.close()
            temp_conn.close()

            # Now connect to the specific database
            self.connection = mysql.connector.connect(
                host=self.config['MYSQL_HOST'],
                user=self.config['MYSQL_USER'],
                password=self.config['MYSQL_PASSWORD'],
                database=self.config['MYSQL_DB']
            )

            logger.info("Database initialized successfully")

        except Error as e:
            logger.error(f"Error initializing database: {e}")
            raise

    def _create_tables(self):
        """Create all necessary tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('admin', 'user') DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS honeytokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                token_type ENUM('api_key', 'password', 'file_path', 'database', 'url') NOT NULL,
                token_value VARCHAR(500) UNIQUE NOT NULL,
                token_name VARCHAR(100) NOT NULL,
                description TEXT,
                location VARCHAR(255),
                created_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE,
                sensitivity_level ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS access_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                honeytoken_id INT,
                access_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip VARCHAR(45),
                user_agent TEXT,
                http_method VARCHAR(10),
                request_path VARCHAR(500),
                request_data TEXT,
                country VARCHAR(100),
                city VARCHAR(100),
                isp VARCHAR(200),
                response_code INT,
                risk_score FLOAT DEFAULT 0.0,
                risk_category ENUM('safe', 'suspicious', 'malicious') DEFAULT 'safe',
                analyzed BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (honeytoken_id) REFERENCES honeytokens(id) ON DELETE CASCADE,
                INDEX idx_access_time (access_time),
                INDEX idx_risk_category (risk_category)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                access_log_id INT,
                alert_type ENUM('email', 'telegram', 'dashboard', 'all') NOT NULL,
                alert_message TEXT NOT NULL,
                sent_to VARCHAR(255),
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (access_log_id) REFERENCES access_logs(id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS ai_models (
                id INT AUTO_INCREMENT PRIMARY KEY,
                model_name VARCHAR(100) NOT NULL,
                model_type VARCHAR(50),
                accuracy_score FLOAT,
                precision_score FLOAT,
                recall_score FLOAT,
                f1_score FLOAT,
                training_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                model_path VARCHAR(255),
                is_active BOOLEAN DEFAULT TRUE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(45),
                threat_type VARCHAR(100),
                confidence_score FLOAT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source VARCHAR(100),
                description TEXT,
                INDEX idx_ip_address (ip_address)
            )
            """
        ]

        try:
            cursor = self.connection.cursor()
            for table_query in tables:
                cursor.execute(table_query)

            # Create default admin user if not exists
            cursor.execute("""
                INSERT IGNORE INTO users (username, email, password_hash, role) 
                VALUES ('admin', 'admin@example.com', 
                '$2b$12$LQv3c1yqBWVHxkdUqWQ1e.CTjM7CjPDdK6L9Y4JNQYFJ3wz1vW6u', 'admin')
            """)  # Password: Admin@123

            self.connection.commit()
            cursor.close()
            logger.info("All tables created successfully")

        except Error as e:
            logger.error(f"Error creating tables: {e}")
            self.connection.rollback()
            raise

    @contextmanager
    def get_cursor(self):
        """Context manager for database cursor"""
        cursor = None
        try:
            cursor = self.connection.cursor(dictionary=True)
            yield cursor
            self.connection.commit()
        except Error as e:
            self.connection.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if cursor:
                cursor.close()

    def execute_query(self, query, params=None, fetch_one=False):
        """Execute SQL query"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, params or ())
                if fetch_one:
                    return cursor.fetchone()
                return cursor.fetchall()
        except Error as e:
            logger.error(f"Query execution error: {e}")
            return None

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()