import random
import string
import uuid
import hashlib
from datetime import datetime, timedelta
import secrets


class TokenGenerator:
    @staticmethod
    def generate_api_key():
        """Generate fake API key"""
        prefix = random.choice(['AKIA', 'SKIA', 'BKIA'])
        chars = string.ascii_uppercase + string.digits
        key = prefix + ''.join(secrets.choice(chars) for _ in range(32))
        return key

    @staticmethod
    def generate_password():
        """Generate fake password"""
        patterns = [
            f"Admin{random.randint(1000, 9999)}!",
            f"Password@{random.randint(100, 999)}",
            f"Secret{random.choice(['#', '$', '@'])}{random.randint(100, 999)}",
            f"root{random.randint(1000, 9999)}",
            f"admin{random.choice(['123', 'admin', 'pass'])}"
        ]
        return random.choice(patterns)

    @staticmethod
    def generate_file_path():
        """Generate fake file path"""
        base_dirs = [
            '/etc/passwd.bak',
            '/home/user/.ssh/id_rsa',
            '/var/www/html/config.php',
            '/tmp/credentials.txt',
            '/root/.aws/credentials',
            '/opt/app/database.yml',
            '/var/log/auth.log.bak'
        ]
        return random.choice(base_dirs)

    @staticmethod
    def generate_database_creds():
        """Generate fake database credentials"""
        return {
            'host': f"db-{random.randint(100, 999)}.rds.amazonaws.com",
            'username': random.choice(['admin', 'root', 'postgres', 'mysql']),
            'password': f"DB{random.randint(10000, 99999)}!@#",
            'database': random.choice(['prod_db', 'backup_db', 'config_db'])
        }

    @staticmethod
    def generate_url():
        """Generate fake URL"""
        domains = ['admin', 'api', 'internal', 'backup', 'config', 'test']
        tlds = ['.local', '.internal', '.test', '.dev']
        path = random.choice(['/admin', '/api/v1', '/wp-admin', '/config', '/backup'])
        return f"http://{random.choice(domains)}{random.choice(tlds)}{path}"

    @staticmethod
    def generate_token(token_type):
        """Generate token based on type"""
        generators = {
            'api_key': TokenGenerator.generate_api_key,
            'password': TokenGenerator.generate_password,
            'file_path': TokenGenerator.generate_file_path,
            'url': TokenGenerator.generate_url,
        }

        if token_type == 'database':
            return str(TokenGenerator.generate_database_creds())

        if token_type in generators:
            return generators[token_type]()

        return str(uuid.uuid4())

    @staticmethod
    def get_random_expiry():
        """Generate random expiry date (30-365 days from now)"""
        days = random.randint(30, 365)
        return datetime.now() + timedelta(days=days)