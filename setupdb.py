#!/usr/bin/env python3
"""
MySQL Setup Script for HoneyToken System - Works with Aria engine errors
"""

import mysql.connector
from mysql.connector import Error
import sys
import os
from pathlib import Path


def create_database_and_user():
    """Create database and user without triggering Aria errors"""

    print("🔧 Setting up HoneyToken MySQL Database...")

    try:
        # Connect as root
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password=input("Enter MySQL root password: ")
        )

        if connection.is_connected():
            cursor = connection.cursor()

            # Create database with safe settings
            print("Creating database...")
            cursor.execute(
                "CREATE DATABASE IF NOT EXISTS honeytoken_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")

            # Create user with minimal initial privileges
            print("Creating user...")
            cursor.execute("DROP USER IF EXISTS 'honeytoken'@'localhost'")

            # Create user without grant option initially
            cursor.execute("CREATE USER 'honeytoken'@'localhost' IDENTIFIED BY 'HoneyToken2024!'")

            # Grant basic privileges first
            cursor.execute("""
                GRANT CREATE, ALTER, DROP, INSERT, UPDATE, DELETE, 
                SELECT, REFERENCES, INDEX ON honeytoken_system.* 
                TO 'honeytoken'@'localhost'
            """)

            # Try to grant additional privileges if possible
            try:
                cursor.execute("GRANT CREATE ROUTINE, ALTER ROUTINE ON honeytoken_system.* TO 'honeytoken'@'localhost'")
            except:
                print("Note: Limited privileges granted (some features might require manual setup)")

            print("✅ Database and user created successfully!")

            # Test the connection
            print("\n🔍 Testing connection...")
            test_connection = mysql.connector.connect(
                host="localhost",
                user="honeytoken",
                password="HoneyToken2024!",
                database="honeytoken_system"
            )

            if test_connection.is_connected():
                print("✅ Connection test successful!")
                test_connection.close()

            cursor.close()
            connection.close()

            # Create .env file
            create_env_file()

    except Error as e:
        print(f"❌ Error: {e}")
        print("\n💡 Troubleshooting tips:")
        print("1. Make sure MySQL/MariaDB is running")
        print("2. Check if you have correct root password")
        print("3. Try running: sudo mysql_secure_installation")
        print("4. For Aria errors, try: mysql_upgrade --force")
        sys.exit(1)


def create_env_file():
    """Create environment configuration file"""
    env_content = """# Flask Configuration
SECRET_KEY=your-secret-key-change-this-in-production-123456

# Database Configuration
MYSQL_HOST=localhost
MYSQL_USER=honeytoken
MYSQL_PASSWORD=HoneyToken2024!
MYSQL_DB=honeytoken_system

# Email Configuration (for alerts)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=mysecretid1996@gmail.com
MAIL_PASSWORD=feqeokahfkmqhidg

# Telegram Bot (optional)
TELEGRAM_BOT_TOKEN=7624207219:AAEGJlDT0y1vREmwofdABkkrK6COjIz3QAc
TELEGRAM_CHAT_ID=674489168

# Admin Configuration
ADMIN_EMAIL=mysecretid1996@gmail.com
"""

    with open('.env', 'w') as f:
        f.write(env_content)

    print("\n📁 Created .env file with configuration")
    print("⚠️  Remember to update the email and security settings!")


def alternative_setup_method():
    """Alternative setup using command line"""
    print("\n🔧 Alternative Setup Method:")
    print("1. Login to MySQL as root:")
    print("   mysql -u root -p")
    print("\n2. Run these commands one by one:")
    print("   CREATE DATABASE honeytoken_system;")
    print("   USE honeytoken_system;")
    print("   CREATE USER 'honeytoken'@'localhost' IDENTIFIED BY 'StrongPass123!';")
    print("   GRANT ALL PRIVILEGES ON honeytoken_system.* TO 'honeytoken'@'localhost';")
    print("   EXIT;")
    print("\n3. Restart MySQL:")
    print("   sudo systemctl restart mysql")


if __name__ == "__main__":
    print("=" * 60)
    print("HONEYTOKEN SECURITY SYSTEM - DATABASE SETUP")
    print("=" * 60)

    choice = input(
        "\nChoose setup method:\n1. Automated Setup (Recommended)\n2. Manual Setup Instructions\n3. Fix Aria Engine Error\n\nChoice (1/2/3): ")

    if choice == "1":
        create_database_and_user()
    elif choice == "2":
        alternative_setup_method()
    elif choice == "3":
        fix_aria_error()
    else:
        print("Invalid choice. Using automated setup...")
        create_database_and_user()

    print("\n" + "=" * 60)
    print("SETUP COMPLETE!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Install Python dependencies:")
    print("   pip install -r requirements.txt")
    print("\n2. Run the application:")
    print("   python app.py")
    print("\n3. Access at: http://localhost:5000")
    print("   Login: admin / Admin@123")


def fix_aria_error():
    """Provide instructions to fix Aria engine error"""
    print("\n🛠️  Fixing Aria Storage Engine Error:")
    print("\nRun these commands in terminal:")
    print("""
# Stop MySQL service
sudo systemctl stop mysql

# Repair Aria tables
sudo mysqlcheck --all-databases --auto-repair --check

# Or repair specific mysql tables
sudo mysqlcheck mysql --auto-repair

# Start MySQL service
sudo systemctl start mysql

# Optional: Upgrade MySQL/MariaDB
sudo mysql_upgrade --force
""")