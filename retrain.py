# retrain_model.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from ml_detector import AnomalyDetector
import json


def generate_training_data():
    """Generate better training data with clear anomalies"""
    print("📊 Generating training data...")

    data = []

    # Normal traffic (70%)
    normal_ips = [f'192.168.1.{i}' for i in range(1, 51)]
    normal_countries = ['US', 'UK', 'CA', 'AU', 'DE', 'FR']
    normal_agents = ['Chrome/120.0', 'Firefox/121.0', 'Safari/17.0', 'Edge/120.0']
    normal_actions = ['LOGIN', 'READ', 'VIEW', 'DOWNLOAD', 'API_CALL']
    normal_methods = ['GET', 'POST']

    for i in range(700):
        entry = {
            'access_time': datetime.now() - timedelta(hours=np.random.randint(0, 720)),
            'source_ip': np.random.choice(normal_ips),
            'user_agent': np.random.choice(normal_agents),
            'country': np.random.choice(normal_countries),
            'action_type': np.random.choice(normal_actions),
            'http_method': np.random.choice(normal_methods),
            'classification': 'normal'
        }
        data.append(entry)

    # Suspicious traffic (20%)
    suspicious_ips = ['185.220.101.204', '203.0.113.42', '198.51.100.99']
    suspicious_countries = ['RU', 'CN', 'IR', 'KP', 'Unknown']
    suspicious_agents = ['sqlmap/1.6', 'nikto/2.1.6', 'python-requests/2.28', 'curl/7.88']
    suspicious_actions = ['BRUTE_FORCE', 'SCAN', 'ENUMERATE', 'PROBE']

    for i in range(200):
        entry = {
            'access_time': datetime.now() - timedelta(hours=np.random.randint(0, 720)),
            'source_ip': np.random.choice(suspicious_ips),
            'user_agent': np.random.choice(suspicious_agents),
            'country': np.random.choice(suspicious_countries),
            'action_type': np.random.choice(suspicious_actions),
            'http_method': 'POST',
            'classification': 'suspicious'
        }
        data.append(entry)

    # Malicious traffic (10%)
    malicious_ips = ['185.220.101.204', '192.168.1.999']  # Invalid internal IP
    malicious_agents = ['METERPRETER', 'BEACON', 'CobaltStrike', 'Empire']
    malicious_actions = ['SQL_INJECTION', 'XSS', 'RCE', 'LFI', 'RFI']

    for i in range(100):
        entry = {
            'access_time': datetime.now() - timedelta(hours=np.random.randint(0, 720)),
            'source_ip': np.random.choice(malicious_ips),
            'user_agent': np.random.choice(malicious_agents),
            'country': 'Unknown',
            'action_type': np.random.choice(malicious_actions),
            'http_method': np.random.choice(['POST', 'PUT', 'DELETE']),
            'classification': 'malicious'
        }
        data.append(entry)

    print(f"✅ Generated {len(data)} training samples")
    return data


def test_model_sensitivity(detector):
    """Test if model is sensitive enough"""
    print("\n🧪 Testing model sensitivity...")

    test_cases = [
        {
            'name': 'Normal traffic',
            'data': {
                'access_time': datetime.now(),
                'source_ip': '192.168.1.10',
                'user_agent': 'Chrome/120.0',
                'country': 'US',
                'action_type': 'LOGIN',
                'http_method': 'POST'
            },
            'expected': 'normal'
        },
        {
            'name': 'Suspicious IP',
            'data': {
                'access_time': datetime.now(),
                'source_ip': '185.220.101.204',
                'user_agent': 'Chrome/120.0',
                'country': 'Unknown',
                'action_type': 'LOGIN',
                'http_method': 'POST'
            },
            'expected': 'suspicious'
        },
        {
            'name': 'Hacking tool',
            'data': {
                'access_time': datetime.now(),
                'source_ip': '192.168.1.10',
                'user_agent': 'sqlmap/1.6',
                'country': 'US',
                'action_type': 'API_CALL',
                'http_method': 'POST'
            },
            'expected': 'malicious'
        },
        {
            'name': 'Brute force',
            'data': {
                'access_time': datetime.now(),
                'source_ip': '203.0.113.42',
                'user_agent': 'python-requests',
                'country': 'CN',
                'action_type': 'BRUTE_FORCE',
                'http_method': 'POST'
            },
            'expected': 'malicious'
        }
    ]

    for test in test_cases:
        score, classification = detector.predict(test['data'])
        passed = classification == test['expected']
        symbol = '✅' if passed else '❌'
        print(
            f"{symbol} {test['name']:20} -> Score: {score:.2%}, Class: {classification}, Expected: {test['expected']}")


def main():
    print("🔄 Retraining ML Model for Better Alert Detection")
    print("=" * 60)

    # Create detector
    detector = AnomalyDetector()

    # Generate training data
    training_data = generate_training_data()

    # Train model with higher sensitivity
    print("\n🤖 Training model with contamination=0.25 (high sensitivity)...")
    detector.train_model(training_data, contamination=0.25)

    # Test sensitivity
    test_model_sensitivity(detector)

    # Save model info
    info = detector.get_model_info()
    print("\n📋 Model Info:")
    print(f"   Status: {info['status']}")
    print(f"   Type: {info['model_type']}")
    print(f"   Features: {info['features']}")
    print(f"   Thresholds: {info['thresholds']}")

    print("\n✅ Model retrained successfully!")
    print("💡 Now test alerts with the alert tester script.")


if __name__ == "__main__":
    main()