# ml_detector.py - UPDATED VERSION
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
from datetime import datetime
import warnings
import re

warnings.filterwarnings('ignore')


class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = []
        # More sensitive thresholds for testing
        self.safe_threshold = 0.2  # Below this = normal
        self.suspicious_threshold = 0.5  # Above this = suspicious
        self.malicious_threshold = 0.7  # Above this = malicious

    def prepare_features(self, log_data):
        """Prepare features from log data with enhanced features"""
        df = pd.DataFrame(log_data)
        features = {}

        # Time features
        if 'access_time' in df.columns:
            df['access_time'] = pd.to_datetime(df['access_time'])
            df['hour'] = df['access_time'].dt.hour
            df['day_of_week'] = df['access_time'].dt.dayofweek
            df['is_night'] = ((df['hour'] >= 0) & (df['hour'] <= 5)).astype(int)
            df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)

            features['hour'] = df['hour'].values
            features['day_of_week'] = df['day_of_week'].values
            features['is_night'] = df['is_night'].values
            features['is_weekend'] = df['is_weekend'].values

        # IP features
        if 'source_ip' in df.columns:
            # Check for suspicious IP patterns
            df['is_local_ip'] = df['source_ip'].apply(
                lambda x: 1 if x.startswith(('192.168.', '10.', '127.', '172.')) else 0)
            df['is_known_malicious'] = df['source_ip'].apply(self._is_suspicious_ip)
            features['is_local_ip'] = df['is_local_ip'].values
            features['is_known_malicious'] = df['is_known_malicious'].values

        # Action type features
        if 'action_type' in df.columns:
            if 'action_type' not in self.label_encoders:
                self.label_encoders['action_type'] = LabelEncoder()
                self.label_encoders['action_type'].fit(df['action_type'])
            features['action_type'] = self.label_encoders['action_type'].transform(df['action_type'])

            # Flag suspicious actions
            suspicious_actions = ['BRUTE_FORCE', 'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION',
                                  'FILE_UPLOAD', 'DIRECTORY_TRAVERSAL', 'PORT_SCAN']
            df['is_suspicious_action'] = df['action_type'].apply(
                lambda x: 1 if any(sus in str(x).upper() for sus in suspicious_actions) else 0
            )
            features['is_suspicious_action'] = df['is_suspicious_action'].values

        # User agent features
        if 'user_agent' in df.columns:
            df['user_agent'] = df['user_agent'].fillna('Unknown')
            # Check for hacking tools in user agent
            hacking_tools = ['sqlmap', 'nikto', 'nmap', 'metasploit', 'burp', 'w3af',
                             'hydra', 'john', 'hashcat', 'aircrack', 'nessus']
            df['is_hacking_tool'] = df['user_agent'].apply(
                lambda x: 1 if any(tool in str(x).lower() for tool in hacking_tools) else 0
            )
            features['is_hacking_tool'] = df['is_hacking_tool'].values

        # Country features
        if 'country' in df.columns:
            df['country'] = df['country'].fillna('Unknown')
            if 'country' not in self.label_encoders:
                self.label_encoders['country'] = LabelEncoder()
                self.label_encoders['country'].fit(df['country'])
            features['country'] = self.label_encoders['country'].transform(df['country'])

            # Flag unusual countries
            usual_countries = ['US', 'UK', 'CA', 'AU', 'DE', 'FR', 'JP']
            df['is_unusual_country'] = df['country'].apply(
                lambda x: 0 if str(x).upper() in usual_countries else 1
            )
            features['is_unusual_country'] = df['is_unusual_country'].values

        # Request method features
        if 'http_method' in df.columns:
            df['is_dangerous_method'] = df['http_method'].apply(
                lambda x: 1 if str(x).upper() in ['POST', 'PUT', 'DELETE', 'PATCH'] else 0
            )
            features['is_dangerous_method'] = df['is_dangerous_method'].values

        # Create feature matrix
        if features:
            feature_matrix = np.column_stack(list(features.values()))
            self.feature_columns = list(features.keys())
            return feature_matrix
        else:
            return np.array([])

    def _is_suspicious_ip(self, ip):
        """Check if IP is known malicious or suspicious"""
        suspicious_ranges = [
            '185.220.101.',  # Tor exit nodes
            '192.168.',  # Internal (shouldn't be accessing from outside)
            '10.',  # Internal
            '172.16.',  # Internal
            '127.',  # Localhost
        ]

        known_malicious = [
            '185.220.101.204',
            '203.0.113.',  # Example only
            '198.51.100.',  # Example only
        ]

        ip_str = str(ip)
        for pattern in known_malicious + suspicious_ranges:
            if ip_str.startswith(pattern):
                return 1
        return 0

    def train_model(self, log_data, contamination=0.2):  # Increased contamination
        """Train Isolation Forest model with more sensitivity"""
        print("🤖 Training AI model with enhanced features...")

        X = self.prepare_features(log_data)
        if X.shape[0] == 0:
            print("⚠️ No features extracted, using dummy data")
            log_data = self.generate_realistic_dummy_data()
            X = self.prepare_features(log_data)

        X_scaled = self.scaler.fit_transform(X)

        # Use higher contamination for more sensitivity
        self.model = IsolationForest(
            n_estimators=150,  # More trees
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
            max_features=0.8  # Use more features per tree
        )

        self.model.fit(X_scaled)
        print("✅ Model trained successfully with contamination:", contamination)

        self.save_model('models/anomaly_detector.pkl')

        return self.model

    def predict(self, log_entry):
        """Predict if log entry is anomalous with enhanced detection"""
        if not self.model:
            self.load_model('models/anomaly_detector.pkl')

        df = pd.DataFrame([log_entry])
        X = self.prepare_features(df)

        if X.shape[1] == 0:
            # If no features, use manual detection
            return self._manual_detection(log_entry)

        try:
            X_scaled = self.scaler.transform(X)
            score = self.model.score_samples(X_scaled)[0]

            # Convert to risk score (0-1)
            # Isolation Forest: more negative = more anomalous
            risk_score = 1 / (1 + np.exp(-score))  # Sigmoid to get 0-1

            # Apply manual rules to boost score for suspicious patterns
            boosted_score = self._apply_manual_boost(log_entry, risk_score)

            # Classify based on thresholds
            if boosted_score < self.safe_threshold:
                classification = 'normal'
            elif boosted_score < self.malicious_threshold:
                classification = 'suspicious'
            else:
                classification = 'malicious'

            return boosted_score, classification

        except Exception as e:
            print(f"⚠️ ML prediction failed: {e}")
            return self._manual_detection(log_entry)

    def _apply_manual_boost(self, log_entry, base_score):
        """Apply manual rules to boost risk score for suspicious patterns"""
        boosted_score = base_score

        # Check for known malicious IPs
        if 'source_ip' in log_entry:
            if self._is_suspicious_ip(log_entry['source_ip']):
                boosted_score = min(1.0, boosted_score + 0.4)

        # Check for hacking tools in user agent
        if 'user_agent' in log_entry:
            hacking_tools = ['sqlmap', 'nikto', 'nmap', 'metasploit', 'burp', 'hydra']
            ua = str(log_entry['user_agent']).lower()
            if any(tool in ua for tool in hacking_tools):
                boosted_score = min(1.0, boosted_score + 0.3)

        # Check for suspicious actions
        if 'action_type' in log_entry:
            suspicious_actions = ['BRUTE_FORCE', 'SQL_INJECTION', 'XSS', 'INJECTION',
                                  'EXPLOIT', 'SCAN', 'ENUMERATION']
            action = str(log_entry['action_type']).upper()
            if any(sus in action for sus in suspicious_actions):
                boosted_score = min(1.0, boosted_score + 0.25)

        # Check for unusual times (night/weekend)
        if 'access_time' in log_entry:
            try:
                access_time = pd.to_datetime(log_entry['access_time'])
                hour = access_time.hour
                day = access_time.weekday()
                if 0 <= hour <= 5:  # Midnight to 5 AM
                    boosted_score = min(1.0, boosted_score + 0.15)
                if day >= 5:  # Weekend
                    boosted_score = min(1.0, boosted_score + 0.1)
            except:
                pass

        return boosted_score

    def _manual_detection(self, log_entry):
        """Manual detection when ML fails"""
        score = 0.3  # Start with baseline

        # IP checks
        if 'source_ip' in log_entry:
            if self._is_suspicious_ip(log_entry['source_ip']):
                score += 0.3

        # User agent checks
        if 'user_agent' in log_entry:
            ua = str(log_entry['user_agent']).lower()
            if any(tool in ua for tool in ['sqlmap', 'nikto', 'nmap', 'metasploit']):
                score += 0.4

        # Action type checks
        if 'action_type' in log_entry:
            action = str(log_entry['action_type']).upper()
            if any(sus in action for sus in ['BRUTE_FORCE', 'SQL_INJECTION', 'EXPLOIT']):
                score += 0.3

        # Cap at 1.0
        score = min(1.0, score)

        # Classify
        if score < 0.3:
            return score, 'normal'
        elif score < 0.7:
            return score, 'suspicious'
        else:
            return score, 'malicious'

    def save_model(self, filepath):
        """Save model to file"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_columns': self.feature_columns,
            'thresholds': {
                'safe': self.safe_threshold,
                'suspicious': self.suspicious_threshold,
                'malicious': self.malicious_threshold
            }
        }
        joblib.dump(model_data, filepath)
        print(f"💾 Model saved to {filepath}")

    def load_model(self, filepath):
        """Load model from file"""
        try:
            model_data = joblib.load(filepath)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoders = model_data['label_encoders']
            self.feature_columns = model_data['feature_columns']

            # Load thresholds if they exist
            if 'thresholds' in model_data:
                thresholds = model_data['thresholds']
                self.safe_threshold = thresholds.get('safe', 0.2)
                self.suspicious_threshold = thresholds.get('suspicious', 0.5)
                self.malicious_threshold = thresholds.get('malicious', 0.7)

            print(f"📂 Model loaded from {filepath}")
            print(f"   Thresholds: Safe={self.safe_threshold}, "
                  f"Suspicious={self.suspicious_threshold}, "
                  f"Malicious={self.malicious_threshold}")
        except Exception as e:
            print(f"⚠️ No saved model found or error loading: {e}")
            print("Training new model with realistic data...")
            dummy_data = self.generate_realistic_dummy_data()
            self.train_model(dummy_data, contamination=0.25)  # Even higher for testing

    def generate_realistic_dummy_data(self, n_samples=2000):
        """Generate realistic dummy data with some anomalies"""
        np.random.seed(42)
        data = []

        # Normal patterns
        for i in range(int(n_samples * 0.8)):
            hour = np.random.choice([9, 10, 11, 14, 15, 16], p=[0.15, 0.2, 0.2, 0.2, 0.15, 0.1])
            day = np.random.choice([0, 1, 2, 3, 4], p=[0.2, 0.2, 0.2, 0.2, 0.2])  # Weekdays
            ip = f'192.168.1.{np.random.randint(1, 50)}'
            action = np.random.choice(['READ', 'LOGIN', 'API_CALL', 'VIEW'], p=[0.4, 0.3, 0.2, 0.1])
            country = np.random.choice(['US', 'UK', 'DE', 'CA'], p=[0.5, 0.2, 0.2, 0.1])
            ua = np.random.choice(['Chrome', 'Firefox', 'Safari', 'Edge'])

            data.append({
                'access_time': datetime(2023, 12, np.random.randint(1, 31), hour, 0, 0),
                'source_ip': ip,
                'action_type': action,
                'country': country,
                'user_agent': ua,
                'http_method': 'GET'
            })

        # Anomalous patterns (20% of data)
        for i in range(int(n_samples * 0.2)):
            hour = np.random.choice([0, 1, 2, 3, 4, 22, 23])  # Night hours
            day = np.random.choice([5, 6])  # Weekend
            ip = np.random.choice(['185.220.101.204', '203.0.113.42', '198.51.100.99'])
            action = np.random.choice(['BRUTE_FORCE', 'SQL_INJECTION', 'PORT_SCAN', 'EXPLOIT'])
            country = np.random.choice(['RU', 'CN', 'IR', 'KP'])
            ua = np.random.choice(['sqlmap/1.6', 'nikto/2.1.6', 'nmap/7.80', 'python-requests'])

            data.append({
                'access_time': datetime(2023, 12, np.random.randint(1, 31), hour, 0, 0),
                'source_ip': ip,
                'action_type': action,
                'country': country,
                'user_agent': ua,
                'http_method': 'POST'
            })

        return data

    def get_model_info(self):
        """Get model information"""
        if not self.model:
            return {"status": "Not trained"}

        return {
            "status": "Trained",
            "model_type": "Isolation Forest",
            "n_features": len(self.feature_columns),
            "features": self.feature_columns,
            "thresholds": {
                "safe": self.safe_threshold,
                "suspicious": self.suspicious_threshold,
                "malicious": self.malicious_threshold
            }
        }