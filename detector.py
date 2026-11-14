import pandas as pd
import numpy as np
from datetime import datetime
import pickle
import os
import logging
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyDetector:
    def __init__(self, model_path='ai_detection/models/isolation_forest.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'is_weekend',
            'ip_hash', 'user_agent_hash', 'method_encoded',
            'attempts_last_hour', 'attempts_last_day',
            'unique_tokens_accessed', 'payload_length',
            'has_suspicious_pattern', 'country_risk_score'
        ]

        self._load_or_train_model()

    def _load_or_train_model(self):
        """Load existing model or train a new one"""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.scaler = data['scaler']
                    self.label_encoders = data['label_encoders']
                logger.info("AI model loaded successfully")
            except Exception as e:
                logger.error(f"Error loading model: {e}")
                self._train_initial_model()
        else:
            self._train_initial_model()

    def _train_initial_model(self):
        """Train initial model with synthetic normal data"""
        logger.info("Training initial AI model...")

        # Generate synthetic normal data
        np.random.seed(42)
        n_samples = 1000

        # Create normal patterns
        data = {
            'hour_of_day': np.random.randint(9, 18, n_samples),  # Normal work hours
            'day_of_week': np.random.randint(0, 5, n_samples),  # Weekdays
            'is_weekend': np.zeros(n_samples),
            'ip_hash': np.random.rand(n_samples) * 100,
            'user_agent_hash': np.random.rand(n_samples) * 100,
            'method_encoded': np.random.choice([0, 1], n_samples, p=[0.8, 0.2]),  # Mostly GET
            'attempts_last_hour': np.random.poisson(1, n_samples),
            'attempts_last_day': np.random.poisson(5, n_samples),
            'unique_tokens_accessed': np.random.randint(1, 3, n_samples),
            'payload_length': np.random.randint(0, 100, n_samples),
            'has_suspicious_pattern': np.zeros(n_samples),
            'country_risk_score': np.random.uniform(0, 0.3, n_samples)  # Low risk countries
        }

        df = pd.DataFrame(data)
        X = self.scaler.fit_transform(df[self.feature_columns])

        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,  # Expect 10% anomalies
            random_state=42
        )

        self.model.fit(X)

        # Save the model
        self._save_model()

        logger.info("Initial model trained and saved")

    def _save_model(self):
        """Save the trained model"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'label_encoders': self.label_encoders
            }, f)

    def extract_features(self, log_data):
        """Extract features from log data for AI analysis"""
        try:
            # Time-based features
            access_time = datetime.fromisoformat(str(log_data['access_time']))
            features = {
                'hour_of_day': access_time.hour,
                'day_of_week': access_time.weekday(),
                'is_weekend': 1 if access_time.weekday() >= 5 else 0,

                # Hash-based features for categorical data
                'ip_hash': self._hash_string(str(log_data.get('source_ip', ''))),
                'user_agent_hash': self._hash_string(str(log_data.get('user_agent', ''))),

                # Method encoding
                'method_encoded': self._encode_method(str(log_data.get('http_method', 'GET'))),

                # Behavioral features (would normally come from database)
                'attempts_last_hour': log_data.get('attempts_last_hour', 1),
                'attempts_last_day': log_data.get('attempts_last_day', 1),
                'unique_tokens_accessed': log_data.get('unique_tokens_accessed', 1),

                # Payload analysis
                'payload_length': len(str(log_data.get('request_data', ''))),
                'has_suspicious_pattern': self._check_suspicious_patterns(
                    str(log_data.get('request_data', ''))
                ),

                # Location risk (simplified)
                'country_risk_score': self._get_country_risk_score(
                    log_data.get('country', 'Unknown')
                )
            }

            return features

        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return None

    def _hash_string(self, text):
        """Create numeric hash from string"""
        return int(hashlib.sha256(text.encode()).hexdigest()[:8], 16) % 1000

    def _encode_method(self, method):
        """Encode HTTP method"""
        method = method.upper()
        if method in ['GET', 'HEAD', 'OPTIONS']:
            return 0  # Safe methods
        elif method in ['POST', 'PUT', 'PATCH']:
            return 1  # Data modification
        else:
            return 2  # Dangerous methods

    def _check_suspicious_patterns(self, payload):
        """Check for suspicious patterns in payload"""
        suspicious_patterns = [
            '../../', '../', 'etc/passwd', 'union select', 'drop table',
            'script>', '<script', 'javascript:', 'base64_decode',
            'exec(', 'system(', 'shell_exec', 'phpinfo'
        ]

        payload_lower = payload.lower()
        for pattern in suspicious_patterns:
            if pattern in payload_lower:
                return 1
        return 0

    def _get_country_risk_score(self, country):
        """Get risk score based on country (simplified)"""
        high_risk_countries = ['CN', 'RU', 'KP', 'IR', 'SY']
        medium_risk_countries = ['IN', 'BR', 'VN', 'TH', 'ID']

        country_code = country.upper() if len(country) == 2 else country[:2].upper()

        if country_code in high_risk_countries:
            return 0.8
        elif country_code in medium_risk_countries:
            return 0.5
        else:
            return 0.1

    def analyze_access(self, log_data):
        """Analyze access log and return risk assessment"""
        try:
            # Extract features
            features_dict = self.extract_features(log_data)
            if not features_dict:
                return {'risk_score': 0.5, 'risk_category': 'suspicious', 'confidence': 0.7}

            # Convert to DataFrame
            features_df = pd.DataFrame([features_dict])

            # Ensure all feature columns are present
            for col in self.feature_columns:
                if col not in features_df.columns:
                    features_df[col] = 0

            # Scale features
            X_scaled = self.scaler.transform(features_df[self.feature_columns])

            # Predict anomaly score
            anomaly_score = self.model.score_samples(X_scaled)[0]

            # Convert to risk score (0-1, where 1 is most risky)
            risk_score = 1 - (anomaly_score + 0.5)  # Normalize to 0-1

            # Determine risk category
            if risk_score < 0.3:
                risk_category = 'safe'
            elif risk_score < 0.7:
                risk_category = 'suspicious'
            else:
                risk_category = 'malicious'

            # Calculate confidence
            confidence = min(0.95, abs(anomaly_score) * 2)

            return {
                'risk_score': float(risk_score),
                'risk_category': risk_category,
                'confidence': float(confidence),
                'anomaly_score': float(anomaly_score),
                'features_used': self.feature_columns
            }

        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
            return {'risk_score': 0.5, 'risk_category': 'suspicious', 'confidence': 0.6}