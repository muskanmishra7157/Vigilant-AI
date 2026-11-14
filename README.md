# Vigilant AI: Deception-Based Intrusion Detection System

## 📌 Project Overview
Vigilant AI is an end-to-end cybersecurity platform designed to proactively trap and log unauthorized network access using dynamic honeytokens. By analyzing behavioral features, the system detects anomalies in real-time using an Isolation Forest Machine Learning model.

## ⚙️ Tech Stack
* **Language:** Python
* **Machine Learning:** Scikit-Learn (Isolation Forest), Pandas, NumPy
* **Backend Framework:** Flask
* **Database:** SQLite
* **Visualization:** Plotly (Dashboard)

## 🚀 Key Features
1. **Dynamic Honeytokens:** Deployed fake endpoints (`/api/v1/secure-data`) acting as traps for malicious actors.
2. **Behavioral Feature Engineering:** Extracted 12+ features including geolocation IP codes, temporal anomalies (time of request), and payload signatures (length and characters).
3. **Real-Time Threat Detection:** Trained an Isolation Forest model achieving >90% accuracy and <4% false-positive rate.
4. **Automated Logging:** SQLite database integration for logging attack vectors and incident tracking.

## 🛠️ How to Run
1. Install requirements: `pip install -r requirements.txt`
2. Train the ML model: `python train_model.py`
3. Start the Flask Backend: `python app.py`
4. Access the honeytoken endpoint: `http://localhost:5000/api/v1/secure-data`