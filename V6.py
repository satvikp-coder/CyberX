from flask import Flask, render_template, request, jsonify
import joblib
import pandas as pd
import numpy as np
import requests
import whois
import tldextract
from urllib.parse import urlparse
import re
from datetime import datetime
import ssl
import socket
import time
from bs4 import BeautifulSoup
import urllib3
import dns.resolver
import warnings

# Suppress all warnings
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Global session for connection reuse
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
})


# --- Include all your existing functions here ---
# Copy and paste ALL the functions from your original code:
# verify_website_existence, having_ip_address, url_length, etc.
# ... [PASTE ALL YOUR EXISTING FUNCTIONS HERE] ...

def verify_website_existence(url):
    """Your existing verify_website_existence function"""
    print("🔍 Verifying website existence...")
    existence_checks = {
        'dns_resolution': False,
        'http_accessible': False,
        'https_accessible': False,
        'responsive': False,
        'valid_content': False
    }
    try:
        domain = urlparse(url).netloc
        # 1. DNS Resolution Check
        try:
            dns.resolver.resolve(domain, 'A')
            existence_checks['dns_resolution'] = True
            print("  ✅ DNS resolution successful")
        except:
            print("  ❌ DNS resolution failed")
            return False, existence_checks

        # 2. HTTP Accessibility (OPTIONAL)
        try:
            http_url = f"http://{domain}" if not url.startswith('http') else url.replace('https://', 'http://')
            response = session.get(http_url, timeout=10, verify=False, allow_redirects=True)
            if response.status_code == 200:
                existence_checks['http_accessible'] = True
                print("  ✅ HTTP access successful")
        except:
            print("  ⚠️ HTTP access failed (optional)")

        # 3. HTTPS Accessibility (STRICT)
        try:
            https_url = f"https://{domain}" if not url.startswith('http') else url.replace('http://', 'https://')
            response = session.get(https_url, timeout=10, verify=True, allow_redirects=True)
            if response.status_code == 200:
                existence_checks['https_accessible'] = True
                print("  ✅ HTTPS access successful")
                if len(response.content) > 1000:
                    existence_checks['valid_content'] = True
                    print("  ✅ Valid content detected")
        except:
            print("  ❌ HTTPS access failed")

        # 4. Responsiveness Check
        try:
            test_url = https_url if existence_checks['https_accessible'] else http_url
            start_time = time.time()
            response = session.get(test_url, timeout=15, verify=False)
            load_time = time.time() - start_time
            if load_time < 10:
                existence_checks['responsive'] = True
                print(f"  ✅ Website responsive (load time: {load_time:.2f}s)")
            else:
                print(f"  ⚠️ Slow response (load time: {load_time:.2f}s)")
        except:
            print("  ❌ Website not responsive")

        passed_checks = sum(existence_checks.values())
        print(f"  📊 Existence checks passed: {passed_checks}/5")
        return passed_checks >= 2, existence_checks

    except Exception as e:
        print(f"  ❌ Existence verification failed: {str(e)}")
        return False, existence_checks


# ... [CONTINUE PASTING ALL YOUR OTHER FUNCTIONS] ...
# having_ip_address, url_length, shortining_service, etc.
# ... [PASTE EVERYTHING UNTIL THE MAIN FUNCTION] ...

def calculate_phishing_score(features):
    """Calculate strict phishing score"""
    phishing_indicators = sum(1 for f in features if f == -1)
    legitimate_indicators = sum(1 for f in features if f == 1)
    total_meaningful = phishing_indicators + legitimate_indicators

    if total_meaningful == 0:
        return 0.5, "UNKNOWN"

    phishing_ratio = phishing_indicators / total_meaningful

    if phishing_ratio >= 0.8:
        return phishing_ratio, "DEFINITE PHISHING"
    elif phishing_ratio >= 0.6:
        return phishing_ratio, "HIGH RISK PHISHING"
    elif phishing_ratio >= 0.4:
        return phishing_ratio, "SUSPICIOUS"
    elif phishing_ratio >= 0.2:
        return phishing_ratio, "LOW RISK"
    else:
        return phishing_ratio, "LIKELY LEGITIMATE"


def predict_phishing(features_list):
    """
    Enhanced prediction with strict scoring
    """
    try:
        # Try to use trained model first
        model = joblib.load('website_classifier.joblib')
        feature_columns = joblib.load('feature_columns.joblib')

        input_data = pd.DataFrame([features_list], columns=feature_columns)
        prediction = model.predict(input_data)[0]
        prediction_proba = model.predict_proba(input_data)[0]

        if prediction == 1:
            result = "Legitimate"
            confidence = prediction_proba[1]
        else:
            result = "Fake (Phishing)"
            confidence = prediction_proba[0]

        # Calculate strict phishing score as backup
        phishing_score, risk_level = calculate_phishing_score(features_list)

        return {
            "prediction": result,
            "confidence": f"{confidence * 100:.1f}%",
            "risk_level": risk_level,
            "phishing_score": f"{phishing_score * 100:.1f}%",
            "raw_confidence": confidence
        }

    except FileNotFoundError:
        # Fallback to strict manual analysis
        phishing_score, risk_level = calculate_phishing_score(features_list)
        return {
            "prediction": "PHISHING" if phishing_score >= 0.5 else "LEGITIMATE",
            "confidence": f"{max(phishing_score, 1 - phishing_score) * 100:.1f}%",
            "risk_level": risk_level,
            "phishing_score": f"{phishing_score * 100:.1f}%",
            "raw_confidence": max(phishing_score, 1 - phishing_score),
            "note": "Using strict manual analysis (model not found)"
        }
    except Exception as e:
        return {"error": f"Prediction error: {str(e)}"}


# Flask Routes
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze_url():
    """API endpoint to analyze URL"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        user_url = data['url'].strip()
        if not user_url:
            return jsonify({'error': 'URL cannot be empty'}), 400

        print(f"🔍 Analyzing URL from web: {user_url}")

        # Step 1: Verify website existence
        website_exists, existence_checks = verify_website_existence(user_url)

        if not website_exists:
            return jsonify({
                'error': 'Website verification failed',
                'details': 'The website does not exist or is not accessible',
                'existence_checks': existence_checks
            }), 400

        # Step 2: Extract features
        features = extract_features_from_url(user_url)

        # Step 3: Get prediction
        result = predict_phishing(features)

        # Add additional information to result
        result['url'] = user_url
        result['existence_checks'] = existence_checks
        result['feature_analysis'] = {
            'phishing_indicators': sum(1 for f in features if f == -1),
            'legitimate_indicators': sum(1 for f in features if f == 1),
            'unknown_indicators': sum(1 for f in features if f == 0)
        }

        return jsonify(result)

    except Exception as e:
        print(f"Error in analyze_url: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500


@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'Phishing Detector API is running'})


if __name__ == '__main__':
    print("🚀 Starting Phishing Detection Web Server...")
    print("📍 Visit http://localhost:5000 to access the web interface")
    app.run(debug=True, host='0.0.0.0', port=5000)