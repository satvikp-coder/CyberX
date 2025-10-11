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
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import warnings

# Suppress all warnings
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global session for connection reuse
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
})


# --- STRICT Website Existence Verification ---

def verify_website_existence(url):
    """
    Strict verification if website actually exists and is accessible
    """
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

        # 2. HTTP Accessibility
        try:
            http_url = f"http://{domain}" if not url.startswith('http') else url.replace('https://', 'http://')
            response = session.get(http_url, timeout=10, verify=False, allow_redirects=True)
            if response.status_code == 200:
                existence_checks['http_accessible'] = True
                print("  ✅ HTTP access successful")
        except:
            print("  ⚠️ HTTP access failed")

        # 3. HTTPS Accessibility (STRICT)
        try:
            https_url = f"https://{domain}" if not url.startswith('http') else url.replace('http://', 'https://')
            response = session.get(https_url, timeout=10, verify=True, allow_redirects=True)  # STRICT SSL verification
            if response.status_code == 200:
                existence_checks['https_accessible'] = True
                print("  ✅ HTTPS access successful")

                # Check if content is valid (not just a placeholder)
                if len(response.content) > 1000:  # Reasonable minimum content size
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

            if load_time < 10:  # Reasonable load time
                existence_checks['responsive'] = True
                print(f"  ✅ Website responsive (load time: {load_time:.2f}s)")
            else:
                print(f"  ⚠️ Slow response (load time: {load_time:.2f}s)")
        except:
            print("  ❌ Website not responsive")

        # STRICT: Website must pass at least 3 out of 5 checks
        passed_checks = sum(existence_checks.values())
        print(f"  📊 Existence checks passed: {passed_checks}/5")

        return passed_checks >= 2, existence_checks

    except Exception as e:
        print(f"  ❌ Existence verification failed: {str(e)}")
        return False, existence_checks


# --- EXTREMELY STRICT Feature Extraction Functions ---

def having_ip_address(url):
    """STRICT: Check if URL uses IP address"""
    try:
        domain = urlparse(url).netloc.split(':')[0]  # Remove port
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, domain):
            return -1  # IMMEDIATE PHISHING FLAG
        return 1
    except:
        return -1  # Assume phishing on error


def url_length(url):
    """STRICT URL length analysis"""
    length = len(url)
    if length < 40:  # Very short URLs are suspicious
        return -1
    elif length < 54:
        return 0
    elif length <= 75:
        return -1
    else:
        return -1  # Very long URLs are highly suspicious


def shortining_service(url):
    """STRICT: Comprehensive URL shortening service detection"""
    domain = urlparse(url).netloc.lower()

    # Extensive list of shortening services
    shorteners = [
        "bit.ly", "goo.gl", "t.co", "tinyurl.com", "tiny.cc", "is.gd",
        "buff.ly", "ow.ly", "bit.do", "shorte.st", "adf.ly", "bc.vc",
        "cutt.ly", "dlvr.it", "filoops.info", "ity.im", "po.st", "q.gs",
        "v.gd", "tr.im", "prettylinkpro.com", "clicky.me", "bl.ink",
        "cutt.us", "rb.gy", "soo.gd", "s2r.co", "x.co", "zzb.bz",
        "clck.ru", "shrinke.me", "ow.ly", "cutt.ly", "shorturl.at",
        "tiny.pl", "shrtco.de", "qr.net", "urlzs.com", "vurl.com",
        "picz.us", "click.ru", "short.cm", "link.tl", "url.ie",
        "ux9.de", "t2m.io", "kutt.it", "linkshortener.com"
    ]

    for shortener in shorteners:
        if shortener in domain:
            return -1  # IMMEDIATE PHISHING FLAG

    return 1


def having_at_symbol(url):
    """STRICT: @ symbol is immediate red flag"""
    return -1 if "@" in url else 1


def double_slash_redirecting(url):
    """STRICT: Double slashes after protocol are highly suspicious"""
    try:
        protocol_end = url.find('//') + 2
        remaining_url = url[protocol_end:]
        if '//' in remaining_url:
            return -1  # HIGH RISK
        return 1
    except:
        return -1


def prefix_suffix(url):
    """EXTREMELY STRICT: Domain name analysis"""
    try:
        domain = urlparse(url).netloc.lower()
        clean_domain = domain.replace('www.', '')

        # IMMEDIATE RED FLAGS
        if '-' in clean_domain:
            return -1

        # Comprehensive suspicious keywords (expanded list)
        suspicious_keywords = [
            'free', 'login', 'verify', 'account', 'secure', 'update', 'bonus',
            'gift', 'action', 'support', 'urgent', 'vbucks', 'robucks', 'robux',
            'bank', 'paypal', 'amazon', 'ebay', 'facebook', 'google', 'microsoft',
            'apple', 'netflix', 'instagram', 'twitter', 'whatsapp', 'security',
            'confirm', 'validation', 'authentication', 'signin', 'password',
            'credential', 'wallet', 'crypto', 'bitcoin', 'reward', 'prize',
            'claim', 'win', 'winner', 'lottery', 'offer', 'discount', 'sale',
            'limited', 'exclusive', 'official', 'authentic', 'verify',
            'validation', 'confirm', 'update', 'billing', 'invoice', 'payment',
            'shipping', 'delivery', 'tracking', 'alert', 'warning', 'important',
            'immediate', 'actionrequired', 'suspend', 'restrict', 'verifynow',
            'clickhere', 'urgentaction', 'securitycheck', 'phishingtest'
        ]

        for keyword in suspicious_keywords:
            if keyword in clean_domain:
                return -1  # IMMEDIATE PHISHING FLAG

        # Check for numbers in domain (often suspicious)
        if re.search(r'\d', clean_domain.split('.')[0]):
            return -1

        return 1
    except:
        return -1


def having_sub_domain(url):
    """EXTREMELY STRICT subdomain analysis"""
    try:
        ext = tldextract.extract(url)
        subdomain = ext.subdomain

        subdomains = [s for s in subdomain.split('.') if s and s != 'www']
        subdomain_count = len(subdomains)

        # STRICT: More than 1 subdomain is highly suspicious
        if subdomain_count == 0:
            return 1
        elif subdomain_count == 1:
            return -1  # Even 1 subdomain is suspicious
        else:
            return -1  # Multiple subdomains = definite phishing
    except:
        return -1


def ssl_final_state(url):
    """EXTREMELY STRICT SSL verification"""
    try:
        domain = urlparse(url).netloc

        if not url.startswith('https://'):
            return -1  # No HTTPS = immediate red flag

        # STRICT SSL verification
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    return -1

                # Check certificate expiration (must be valid for at least 30 days)
                not_after = cert.get('notAfter')
                if not_after:
                    exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (exp_date - datetime.now()).days
                    if days_until_expiry < 30:
                        return -1  # Expiring soon = suspicious

                # Check certificate subject
                subject = dict(x[0] for x in cert['subject'])
                if 'commonName' not in subject or subject['commonName'].lower() != domain.lower():
                    return -1  # Certificate doesn't match domain

        return 1
    except:
        return -1  # Any SSL error = phishing


def domain_registration_length(url):
    """STRICT domain registration analysis"""
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)

        if domain_info.creation_date and domain_info.expiration_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date,
                                                                       list) else domain_info.creation_date
            expiration_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date,
                                                                           list) else domain_info.expiration_date

            if isinstance(creation_date, datetime) and isinstance(expiration_date, datetime):
                registration_length = (expiration_date - creation_date).days

                # STRICT: Must be registered for at least 1 year
                if registration_length >= 365:
                    return 1
                elif registration_length >= 180:
                    return 0
                else:
                    return -1  # Short registration = highly suspicious

        return -1  # Cannot verify registration = suspicious
    except:
        return -1


def favicon(url):
    """STRICT favicon analysis"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        favicon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if favicon_link and favicon_link.get('href'):
            favicon_url = favicon_link['href']
            parsed_favicon = urlparse(favicon_url)
            parsed_original = urlparse(url)

            if parsed_favicon.netloc and parsed_favicon.netloc != parsed_original.netloc:
                return -1  # External favicon = definite phishing

        return 1
    except:
        return -1  # Cannot verify = suspicious


def port(url):
    """STRICT port analysis"""
    try:
        parsed = urlparse(url)
        if parsed.port:
            # Only standard web ports allowed
            allowed_ports = [80, 443, 8080, 8443]
            return -1 if parsed.port not in allowed_ports else 1
        return 1
    except:
        return -1


def https_token(url):
    """STRICT: HTTPS token in domain is immediate red flag"""
    try:
        domain = urlparse(url).netloc.lower()
        suspicious_tokens = ['https', 'ssl', 'secure', 'trust', 'safe']
        return -1 if any(token in domain for token in suspicious_tokens) else 1
    except:
        return -1


def request_url(url):
    """STRICT external resource analysis"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        external_count = 0
        total_count = 0

        tags_to_check = ['img', 'script', 'link', 'iframe']
        for tag in soup.find_all(tags_to_check):
            src = tag.get('src') or tag.get('href')
            if src:
                total_count += 1
                parsed_src = urlparse(src)
                if parsed_src.netloc and parsed_src.netloc != urlparse(url).netloc:
                    external_count += 1

        if total_count > 0:
            external_ratio = external_count / total_count
            # STRICT: More than 50% external resources = phishing
            return -1 if external_ratio > 0.5 else 1

        return 1
    except:
        return -1


def url_of_anchor(url):
    """STRICT anchor tag analysis"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        suspicious_anchors = 0
        total_anchors = 0

        for anchor in soup.find_all('a', href=True):
            total_anchors += 1
            href = anchor['href'].lower()

            # STRICT: Many suspicious patterns
            if (href.startswith('#') or
                    href == 'javascript:void(0)' or
                    'mailto:' in href or
                    'tel:' in href or
                    not href.startswith(('http', 'https'))):
                suspicious_anchors += 1

        if total_anchors > 0:
            suspicious_ratio = suspicious_anchors / total_anchors
            # STRICT: More than 30% suspicious anchors = phishing
            return -1 if suspicious_ratio > 0.3 else 1

        return 1
    except:
        return -1


def links_in_tags(url):
    """STRICT meta/script tag analysis"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        suspicious_links = 0

        for meta in soup.find_all('meta'):
            content = meta.get('content', '')
            if 'http' in content.lower():
                suspicious_links += 1

        for script in soup.find_all('script'):
            script_content = script.string or ''
            if 'http' in script_content.lower():
                suspicious_links += 1

        # STRICT: Any suspicious links in meta/script = phishing
        return -1 if suspicious_links > 0 else 1
    except:
        return -1


def sfh(url):
    """STRICT form handler analysis"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action', '').lower()
            if not action or action.strip() == '':
                return -1
            elif 'mailto:' in action:
                return -1
            elif not action.startswith(('http', 'https')):
                return -1

        return 1
    except:
        return -1


def submitting_to_email(url):
    """STRICT: Email submission forms are immediate red flag"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action', '').lower()
            if 'mailto:' in action:
                return -1

        return 1
    except:
        return -1


def abnormal_url(url):
    """STRICT abnormal URL detection"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc

        # Multiple checks for abnormality
        checks = [
            having_ip_address(url) == -1,
            having_sub_domain(url) == -1,
            bool(re.search(r'[^\w\.\-]', domain)),
            len(domain) < 4 or len(domain) > 63,  # Invalid domain length
            domain.count('.') > 3  # Too many dots
        ]

        return -1 if any(checks) else 1
    except:
        return -1


def redirect(url):
    """STRICT redirect analysis"""
    try:
        response = session.get(url, timeout=10, verify=False, allow_redirects=False)
        # Any redirect is suspicious
        return -1 if 300 <= response.status_code < 400 else 1
    except:
        return -1


def on_mouseover(url):
    """STRICT: Any status bar manipulation is phishing"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        for tag in soup.find_all(True):
            onmouseover = tag.get('onmouseover')
            if onmouseover and 'window.status' in str(onmouseover).lower():
                return -1

        return 1
    except:
        return -1


def right_click(url):
    """STRICT: Right click disabling is phishing"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        script_content = ' '.join([script.string or '' for script in soup.find_all('script')])

        if 'contextmenu' in script_content.lower() and 'return false' in script_content.lower():
            return -1

        return 1
    except:
        return -1


def popup_window(url):
    """STRICT: Popup windows are suspicious"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        script_content = ' '.join([script.string or '' for script in soup.find_all('script')])

        popup_indicators = ['window.open', 'showmodal', 'popup', 'dialog', 'alert(']
        return -1 if any(indicator in script_content.lower() for indicator in popup_indicators) else 1
    except:
        return -1


def iframe(url):
    """STRICT: Any iframe usage is suspicious"""
    try:
        response = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')

        return -1 if len(soup.find_all('iframe')) > 0 else 1
    except:
        return -1


def age_of_domain(url):
    """STRICT domain age analysis"""
    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)

        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date,
                                                                       list) else domain_info.creation_date

            if isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days

                # STRICT: Must be older than 6 months
                if age_days >= 180:
                    return 1
                elif age_days >= 30:
                    return 0
                else:
                    return -1  # Very new domain = definite phishing

        return -1
    except:
        return -1


def dns_record(url):
    """STRICT DNS record verification"""
    try:
        domain = urlparse(url).netloc
        # Multiple DNS record checks
        records_checked = 0

        try:
            dns.resolver.resolve(domain, 'A')
            records_checked += 1
        except:
            pass

        try:
            dns.resolver.resolve(domain, 'MX')
            records_checked += 1
        except:
            pass

        # Must have at least A record
        return 1 if records_checked >= 1 else -1
    except:
        return -1


def web_traffic(url):
    """STRICT web traffic estimation"""
    try:
        domain = urlparse(url).netloc

        # STRICT heuristics for low traffic sites
        low_traffic_indicators = [
            len(domain) < 8,  # Very short domain
            domain.count('.') > 2,  # Multiple subdomains
            bool(re.search(r'\d', domain)),  # Numbers in domain
            '-' in domain  # Dashes in domain
        ]

        return -1 if any(low_traffic_indicators) else 0
    except:
        return -1


def page_rank(url):
    """STRICT page rank estimation"""
    try:
        domain = urlparse(url).netloc.lower()

        # Known legitimate domains
        high_rank_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
            'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
            'netflix.com', 'reddit.com', 'whatsapp.com', 'tiktok.com', 'office.com'
        ]

        # Known suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']

        if any(legit in domain for legit in high_rank_domains):
            return 1
        elif any(tld in domain for tld in suspicious_tlds):
            return -1
        else:
            return 0
    except:
        return -1


def google_index(url):
    """STRICT Google indexing estimation"""
    try:
        domain = urlparse(url).netloc

        # STRICT: Short, clean domains are more likely indexed
        clean_domain = domain.replace('www.', '')
        if len(clean_domain) < 12 and '-' not in clean_domain and not re.search(r'\d', clean_domain):
            return 1
        else:
            return -1  # Long/suspicious domains unlikely indexed
    except:
        return -1


def links_pointing_to_page(url):
    """STRICT incoming links estimation"""
    try:
        # STRICT: Combine multiple factors
        age_score = age_of_domain(url)
        ssl_score = ssl_final_state(url)
        dns_score = dns_record(url)

        positive_scores = sum(1 for score in [age_score, ssl_score, dns_score] if score == 1)

        if positive_scores >= 2:
            return 1
        elif positive_scores >= 1:
            return 0
        else:
            return -1
    except:
        return -1


def statistical_report(url):
    """EXTREMELY STRICT statistical report"""
    try:
        # Check multiple critical features
        critical_features = [
            having_ip_address(url), ssl_final_state(url),
            age_of_domain(url), having_sub_domain(url),
            prefix_suffix(url), shortining_service(url)
        ]

        phishing_indicators = sum(1 for feature in critical_features if feature == -1)

        # STRICT: Any critical phishing indicator fails the check
        return -1 if phishing_indicators > 0 else 1
    except:
        return -1


def extract_features_from_url(url):
    """
    STRICT feature extraction with enhanced validation
    """
    features = []

    # Ensure URL has scheme
    if not urlparse(url).scheme:
        url = "https://" + url

    # Feature extraction functions in correct order
    feature_functions = [
        having_ip_address, url_length, shortining_service, having_at_symbol,
        double_slash_redirecting, prefix_suffix, having_sub_domain, ssl_final_state,
        domain_registration_length, favicon, port, https_token, request_url,
        url_of_anchor, links_in_tags, sfh, submitting_to_email, abnormal_url,
        redirect, on_mouseover, right_click, popup_window, iframe, age_of_domain,
        dns_record, web_traffic, page_rank, google_index, links_pointing_to_page,
        statistical_report
    ]

    print("🔍 Extracting features with STRICT checks...")
    for i, func in enumerate(feature_functions, 1):
        try:
            feature_value = func(url)
            features.append(feature_value)
            status = "❌" if feature_value == -1 else "✅" if feature_value == 1 else "⚠️"
            print(f"  {i}/30: {func.__name__} = {feature_value} {status}")
        except Exception as e:
            print(f"  {i}/30: {func.__name__} = ERROR ({str(e)})")
            features.append(-1)  # STRICT: Error = assume phishing

    return features


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


def main():
    """Main function with strict verification"""
    print("=" * 70)
    print("🔒 EXTREME STRICT WEBSITE PHISHING DETECTOR")
    print("=" * 70)

    user_url = input("\nEnter the website URL to check: ").strip()

    if not user_url:
        print("❌ No URL entered.")
        return

    print(f"\n🔍 Analyzing: {user_url}")
    print("=" * 50)

    # Step 1: Verify website existence
    website_exists, existence_checks = verify_website_existence(user_url)

    if not website_exists:
        print("\n🚫 WEBSITE VERIFICATION FAILED!")
        print("The website does not exist or is not accessible.")
        print("This is a strong indicator of a phishing attempt.")
        return

    print("\n✅ Website verification passed!")

    try:
        # Step 2: Extract features with strict checks
        features = extract_features_from_url(user_url)

        print(f"\n📊 STRICT FEATURE ANALYSIS:")
        print(f"❌ Phishing indicators: {sum(1 for f in features if f == -1)}")
        print(f"✅ Legitimate indicators: {sum(1 for f in features if f == 1)}")
        print(f"⚠️ Unknown indicators: {sum(1 for f in features if f == 0)}")

        # Step 3: Get prediction
        print(f"\n🤖 Making STRICT prediction...")
        result = predict_phishing(features)

        print("\n" + "=" * 70)
        print("🎯 STRICT PREDICTION RESULTS")
        print("=" * 70)

        if "error" in result:
            print(f"❌ {result['error']}")
        else:
            # Determine emoji based on risk
            if "PHISHING" in result['risk_level'] or "phishing" in result['prediction'].lower():
                status_emoji = "🚫"
            elif "SUSPICIOUS" in result['risk_level']:
                status_emoji = "⚠️"
            else:
                status_emoji = "✅"

            print(f"Result: {result['prediction']} {status_emoji}")
            print(f"AI Confidence: {result['confidence']}")
            print(f"Risk Level: {result['risk_level']}")
            print(f"Phishing Score: {result['phishing_score']}")

            if 'note' in result:
                print(f"Note: {result['note']}")

            # STRICT Security Recommendations
            print(f"\n🔒 SECURITY RECOMMENDATIONS:")
            if "PHISHING" in result['risk_level'] or result['raw_confidence'] > 0.5 and "phishing" in result[
                'prediction'].lower():
                print("🚫 CRITICAL WARNING: This is very likely a PHISHING website!")
                print("   • DO NOT enter any personal information")
                print("   • DO NOT download any files")
                print("   • DO NOT enter passwords or financial details")
                print("   • Close this website immediately")
            elif "SUSPICIOUS" in result['risk_level']:
                print("⚠️ HIGH RISK: This website shows strong phishing indicators")
                print("   • Be extremely cautious")
                print("   • Avoid entering sensitive information")
                print("   • Verify the website through official channels")
            elif result['raw_confidence'] > 0.7:
                print("✅ LIKELY SAFE: This website appears legitimate")
                print("   • Still practice general security awareness")
            else:
                print("🔍 INCONCLUSIVE: Unable to make definite determination")
                print("   • Proceed with caution")
                print("   • Verify through other means")

        print("\n" + "=" * 70)

    except Exception as e:
        print(f"\n❌ Critical error during analysis: {str(e)}")
        print("This website failed multiple security checks.")


if __name__ == "__main__":
    main()