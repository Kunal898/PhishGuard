"""
URL Feature Extractor for Phishing Detection
Extracts lexical and domain-based features from URLs.
"""

import re
import math
import socket
from urllib.parse import urlparse
import tldextract

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_WORDS = [
    'login', 'verify', 'secure', 'bank', 'update', 'free', 'lucky',
    'service', 'bonus', 'ebayisapi', 'webscr', 'signin', 'account',
    'confirm', 'password', 'suspend', 'alert', 'billing', 'pay',
    'security', 'unusual', 'activity', 'notification', 'limited',
    'click', 'urgent', 'immediately', 'expire', 'validate',
    'wallet', 'prize', 'gift', 'reward', 'offer', 'deal',
    'restore', 'recover', 'unlock', 'authenticate', 'credential'
]


def is_ip_address(domain: str) -> bool:
    """Check if the domain is an IP address."""
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        pass
    # Check for hex/octal IP patterns
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$|'
        r'^0x[0-9a-fA-F]+|'
        r'^\d{8,}$'
    )
    return bool(ip_pattern.match(domain))


def count_suspicious_words(url: str) -> int:
    """Count the number of suspicious words in the URL."""
    url_lower = url.lower()
    count = 0
    for word in SUSPICIOUS_WORDS:
        if word in url_lower:
            count += 1
    return count


def get_digit_letter_ratio(url: str) -> float:
    """Calculate the ratio of digits to letters in the URL."""
    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    if letters == 0:
        return float(digits) if digits > 0 else 0.0
    return round(digits / letters, 4)


def entropy(text: str) -> float:
    """Calculate Shannon entropy of the text."""
    if not text:
        return 0.0
    prob = {}
    for char in text:
        prob[char] = prob.get(char, 0) + 1
    length = len(text)
    ent = 0.0
    for count in prob.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return round(ent, 4)


def extract_features(url: str) -> dict:
    """
    Extract all features from a URL for phishing detection.
    Returns a dictionary with feature names and values.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = parsed.netloc
    path = parsed.path
    full_url = url

    # --- Lexical Features ---
    url_length = len(full_url)
    domain_length = len(domain)
    path_length = len(path)
    num_dots = full_url.count('.')
    num_hyphens = domain.count('-')
    num_underscores = full_url.count('_')
    num_slashes = full_url.count('/')
    num_digits_url = sum(c.isdigit() for c in full_url)

    # Subdomain analysis
    subdomain = extracted.subdomain
    num_subdomains = len(subdomain.split('.')) if subdomain else 0

    # Boolean features
    has_ip = 1 if is_ip_address(extracted.domain) else 0
    has_https = 1 if parsed.scheme == 'https' else 0
    has_at_symbol = 1 if '@' in full_url else 0
    has_double_slash = 1 if '//' in full_url[8:] else 0  # After protocol
    has_dash_in_domain = 1 if '-' in extracted.domain else 0
    has_equals = 1 if '=' in full_url else 0
    has_question_mark = 1 if '?' in full_url else 0
    has_ampersand = 1 if '&' in full_url else 0
    has_tilde = 1 if '~' in full_url else 0
    has_percent = 1 if '%' in full_url else 0

    # Numeric features
    digit_letter_ratio = get_digit_letter_ratio(full_url)
    suspicious_word_count = count_suspicious_words(full_url)
    url_entropy = entropy(full_url)
    domain_entropy = entropy(domain)

    # Query string features
    query = parsed.query
    num_params = len(query.split('&')) if query else 0
    query_length = len(query)

    # Fragment
    has_fragment = 1 if parsed.fragment else 0

    # Port
    has_non_standard_port = 0
    if parsed.port and parsed.port not in [80, 443]:
        has_non_standard_port = 1

    # TLD analysis
    tld = extracted.suffix
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw', 'cc', 'club', 'work', 'date', 'racing', 'stream']
    has_suspicious_tld = 1 if tld.lower() in suspicious_tlds else 0

    # Path features
    path_tokens = [t for t in path.split('/') if t]
    num_path_tokens = len(path_tokens)
    max_path_token_len = max((len(t) for t in path_tokens), default=0)

    # Special character density
    special_chars = sum(not c.isalnum() and c not in './-:' for c in full_url)
    special_char_ratio = round(special_chars / max(len(full_url), 1), 4)

    # WWW prefix
    has_www = 1 if 'www.' in domain else 0

    features = {
        # Lexical features
        'url_length': url_length,
        'domain_length': domain_length,
        'path_length': path_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_slashes': num_slashes,
        'num_digits': num_digits_url,
        'num_subdomains': num_subdomains,
        'digit_letter_ratio': digit_letter_ratio,
        'url_entropy': url_entropy,
        'domain_entropy': domain_entropy,

        # Boolean features
        'has_ip_address': has_ip,
        'has_https': has_https,
        'has_at_symbol': has_at_symbol,
        'has_double_slash_redirect': has_double_slash,
        'has_dash_in_domain': has_dash_in_domain,
        'has_equals': has_equals,
        'has_question_mark': has_question_mark,
        'has_ampersand': has_ampersand,
        'has_tilde': has_tilde,
        'has_percent_encoding': has_percent,
        'has_non_standard_port': has_non_standard_port,
        'has_suspicious_tld': has_suspicious_tld,
        'has_www': has_www,
        'has_fragment': has_fragment,

        # Counts
        'suspicious_word_count': suspicious_word_count,
        'num_query_params': num_params,
        'query_length': query_length,
        'num_path_tokens': num_path_tokens,
        'max_path_token_length': max_path_token_len,
        'special_char_ratio': special_char_ratio,
    }

    return features


def features_to_vector(features: dict) -> list:
    """Convert features dict to ordered list for ML model input."""
    feature_order = [
        'url_length', 'domain_length', 'path_length', 'num_dots',
        'num_hyphens', 'num_underscores', 'num_slashes', 'num_digits',
        'num_subdomains', 'digit_letter_ratio', 'url_entropy', 'domain_entropy',
        'has_ip_address', 'has_https', 'has_at_symbol', 'has_double_slash_redirect',
        'has_dash_in_domain', 'has_equals', 'has_question_mark', 'has_ampersand',
        'has_tilde', 'has_percent_encoding', 'has_non_standard_port',
        'has_suspicious_tld', 'has_www', 'has_fragment',
        'suspicious_word_count', 'num_query_params', 'query_length',
        'num_path_tokens', 'max_path_token_length', 'special_char_ratio',
    ]
    return [features.get(f, 0) for f in feature_order]


# Feature names in the exact order expected by the model
FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'num_dots',
    'num_hyphens', 'num_underscores', 'num_slashes', 'num_digits',
    'num_subdomains', 'digit_letter_ratio', 'url_entropy', 'domain_entropy',
    'has_ip_address', 'has_https', 'has_at_symbol', 'has_double_slash_redirect',
    'has_dash_in_domain', 'has_equals', 'has_question_mark', 'has_ampersand',
    'has_tilde', 'has_percent_encoding', 'has_non_standard_port',
    'has_suspicious_tld', 'has_www', 'has_fragment',
    'suspicious_word_count', 'num_query_params', 'query_length',
    'num_path_tokens', 'max_path_token_length', 'special_char_ratio',
]


if __name__ == '__main__':
    # Test feature extraction
    test_urls = [
        'https://www.google.com',
        'http://192.168.1.1/login.php',
        'http://secure-bank-login.tk/verify?user=test&id=123',
        'https://paypal.com.suspicious-site.xyz/account/login',
    ]
    for url in test_urls:
        print(f"\nURL: {url}")
        feats = extract_features(url)
        for k, v in feats.items():
            print(f"  {k}: {v}")
