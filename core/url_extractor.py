import re
import math
from urllib.parse import urlparse
import tldextract

# Known URL shortening domains
SHORTENING_SERVICES = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 'rebrand.ly', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'shorturl.at',
    'trib.al', 'tiny.cc', 'rb.gy', 'shorte.st', 'hyperurl.co'
}

# High-risk TLDs commonly abused in phishing campaigns
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw', 'buzz',
    'work', 'club', 'fit', 'surf', 'click', 'link', 'icu', 'rest',
    'support', 'country', 'stream', 'gdn', 'mom', 'kim'
}

# Suspicious security and credential related keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'update',
    'secure', 'security', 'account', 'banking', 'wallet', 'confirm',
    'authenticate', 'password', 'credential', 'support', 'service',
    'paypal', 'appleid', 'microsoft', 'netflix', 'amazon', 'recovery',
    'webscr', 'ebayisapi', 'billing', 'invoice', 'unlock', 'suspended'
]

FEATURE_NAMES = [
    'url_length',
    'domain_length',
    'is_ip',
    'count_dots',
    'count_hyphens',
    'count_at',
    'count_question',
    'count_and',
    'count_equal',
    'count_slash',
    'count_percent',
    'count_digits',
    'count_subdomains',
    'has_https',
    'https_in_domain',
    'is_shortened',
    'has_suspicious_keyword',
    'path_depth',
    'prefix_suffix_hyphen',
    'entropy',
    'domain_entropy',
    'tld_risk',
    'punycode',
    'special_char_ratio'
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to quantify randomness in text."""
    if not text:
        return 0.0
    probabilities = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probabilities if p > 0)


def is_ip_address(domain: str) -> int:
    """Check if domain is an IPv4 or IPv6 address."""
    # IPv4 regex
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
    # Hex or IPv6 pattern
    ipv6_pattern = r'^\[?[0-9a-fA-F:]+\]?(:\d+)?$'
    if re.match(ipv4_pattern, domain) or (':' in domain and re.match(ipv6_pattern, domain)):
        return 1
    return 0


def extract_url_features(url: str) -> dict:
    """
    Extract 24 comprehensive lexical, structural, and behavioral features
    from an input URL string.
    """
    if not url:
        return {name: 0 for name in FEATURE_NAMES}

    # Normalize url
    clean_url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = 'http://' + clean_url

    parsed = urlparse(clean_url)
    extracted = tldextract.extract(clean_url)

    domain = (parsed.netloc or '').lower()
    path = parsed.path or ''
    query = parsed.query or ''
    full_url = clean_url.lower()

    # 1. Length features
    url_length = len(clean_url)
    domain_length = len(domain)

    # 2. IP address detection
    has_ip = is_ip_address(domain)

    # 3. Delimiter and punctuation counts
    count_dots = clean_url.count('.')
    count_hyphens = clean_url.count('-')
    count_at = clean_url.count('@')
    count_question = clean_url.count('?')
    count_and = clean_url.count('&')
    count_equal = clean_url.count('=')
    count_slash = clean_url.count('/')
    count_percent = clean_url.count('%')

    # 4. Digit count
    count_digits = sum(c.isdigit() for c in clean_url)

    # 5. Subdomain levels
    subdomain = extracted.subdomain
    count_subdomains = len(subdomain.split('.')) if subdomain else 0

    # 6. Scheme / HTTPS analysis
    has_https = 1 if parsed.scheme.lower() == 'https' else 0
    https_in_domain = 1 if 'https' in domain else 0

    # 7. Shortening service check
    registered_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    is_shortened = 1 if (domain in SHORTENING_SERVICES or registered_domain in SHORTENING_SERVICES) else 0

    # 8. Suspicious keywords check
    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full_url)
    has_suspicious_keyword = 1 if keyword_hits > 0 else 0

    # 9. Path depth
    path_segments = [p for p in path.split('/') if p]
    path_depth = len(path_segments)

    # 10. Prefix / Suffix hyphen in hostname
    prefix_suffix_hyphen = 1 if '-' in extracted.domain else 0

    # 11. Shannon Entropy
    entropy = round(calculate_entropy(clean_url), 4)
    domain_entropy = round(calculate_entropy(domain), 4)

    # 12. TLD risk
    tld = extracted.suffix.lower().split('.')[-1] if extracted.suffix else ''
    tld_risk = 1 if tld in SUSPICIOUS_TLDS else 0

    # 13. Punycode / IDN Homograph check
    punycode = 1 if ('xn--' in domain or any(ord(c) > 127 for c in clean_url)) else 0

    # 14. Special character ratio
    special_chars = sum(not c.isalnum() for c in clean_url)
    special_char_ratio = round(special_chars / max(1, url_length), 4)

    features = {
        'url_length': url_length,
        'domain_length': domain_length,
        'is_ip': has_ip,
        'count_dots': count_dots,
        'count_hyphens': count_hyphens,
        'count_at': count_at,
        'count_question': count_question,
        'count_and': count_and,
        'count_equal': count_equal,
        'count_slash': count_slash,
        'count_percent': count_percent,
        'count_digits': count_digits,
        'count_subdomains': count_subdomains,
        'has_https': has_https,
        'https_in_domain': https_in_domain,
        'is_shortened': is_shortened,
        'has_suspicious_keyword': has_suspicious_keyword,
        'path_depth': path_depth,
        'prefix_suffix_hyphen': prefix_suffix_hyphen,
        'entropy': entropy,
        'domain_entropy': domain_entropy,
        'tld_risk': tld_risk,
        'punycode': punycode,
        'special_char_ratio': special_char_ratio
    }

    return features


def features_to_vector(features: dict) -> list:
    """Convert features dictionary to ordered numeric vector matching FEATURE_NAMES."""
    return [features.get(name, 0) for name in FEATURE_NAMES]
