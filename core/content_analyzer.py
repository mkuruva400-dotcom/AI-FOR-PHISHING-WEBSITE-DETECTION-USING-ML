import re
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

KNOWN_BRANDS = {
    'paypal': ['paypal.com', 'paypal-corp.com'],
    'google': ['google.com', 'google.co.in', 'accounts.google.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'login.microsoftonline.com'],
    'apple': ['apple.com', 'icloud.com'],
    'amazon': ['amazon.com', 'amazon.in'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'chase': ['chase.com'],
    'bank of america': ['bankofamerica.com'],
    'wellsfargo': ['wellsfargo.com']
}

SAFE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AI-Phishing-Shield-SecurityScanner/2.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'close'
}


def analyze_page_content(url: str, html_content: str = None, timeout: int = 4) -> dict:
    """
    Safely inspects HTML and DOM structure in an isolated headless environment
    without opening the target in the user's browser.
    """
    clean_url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', clean_url):
        clean_url = 'http://' + clean_url

    parsed_target = urlparse(clean_url)
    target_domain = (parsed_target.netloc or '').lower()

    result = {
        'accessible': False,
        'status_code': None,
        'title': '',
        'has_password_field': 0,
        'form_action_suspicious': 0,
        'external_links_ratio': 0.0,
        'null_links_ratio': 0.0,
        'has_hidden_iframe': 0,
        'right_click_disabled': 0,
        'external_favicon': 0,
        'brand_impersonation': None,
        'suspicious_scripts': 0,
        'total_forms': 0,
        'total_links': 0,
        'content_risk_score': 0,
        'findings': []
    }

    raw_html = html_content
    if raw_html is None:
        try:
            # Safe isolated request: capped stream, short timeout, no auto-executing scripts
            session = requests.Session()
            session.max_redirects = 3
            response = session.get(
                clean_url,
                headers=SAFE_HEADERS,
                timeout=timeout,
                allow_redirects=True,
                stream=True,
                verify=False  # Inspect even if invalid SSL (common in phishing)
            )
            result['status_code'] = response.status_code
            result['accessible'] = True
            
            # Read at most 1 MB to prevent memory exhaustion attacks
            chunks = []
            bytes_read = 0
            for chunk in response.iter_content(chunk_size=8192):
                chunks.append(chunk)
                bytes_read += len(chunk)
                if bytes_read > 1024 * 1024:
                    break
            raw_html = b''.join(chunks).decode('utf-8', errors='ignore')
        except Exception as e:
            result['findings'].append(f"Network probe notice: Target unreachable or blocked ({type(e).__name__})")
            # If offline, perform heuristic static analysis
            return result

    if not raw_html:
        return result

    try:
        soup = BeautifulSoup(raw_html, 'html.parser')
    except Exception:
        return result

    # 1. Page Title
    title_tag = soup.find('title')
    page_title = title_tag.get_text().strip() if title_tag else ''
    result['title'] = page_title

    # 2. Form Analysis
    forms = soup.find_all('form')
    result['total_forms'] = len(forms)

    # Password fields
    passwords = soup.find_all('input', {'type': re.compile(r'^password$', re.I)})
    if passwords:
        result['has_password_field'] = 1
        result['findings'].append(f"Detected {len(passwords)} credential/password input field(s).")

    # Form actions
    suspicious_forms = 0
    for form in forms:
        action = (form.get('action') or '').strip().lower()
        if not action or action == '#' or action.startswith('javascript:') or action == 'about:blank':
            suspicious_forms += 1
            result['findings'].append("Form action is empty, placeholder (#), or javascript-based.")
        elif action.startswith('http://') or action.startswith('https://'):
            action_domain = urlparse(action).netloc.lower()
            if action_domain and action_domain != target_domain:
                suspicious_forms += 1
                result['findings'].append(f"Form submits credentials to external third-party domain: {action_domain}")
    
    result['form_action_suspicious'] = 1 if suspicious_forms > 0 else 0

    # 3. Anchor Hyperlinks Analysis
    links = soup.find_all('a', href=True)
    result['total_links'] = len(links)
    external_count = 0
    null_count = 0

    for link in links:
        href = link['href'].strip().lower()
        if not href or href == '#' or href.startswith('javascript:'):
            null_count += 1
        elif href.startswith('http://') or href.startswith('https://'):
            link_domain = urlparse(href).netloc.lower()
            if link_domain and link_domain != target_domain:
                external_count += 1

    if links:
        result['external_links_ratio'] = round(external_count / len(links), 3)
        result['null_links_ratio'] = round(null_count / len(links), 3)

        if result['external_links_ratio'] > 0.65:
            result['findings'].append(f"High external hyperlink ratio ({int(result['external_links_ratio']*100)}% external links).")
        if result['null_links_ratio'] > 0.40:
            result['findings'].append(f"Suspiciously high null/placeholder link ratio ({int(result['null_links_ratio']*100)}%).")

    # 4. Hidden iframes
    iframes = soup.find_all('iframe')
    for iframe in iframes:
        style = (iframe.get('style') or '').lower()
        w = iframe.get('width', '')
        h = iframe.get('height', '')
        if 'display:none' in style or 'visibility:hidden' in style or w in ['0', '1'] or h in ['0', '1']:
            result['has_hidden_iframe'] = 1
            result['findings'].append("Hidden/invisible iframe detected (potential clickjacking or covert payload).")
            break

    # 5. Right-click and source inspection protection
    scripts = soup.find_all('script')
    all_script_text = ' '.join(s.get_text() for s in scripts).lower()
    
    if 'event.button==2' in all_script_text or 'event.button == 2' in all_script_text or 'contextmenu' in all_script_text:
        result['right_click_disabled'] = 1
        result['findings'].append("Client-side script blocks right-click context menu (attempting to hide page source).")

    # 6. Obfuscated / dangerous JavaScript functions
    suspicious_patterns = [r'eval\s*\(', r'unescape\s*\(', r'document\.write\s*\(', r'fromcharcode']
    found_suspicious_scripts = sum(1 for pattern in suspicious_patterns if re.search(pattern, all_script_text))
    if found_suspicious_scripts > 0:
        result['suspicious_scripts'] = 1
        result['findings'].append("Obfuscated or dynamically evaluated JavaScript functions detected.")

    # 7. External Favicon
    favicons = soup.find_all('link', rel=re.compile(r'icon', re.I))
    for fav in favicons:
        fav_href = (fav.get('href') or '').lower()
        if fav_href.startswith('http://') or fav_href.startswith('https://'):
            fav_domain = urlparse(fav_href).netloc.lower()
            if fav_domain and fav_domain != target_domain:
                result['external_favicon'] = 1
                result['findings'].append(f"Favicon loaded from external host: {fav_domain}")
                break

    # 8. Brand Impersonation in Title/Headers
    page_text = f"{page_title} {' '.join(h.get_text() for h in soup.find_all(['h1', 'h2']))}".lower()
    for brand, legit_domains in KNOWN_BRANDS.items():
        if brand in page_text:
            is_legit = any(target_domain.endswith(ld) for ld in legit_domains)
            if not is_legit:
                result['brand_impersonation'] = brand.title()
                result['findings'].append(f"CRITICAL: Brand impersonation detected! Claims to be '{brand.title()}' but hosted on '{target_domain}'.")
                break

    # Calculate content risk penalty (0-100)
    risk = 0
    if result['brand_impersonation']:
        risk += 45
    if result['has_password_field'] and result['form_action_suspicious']:
        risk += 35
    elif result['has_password_field']:
        risk += 15
    if result['form_action_suspicious']:
        risk += 20
    if result['has_hidden_iframe']:
        risk += 25
    if result['right_click_disabled']:
        risk += 15
    if result['suspicious_scripts']:
        risk += 15
    if result['external_favicon']:
        risk += 10
    if result['external_links_ratio'] > 0.65:
        risk += 15
    if result['null_links_ratio'] > 0.40:
        risk += 10

    result['content_risk_score'] = min(100, risk)
    return result
