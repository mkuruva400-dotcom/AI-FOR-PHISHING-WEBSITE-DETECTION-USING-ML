def calculate_url_heuristic_risk(features: dict) -> dict:
    """
    Computes rule-based URL structural threat score (0-100)
    and collects triggered security indicators.
    """
    score = 0
    reasons = []

    if features.get('is_ip', 0) == 1:
        score += 35
        reasons.append("Host is an IP address rather than a registered domain name.")

    if features.get('tld_risk', 0) == 1:
        score += 25
        reasons.append("Domain utilizes a high-abuse TLD (.tk, .xyz, .top, .ml, .cf, .pw).")

    if features.get('is_shortened', 0) == 1:
        score += 20
        reasons.append("URL is masked using a link-shortening service.")

    if features.get('has_https', 0) == 0:
        score += 20
        reasons.append("Insecure plain HTTP protocol used (no TLS encryption).")

    if features.get('https_in_domain', 0) == 1:
        score += 25
        reasons.append("Deceptive 'https' keyword embedded inside hostname.")

    if features.get('has_suspicious_keyword', 0) == 1:
        score += 20
        reasons.append("Contains sensitive authentication keywords (login, verify, update, account).")

    if features.get('punycode', 0) == 1:
        score += 30
        reasons.append("Punycode (xn--) or non-ASCII homograph characters detected (IDN spoofing).")

    if features.get('count_subdomains', 0) >= 3:
        score += 15
        reasons.append(f"Excessive subdomain depth ({features['count_subdomains']} levels).")

    if features.get('prefix_suffix_hyphen', 0) == 1:
        score += 15
        reasons.append("Hyphenated domain structure frequently used for typosquatting.")

    if features.get('count_at', 0) > 0:
        score += 30
        reasons.append("Contains '@' symbol designed to confuse browser URL parsing.")

    if features.get('entropy', 0) > 4.6:
        score += 15
        reasons.append("Abnormally high character entropy (DGA or obfuscation algorithm).")

    capped_score = min(100, score)
    return {
        'score': capped_score,
        'indicators': reasons
    }


def compute_composite_risk(
    ml_probability: float,
    url_features: dict,
    content_result: dict = None,
    visual_result: dict = None
) -> dict:
    """
    Computes an integrated 0-100 composite risk score blending:
    - Machine Learning & Deep Learning confidence (ml_probability)
    - URL Structural & Lexical Heuristics
    - Safe DOM & Content Inspection
    - Visual Similarity & Brand Impersonation

    Outputs comprehensive risk tier, color coding, warnings, and prevention advice.
    """
    # 1. ML Score (0 to 100)
    ml_score = round(ml_probability * 100, 1)

    # 2. URL Heuristics Score (0 to 100)
    url_heuristics = calculate_url_heuristic_risk(url_features)
    url_score = url_heuristics['score']

    # 3. Content Analysis Score (0 to 100)
    has_content = content_result is not None and content_result.get('accessible', False)
    content_score = content_result.get('content_risk_score', 0) if content_result else 0

    # 4. Visual Similarity Score (0 to 100)
    has_visual = visual_result is not None and visual_result.get('analyzed', False)
    visual_score = visual_result.get('visual_risk_score', 0) if visual_result else 0

    # Dynamic Weighting Fusion
    if has_content and has_visual:
        final_score = (
            0.35 * ml_score +
            0.25 * url_score +
            0.20 * content_score +
            0.20 * visual_score
        )
    elif has_content:
        final_score = (
            0.45 * ml_score +
            0.30 * url_score +
            0.25 * content_score
        )
    elif has_visual:
        final_score = (
            0.50 * ml_score +
            0.30 * url_score +
            0.20 * visual_score
        )
    else:
        final_score = (
            0.60 * ml_score +
            0.40 * url_score
        )

    # Override: Critical brand impersonation or blatant credential theft
    if visual_result and visual_result.get('is_impersonation', False):
        final_score = max(final_score, 85.0)
    if content_result and content_result.get('brand_impersonation'):
        final_score = max(final_score, 88.0)
    if content_result and content_result.get('has_password_field') and content_result.get('form_action_suspicious'):
        final_score = max(final_score, 85.0)

    final_score = round(min(100.0, max(0.0, final_score)), 1)

    # Classification Tier
    if final_score < 50.0:
        verdict = "LEGITIMATE"
        verdict_label = "LEGITIMATE (SAFE)"
        risk_level = "Low Risk - Safe Website"
        color = "#10b981"  # Emerald Green
        badge_class = "success"
        verdict_title = "VERDICT: LEGITIMATE WEBSITE"
        verdict_desc = "This URL has been analyzed and confirmed as SAFE & LEGITIMATE. No phishing patterns or malicious indicators were found."
    else:
        verdict = "PHISHING"
        verdict_label = "PHISHING (MALICIOUS)"
        risk_level = "High Risk - Malicious Phishing Site"
        color = "#ef4444"  # Crimson Red
        badge_class = "danger"
        verdict_title = "VERDICT: PHISHING WEBSITE DETECTED"
        verdict_desc = "CRITICAL ALERT: This URL has been identified as a fraudulent PHISHING website designed to steal credentials or personal data."

    # Compile All Security Warning Indicators
    all_warnings = list(url_heuristics['indicators'])
    if content_result and content_result.get('findings'):
        all_warnings.extend(content_result['findings'])
    if visual_result and visual_result.get('details'):
        all_warnings.extend(visual_result['details'])

    # Compile Actionable Prevention Advice
    prevention_tips = []
    if verdict == "PHISHING":
        prevention_tips = [
            "CRITICAL: Do NOT enter usernames, passwords, credit card numbers, or personal info.",
            "Close this webpage tab immediately to prevent credential harvesting or session hijacking.",
            "Do NOT download files, installers, or browser extensions from this domain.",
            "Verify the official URL of the brand/institution via known bookmarks or official search.",
            "If credentials were submitted, immediately reset passwords on official platforms and enable MFA.",
            "Block domain in organizational firewall / DNS resolvers."
        ]
    else:
        prevention_tips = [
            "Website exhibits low structural and behavioral risk indicators.",
            "Always ensure HTTPS padlock is active when transmitting sensitive data.",
            "Remain vigilant against unprompted requests for personal information."
        ]

    return {
        'risk_score': final_score,
        'verdict': verdict,
        'verdict_label': verdict_label,
        'verdict_title': verdict_title,
        'verdict_desc': verdict_desc,
        'risk_level': risk_level,
        'color': color,
        'badge_class': badge_class,
        'breakdown': {
            'ml_score': ml_score,
            'url_heuristic_score': url_score,
            'content_score': content_score if has_content else None,
            'visual_score': visual_score if has_visual else None
        },
        'warnings': all_warnings,
        'prevention_tips': prevention_tips
    }
