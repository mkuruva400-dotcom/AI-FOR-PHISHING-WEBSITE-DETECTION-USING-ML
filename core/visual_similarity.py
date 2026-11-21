import os
import cv2
import numpy as np
from urllib.parse import urlparse

AUTHORIZED_DOMAINS = {
    'google': ['google.com', 'google.co.in', 'accounts.google.com'],
    'paypal': ['paypal.com', 'paypal-corp.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'login.microsoftonline.com'],
    'amazon': ['amazon.com', 'amazon.in'],
    'netflix': ['netflix.com']
}

def calculate_dhash(image, hash_size=8) -> int:
    """Computes difference hash (dHash) for an image to evaluate structural similarity."""
    resized = cv2.resize(image, (hash_size + 1, hash_size))
    if len(resized.shape) == 3:
        gray = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
    else:
        gray = resized
    diff = gray[:, 1:] > gray[:, :-1]
    return sum([2 ** i for (i, v) in enumerate(diff.flatten()) if v])

def hamming_distance(hash1: int, hash2: int) -> int:
    """Computes bitwise Hamming distance between two integer hashes."""
    return bin(hash1 ^ hash2).count('1')

def calculate_hist_similarity(img1, img2) -> float:
    """Computes normalized HSV color histogram correlation between two images (0.0 to 1.0)."""
    hsv1 = cv2.cvtColor(cv2.resize(img1, (128, 128)), cv2.COLOR_BGR2HSV)
    hsv2 = cv2.cvtColor(cv2.resize(img2, (128, 128)), cv2.COLOR_BGR2HSV)

    hist1 = cv2.calcHist([hsv1], [0, 1], None, [30, 32], [0, 180, 0, 256])
    hist2 = cv2.calcHist([hsv2], [0, 1], None, [30, 32], [0, 180, 0, 256])

    cv2.normalize(hist1, hist1, 0, 1, cv2.NORM_MINMAX)
    cv2.normalize(hist2, hist2, 0, 1, cv2.NORM_MINMAX)

    score = cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL)
    return max(0.0, float(score))

def compare_screenshot_with_brands(image_path: str = None, image_bytes: bytes = None, domain: str = "") -> dict:
    """
    Analyzes an input screenshot or logo against legitimate brand targets.
    Flags deceptive brand impersonation when similarity is high on non-official domains.
    """
    result = {
        'analyzed': False,
        'matched_brand': None,
        'similarity_score': 0.0,
        'is_impersonation': False,
        'visual_risk_score': 0,
        'details': [],
        'brand_scores': {}
    }

    try:
        img = None
        if image_path and os.path.exists(image_path):
            img = cv2.imread(image_path)
        elif image_bytes:
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            return result

        result['analyzed'] = True
        input_hash = calculate_dhash(img)

        # Base directory where brand templates are stored
        base_dir = os.path.dirname(__file__)
        brand_dir = os.path.abspath(os.path.join(base_dir, '..', 'static', 'brand_logos'))

        best_brand = None
        highest_similarity = 0.0

        for brand in ['google', 'paypal', 'microsoft', 'amazon', 'netflix']:
            template_path = os.path.join(brand_dir, f"{brand}.png")
            if not os.path.exists(template_path):
                continue

            tpl_img = cv2.imread(template_path)
            if tpl_img is None:
                continue

            # Compute combined similarity: HSV color correlation + structural dHash
            hist_sim = calculate_hist_similarity(img, tpl_img)
            tpl_hash = calculate_dhash(tpl_img)
            dist = hamming_distance(input_hash, tpl_hash)
            hash_sim = max(0.0, 1.0 - (dist / 64.0))

            combined_sim = round(0.55 * hist_sim + 0.45 * hash_sim, 3)
            result['brand_scores'][brand.title()] = combined_sim

            if combined_sim > highest_similarity:
                highest_similarity = combined_sim
                best_brand = brand

        result['similarity_score'] = highest_similarity
        result['matched_brand'] = best_brand.title() if best_brand else None

        # Check authorization of current domain
        clean_domain = (domain or '').lower().split(':')[0]
        if best_brand and highest_similarity >= 0.45:
            auth_domains = AUTHORIZED_DOMAINS.get(best_brand.lower(), [])
            is_authorized = any(clean_domain.endswith(ad) for ad in auth_domains)

            if not is_authorized and clean_domain:
                result['is_impersonation'] = True
                result['visual_risk_score'] = int(min(100, highest_similarity * 100 * 1.2))
                result['details'].append(
                    f"Visual match to '{best_brand.title()}' ({int(highest_similarity*100)}% match), "
                    f"but hosted on unauthorized domain '{clean_domain}'."
                )
            elif is_authorized:
                result['is_impersonation'] = False
                result['visual_risk_score'] = 0
                result['details'].append(
                    f"Visual match to '{best_brand.title()}' on legitimate domain '{clean_domain}'."
                )
            else:
                result['visual_risk_score'] = int(highest_similarity * 50)
                result['details'].append(f"Visual resemblance detected to '{best_brand.title()}'.")
        else:
            result['visual_risk_score'] = int(highest_similarity * 20)

        return result

    except Exception as e:
        result['details'].append(f"Visual processing exception: {str(e)}")
        return result
