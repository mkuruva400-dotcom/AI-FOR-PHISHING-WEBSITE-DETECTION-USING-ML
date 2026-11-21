import os
import cv2
import numpy as np
from PIL import Image
import qrcode
from urllib.parse import urlparse

def decode_qr_code(image_path: str = None, image_bytes: bytes = None) -> dict:
    """
    Decodes QR Code image to extract embedded URL/payload using OpenCV.
    Returns payload details, decoded status, and Quishing indicators.
    """
    result = {
        'success': False,
        'decoded_text': None,
        'is_url': False,
        'url': None,
        'scheme': None,
        'domain': None,
        'quishing_indicators': [],
        'error': None
    }

    try:
        img = None
        if image_path and os.path.exists(image_path):
            img = cv2.imread(image_path)
        elif image_bytes:
            nparr = np.frombuffer(image_bytes, np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            result['error'] = "Unable to read or parse image file."
            return result

        # Initialize OpenCV QR Code Detector
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)

        # Fallback multi-detector if single didn't catch it
        if not data:
            success, decoded_info, _, _ = detector.detectAndDecodeMulti(img)
            if success and len(decoded_info) > 0:
                data = decoded_info[0]

        # Second fallback: grayscale + Otsu thresholding for low-contrast QR codes
        if not data:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)
            data, _, _ = detector.detectAndDecode(thresh)

        if not data:
            result['error'] = "No valid QR code detected in the uploaded image."
            return result

        result['success'] = True
        result['decoded_text'] = data.strip()

        # Check if the decoded payload is a URL
        parsed = urlparse(result['decoded_text'])
        if parsed.scheme in ['http', 'https'] and parsed.netloc:
            result['is_url'] = True
            result['url'] = result['decoded_text']
            result['scheme'] = parsed.scheme
            result['domain'] = parsed.netloc

            # Check Quishing indicators
            if parsed.scheme == 'http':
                result['quishing_indicators'].append("Insecure HTTP protocol embedded in physical/digital QR code.")
            
            # Check for URL shorteners in QR code
            shorteners = {'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy'}
            if any(s in parsed.netloc.lower() for s in shorteners):
                result['quishing_indicators'].append("QR code masks destination using a URL shortener service (High Quishing Risk).")

            # Check for direct IP in QR code
            if any(c.isdigit() for c in parsed.netloc.split('.')) and len(parsed.netloc.split('.')) == 4:
                result['quishing_indicators'].append("QR code directly targets raw IP address instead of registered domain.")

        elif result['decoded_text'].startswith('www.'):
            result['is_url'] = True
            result['url'] = 'https://' + result['decoded_text']
            result['scheme'] = 'https'
            result['domain'] = result['decoded_text'].split('/')[0]
        else:
            result['quishing_indicators'].append("Payload is non-web text or command string.")

        return result

    except Exception as e:
        result['error'] = f"Decoding exception: {str(e)}"
        return result


def generate_qr_image(url: str, output_path: str) -> str:
    """Generates a QR code image file for a given URL (useful for demonstration and tests)."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)
    return output_path
