import os
import unittest
from core.qr_detector import generate_qr_image, decode_qr_code

class TestQRDetector(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(os.path.dirname(__file__), 'temp')
        os.makedirs(self.test_dir, exist_ok=True)
        self.sample_url = "https://secure-login-account-update.xyz/login.php"
        self.qr_path = os.path.join(self.test_dir, "test_quish.png")
        generate_qr_image(self.sample_url, self.qr_path)

    def tearDown(self):
        if os.path.exists(self.qr_path):
            try:
                os.remove(self.qr_path)
            except Exception:
                pass

    def test_qr_decode(self):
        res = decode_qr_code(image_path=self.qr_path)
        self.assertTrue(res['success'])
        self.assertTrue(res['is_url'])
        self.assertEqual(res['url'], self.sample_url)
        self.assertEqual(res['domain'], "secure-login-account-update.xyz")

if __name__ == '__main__':
    unittest.main()
