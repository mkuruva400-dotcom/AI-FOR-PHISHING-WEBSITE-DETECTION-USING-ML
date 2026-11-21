import unittest
from core.url_extractor import extract_url_features, features_to_vector, FEATURE_NAMES

class TestURLExtractor(unittest.TestCase):
    def test_feature_count(self):
        f = extract_url_features("https://www.google.com")
        self.assertEqual(len(f), len(FEATURE_NAMES))
        self.assertEqual(len(FEATURE_NAMES), 24)

    def test_benign_url(self):
        url = "https://www.wikipedia.org/wiki/Computer_security"
        f = extract_url_features(url)
        self.assertEqual(f['is_ip'], 0)
        self.assertEqual(f['has_https'], 1)
        self.assertEqual(f['tld_risk'], 0)
        self.assertEqual(f['is_shortened'], 0)

    def test_phishing_indicators(self):
        url = "http://192.168.1.1:8080/secure-paypal-login.tk/update.php?user=1"
        f = extract_url_features(url)
        self.assertEqual(f['is_ip'], 1)
        self.assertEqual(f['has_https'], 0)
        self.assertEqual(f['has_suspicious_keyword'], 1)
        self.assertGreaterEqual(f['count_hyphens'], 2)

    def test_vector_conversion(self):
        f = extract_url_features("https://github.com")
        vec = features_to_vector(f)
        self.assertEqual(len(vec), 24)
        self.assertTrue(all(isinstance(v, (int, float)) for v in vec))

if __name__ == '__main__':
    unittest.main()
