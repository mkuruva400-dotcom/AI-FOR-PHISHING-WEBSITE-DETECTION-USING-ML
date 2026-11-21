import unittest
from core.risk_scorer import compute_composite_risk, calculate_url_heuristic_risk

class TestRiskScorer(unittest.TestCase):
    def test_safe_score(self):
        url_features = {
            'is_ip': 0, 'tld_risk': 0, 'is_shortened': 0, 'has_https': 1,
            'https_in_domain': 0, 'has_suspicious_keyword': 0, 'punycode': 0,
            'count_subdomains': 1, 'prefix_suffix_hyphen': 0, 'count_at': 0, 'entropy': 3.1
        }
        res = compute_composite_risk(ml_probability=0.02, url_features=url_features)
        self.assertLess(res['risk_score'], 30.0)
        self.assertIn(res['verdict'], ['LEGITIMATE', 'SAFE'])
        self.assertEqual(res['badge_class'], 'success')

    def test_phishing_score(self):
        url_features = {
            'is_ip': 1, 'tld_risk': 1, 'is_shortened': 1, 'has_https': 0,
            'https_in_domain': 1, 'has_suspicious_keyword': 1, 'punycode': 0,
            'count_subdomains': 4, 'prefix_suffix_hyphen': 1, 'count_at': 1, 'entropy': 5.2
        }
        res = compute_composite_risk(ml_probability=0.98, url_features=url_features)
        self.assertGreaterEqual(res['risk_score'], 70.0)
        self.assertEqual(res['verdict'], 'PHISHING')
        self.assertEqual(res['badge_class'], 'danger')
        self.assertGreater(len(res['warnings']), 3)
        self.assertGreater(len(res['prevention_tips']), 3)

    def test_bounds(self):
        url_features = {'is_ip': 0}
        res_zero = compute_composite_risk(ml_probability=0.0, url_features=url_features)
        self.assertGreaterEqual(res_zero['risk_score'], 0.0)

        res_max = compute_composite_risk(ml_probability=1.0, url_features=url_features)
        self.assertLessEqual(res_max['risk_score'], 100.0)

if __name__ == '__main__':
    unittest.main()
