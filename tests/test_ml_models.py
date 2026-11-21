import unittest
from ml_engine.model_manager import get_model_manager

class TestMLModels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mm = get_model_manager()

    def test_models_loaded(self):
        models = self.mm.models
        expected = ['Random Forest', 'Decision Tree', 'SVM', 'Logistic Regression', 'XGBoost', 'Artificial Neural Network']
        for exp in expected:
            self.assertIn(exp, models, f"Model {exp} should be loaded in model manager")

    def test_benign_prediction(self):
        url = "https://www.google.com/search?q=machine+learning"
        res = self.mm.predict(url, model_choice="Ensemble")
        self.assertLess(res['phishing_probability'], 0.40)
        self.assertIn('shap_explanation', res)

    def test_phishing_prediction(self):
        url = "http://192.168.1.1/paypal/login-account-update.php?token=xyz"
        res = self.mm.predict(url, model_choice="Ensemble")
        self.assertGreater(res['phishing_probability'], 0.60)
        self.assertIn('shap_explanation', res)

    def test_ann_model_prediction(self):
        url = "http://appleid.apple.com.verify-billing-info.cf/auth/login"
        res = self.mm.predict(url, model_choice="Artificial Neural Network")
        self.assertGreater(res['phishing_probability'], 0.60)
        self.assertEqual(res['model_used'], "Artificial Neural Network")

if __name__ == '__main__':
    unittest.main()
