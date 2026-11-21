import os
import joblib
import numpy as np
import shap

FEATURE_DESCRIPTIONS = {
    'url_length': "Overall character length of the URL",
    'domain_length': "Length of the target domain/host name",
    'is_ip': "Domain uses raw IP address instead of registered domain name",
    'count_dots': "Excessive dots indicating deep subdomain layering",
    'count_hyphens': "Excessive hyphens frequently used to mimic legitimate brand names",
    'count_at': "Presence of '@' symbol which masks the true target host in URLs",
    'count_question': "Query parameter initiator",
    'count_and': "Multiple chained parameters in query string",
    'count_equal': "Number of key-value parameter pairs",
    'count_slash': "Path directory structure depth",
    'count_percent': "URL hex encoding used to obfuscate payload",
    'count_digits': "Number of numeric digits (entropy & randomness)",
    'count_subdomains': "Number of subdomain levels preceding root domain",
    'has_https': "Whether connection uses encrypted HTTPS protocol",
    'https_in_domain': "Deceptive use of 'https' keyword inside hostname",
    'is_shortened': "Use of URL shortening redirection service",
    'has_suspicious_keyword': "Contains credential harvesting keywords (login, verify, update)",
    'path_depth': "Subdirectory hierarchy depth",
    'prefix_suffix_hyphen': "Hyphen separating brand prefixes or suffixes in domain",
    'entropy': "Shannon entropy measuring randomness and DGA patterns in URL",
    'domain_entropy': "Shannon entropy of the domain name",
    'tld_risk': "Registration on high-abuse top-level domains (.tk, .xyz, .top)",
    'punycode': "Punycode (xn--) or non-ASCII homograph characters",
    'special_char_ratio': "Proportion of special punctuation characters to total length"
}

class ShapExplainerManager:
    _instance = None

    def __init__(self, model_path: str = None):
        if model_path is None:
            base_dir = os.path.dirname(__file__)
            model_path = os.path.abspath(os.path.join(base_dir, '..', 'ml_engine', 'saved_models', 'random_forest.pkl'))

        self.model = joblib.load(model_path)
        # Initialize TreeExplainer
        self.explainer = shap.TreeExplainer(self.model)

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ShapExplainerManager()
        return cls._instance

    def explain_url_features(self, feature_vector: list, feature_names: list) -> dict:
        """
        Computes exact SHAP values for an input URL feature vector.
        Returns top features influencing the prediction towards Phishing (+) or Benign (-).
        """
        X_sample = np.array(feature_vector).reshape(1, -1)
        raw_shap = self.explainer.shap_values(X_sample)

        # Handle different SHAP output formats across versions
        if isinstance(raw_shap, list):
            # Class 1 (Phishing) SHAP values
            values = raw_shap[1][0] if len(raw_shap) > 1 else raw_shap[0][0]
        elif len(raw_shap.shape) == 3:
            values = raw_shap[0, :, 1]
        else:
            values = raw_shap[0]

        # Extract expected value (base value)
        expected_val = self.explainer.expected_value
        if isinstance(expected_val, (list, np.ndarray)):
            base_val = float(expected_val[1]) if len(expected_val) > 1 else float(expected_val[0])
        else:
            base_val = float(expected_val)

        # Build feature impact records
        impacts = []
        for name, val, sv in zip(feature_names, feature_vector, values):
            impacts.append({
                'feature': name,
                'value': val,
                'shap_value': round(float(sv), 4),
                'impact': 'Phishing' if sv > 0 else 'Legitimate',
                'description': FEATURE_DESCRIPTIONS.get(name, "Structural URL characteristic")
            })

        # Sort by absolute SHAP impact
        sorted_impacts = sorted(impacts, key=lambda x: abs(x['shap_value']), reverse=True)

        top_phishing = [x for x in sorted_impacts if x['shap_value'] > 0][:5]
        top_safe = [x for x in sorted_impacts if x['shap_value'] < 0][:5]

        # Prepare Chart.js formatted data (Top 8 features by magnitude)
        chart_features = sorted_impacts[:8]
        chart_data = {
            'labels': [x['feature'].replace('_', ' ').title() for x in chart_features],
            'values': [x['shap_value'] for x in chart_features],
            'colors': ['rgba(239, 68, 68, 0.85)' if x['shap_value'] > 0 else 'rgba(34, 197, 94, 0.85)' for x in chart_features]
        }

        return {
            'base_value': round(base_val, 4),
            'top_phishing_factors': top_phishing,
            'top_safe_factors': top_safe,
            'all_impacts': sorted_impacts,
            'chart_data': chart_data
        }

def explain_features(feature_vector: list, feature_names: list) -> dict:
    """Convenience function to compute SHAP explanations."""
    manager = ShapExplainerManager.get_instance()
    return manager.explain_url_features(feature_vector, feature_names)
