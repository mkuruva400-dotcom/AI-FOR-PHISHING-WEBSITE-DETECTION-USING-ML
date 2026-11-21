import os
import joblib
import json
import numpy as np

# Suppress verbose TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import keras

from core.url_extractor import extract_url_features, features_to_vector, FEATURE_NAMES
from core.explainable_ai import explain_features

MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'saved_models'))

class ModelManager:
    _instance = None

    def __init__(self, models_dir: str = MODELS_DIR):
        self.models_dir = models_dir
        self.scaler = None
        self.models = {}
        self.best_model_name = "Random Forest"
        self.metrics = {}
        self.load_artifacts()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = ModelManager()
        return cls._instance

    def load_artifacts(self):
        """Loads all saved model binaries, scalers, and benchmark metrics."""
        # 1. Feature Scaler
        scaler_path = os.path.join(self.models_dir, 'scaler.pkl')
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)

        # 2. Benchmark Metrics JSON
        metrics_path = os.path.join(self.models_dir, 'model_metrics.json')
        if os.path.exists(metrics_path):
            with open(metrics_path, 'r') as f:
                self.metrics = json.load(f)
                self.best_model_name = self.metrics.get('best_model', 'Random Forest')

        # 3. Traditional ML models
        model_files = {
            'Random Forest': 'random_forest.pkl',
            'Decision Tree': 'decision_tree.pkl',
            'SVM': 'svm.pkl',
            'Logistic Regression': 'logistic_regression.pkl',
            'XGBoost': 'xgboost_model.pkl'
        }
        for name, filename in model_files.items():
            path = os.path.join(self.models_dir, filename)
            if os.path.exists(path):
                try:
                    self.models[name] = joblib.load(path)
                except Exception as e:
                    print(f"Warning: Failed to load {name} from {path}: {e}")

        # 4. Keras Deep Learning Artificial Neural Network
        ann_path = os.path.join(self.models_dir, 'ann_model.keras')
        if os.path.exists(ann_path):
            try:
                self.models['Artificial Neural Network'] = keras.models.load_model(ann_path)
            except Exception as e:
                print(f"Warning: Failed to load Keras ANN from {ann_path}: {e}")

    def predict(self, url: str, model_choice: str = "Ensemble") -> dict:
        """
        Extracts features from URL and computes phishing probability
        using the selected model or ensemble of models.
        """
        features_dict = extract_url_features(url)
        vector = features_to_vector(features_dict)
        import pandas as pd
        X_df = pd.DataFrame([features_dict])[FEATURE_NAMES]
        X_raw = X_df.values

        X_scaled = self.scaler.transform(X_df) if self.scaler else X_raw

        chosen_model_name = model_choice
        if model_choice in ["Best", "Default"]:
            chosen_model_name = self.best_model_name

        phishing_prob = 0.5
        model_scores = {}

        # Evaluate individual models
        for name, model in self.models.items():
            try:
                if name in ['SVM', 'Logistic Regression']:
                    prob = float(model.predict_proba(X_scaled)[0, 1])
                elif name == 'Artificial Neural Network':
                    prob = float(model.predict(X_scaled, verbose=0)[0, 0])
                else: # Random Forest, Decision Tree, XGBoost
                    prob = float(model.predict_proba(X_df)[0, 1])
                model_scores[name] = round(prob, 4)
            except Exception as e:
                model_scores[name] = 0.5

        # Determine primary prediction probability
        if chosen_model_name == "Ensemble":
            # Weighted ensemble: higher weights to top performers (RF, XGBoost, ANN)
            weights = {
                'Random Forest': 0.30,
                'XGBoost': 0.25,
                'Artificial Neural Network': 0.20,
                'SVM': 0.15,
                'Logistic Regression': 0.05,
                'Decision Tree': 0.05
            }
            weighted_sum = sum(model_scores.get(m, 0.5) * w for m, w in weights.items() if m in model_scores)
            total_weight = sum(w for m, w in weights.items() if m in model_scores)
            phishing_prob = round(weighted_sum / max(1e-5, total_weight), 4)
        elif chosen_model_name in model_scores:
            phishing_prob = model_scores[chosen_model_name]
        else:
            phishing_prob = model_scores.get('Random Forest', 0.5)

        # Explainability via SHAP (using Random Forest / Tree explainer)
        shap_explanation = explain_features(vector, FEATURE_NAMES)

        return {
            'url': url,
            'features': features_dict,
            'vector': vector,
            'model_used': chosen_model_name,
            'phishing_probability': phishing_prob,
            'all_model_probabilities': model_scores,
            'shap_explanation': shap_explanation
        }

def get_model_manager():
    return ModelManager.get_instance()
