import os
import sys
import time
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve
)
from xgboost import XGBClassifier

# Suppress TensorFlow verbose logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import keras
from keras import layers

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.url_extractor import FEATURE_NAMES

def train_all_models(dataset_path: str = None, output_dir: str = None):
    """
    Trains and benchmarks 6 distinct AI models on the authentic URL dataset:
    1. Random Forest (RF)
    2. Decision Tree (DT)
    3. Support Vector Machine (SVM)
    4. Logistic Regression (LR)
    5. Extreme Gradient Boosting (XGBoost)
    6. Artificial Neural Network (ANN - Deep Learning)
    """
    if dataset_path is None:
        dataset_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'phishing_dataset.csv')
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(__file__), 'saved_models')

    os.makedirs(output_dir, exist_ok=True)
    plots_dir = os.path.join(output_dir, 'plots')
    os.makedirs(plots_dir, exist_ok=True)

    print(f"Loading dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)

    X = df[FEATURE_NAMES]
    y = df['label']

    print(f"Dataset Shape: {X.shape} | Benign: {(y==0).sum()} | Phishing: {(y==1).sum()}")

    # Stratified Train-Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Standardize features for SVM, LR, and ANN
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Save feature scaler
    scaler_path = os.path.join(output_dir, 'scaler.pkl')
    joblib.dump(scaler, scaler_path)
    print(f"Saved feature scaler to: {scaler_path}")

    results = {}
    roc_data = {}
    trained_models = {}

    # 1. Random Forest Classifier
    print("\n[1/6] Training Random Forest Classifier...")
    t0 = time.time()
    rf = RandomForestClassifier(n_estimators=150, max_depth=16, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_time = round(time.time() - t0, 3)
    y_pred_rf = rf.predict(X_test)
    y_prob_rf = rf.predict_proba(X_test)[:, 1]
    results['Random Forest'] = evaluate_model(y_test, y_pred_rf, y_prob_rf, rf_time)
    roc_data['Random Forest'] = roc_curve(y_test, y_prob_rf)
    trained_models['Random Forest'] = rf
    joblib.dump(rf, os.path.join(output_dir, 'random_forest.pkl'))

    # 2. Decision Tree Classifier
    print("[2/6] Training Decision Tree Classifier...")
    t0 = time.time()
    dt = DecisionTreeClassifier(max_depth=12, random_state=42)
    dt.fit(X_train, y_train)
    dt_time = round(time.time() - t0, 3)
    y_pred_dt = dt.predict(X_test)
    y_prob_dt = dt.predict_proba(X_test)[:, 1]
    results['Decision Tree'] = evaluate_model(y_test, y_pred_dt, y_prob_dt, dt_time)
    roc_data['Decision Tree'] = roc_curve(y_test, y_prob_dt)
    trained_models['Decision Tree'] = dt
    joblib.dump(dt, os.path.join(output_dir, 'decision_tree.pkl'))

    # 3. Support Vector Machine (RBF Kernel)
    print("[3/6] Training Support Vector Machine (SVM)...")
    t0 = time.time()
    svm = SVC(kernel='rbf', C=2.0, probability=True, random_state=42)
    svm.fit(X_train_scaled, y_train)
    svm_time = round(time.time() - t0, 3)
    y_pred_svm = svm.predict(X_test_scaled)
    y_prob_svm = svm.predict_proba(X_test_scaled)[:, 1]
    results['SVM'] = evaluate_model(y_test, y_pred_svm, y_prob_svm, svm_time)
    roc_data['SVM'] = roc_curve(y_test, y_prob_svm)
    trained_models['SVM'] = svm
    joblib.dump(svm, os.path.join(output_dir, 'svm.pkl'))

    # 4. Logistic Regression
    print("[4/6] Training Logistic Regression...")
    t0 = time.time()
    lr = LogisticRegression(max_iter=1000, C=1.5, random_state=42)
    lr.fit(X_train_scaled, y_train)
    lr_time = round(time.time() - t0, 3)
    y_pred_lr = lr.predict(X_test_scaled)
    y_prob_lr = lr.predict_proba(X_test_scaled)[:, 1]
    results['Logistic Regression'] = evaluate_model(y_test, y_pred_lr, y_prob_lr, lr_time)
    roc_data['Logistic Regression'] = roc_curve(y_test, y_prob_lr)
    trained_models['Logistic Regression'] = lr
    joblib.dump(lr, os.path.join(output_dir, 'logistic_regression.pkl'))

    # 5. XGBoost Classifier
    print("[5/6] Training XGBoost Classifier...")
    t0 = time.time()
    xgb = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        eval_metric='logloss',
        random_state=42
    )
    xgb.fit(X_train, y_train)
    xgb_time = round(time.time() - t0, 3)
    y_pred_xgb = xgb.predict(X_test)
    y_prob_xgb = xgb.predict_proba(X_test)[:, 1]
    results['XGBoost'] = evaluate_model(y_test, y_pred_xgb, y_prob_xgb, xgb_time)
    roc_data['XGBoost'] = roc_curve(y_test, y_prob_xgb)
    trained_models['XGBoost'] = xgb
    joblib.dump(xgb, os.path.join(output_dir, 'xgboost_model.pkl'))

    # 6. Deep Learning - Artificial Neural Network (ANN) using Keras
    print("[6/6] Training Artificial Neural Network (ANN)...")
    t0 = time.time()
    ann = keras.Sequential([
        layers.Input(shape=(len(FEATURE_NAMES),)),
        layers.Dense(64, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.25),
        layers.Dense(32, activation='relu'),
        layers.BatchNormalization(),
        layers.Dropout(0.20),
        layers.Dense(16, activation='relu'),
        layers.Dense(1, activation='sigmoid')
    ])
    ann.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.002),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    history = ann.fit(
        X_train_scaled, y_train,
        epochs=35,
        batch_size=32,
        validation_split=0.15,
        verbose=0
    )
    ann_time = round(time.time() - t0, 3)
    y_prob_ann = ann.predict(X_test_scaled, verbose=0).flatten()
    y_pred_ann = (y_prob_ann >= 0.5).astype(int)
    results['Artificial Neural Network'] = evaluate_model(y_test, y_pred_ann, y_prob_ann, ann_time)
    roc_data['Artificial Neural Network'] = roc_curve(y_test, y_prob_ann)
    ann.save(os.path.join(output_dir, 'ann_model.keras'))

    # Determine Best Model by F1-Score
    best_name = max(results.keys(), key=lambda k: results[k]['f1_score'])
    print(f"\n==========================================")
    print(f"BEST MODEL IDENTIFIED: {best_name} (F1-Score: {results[best_name]['f1_score']})")
    print(f"==========================================")

    # Save best model copy
    if best_name == 'Artificial Neural Network':
        joblib.dump({'type': 'keras', 'path': 'ann_model.keras'}, os.path.join(output_dir, 'best_model.pkl'))
    else:
        joblib.dump(trained_models[best_name], os.path.join(output_dir, 'best_model.pkl'))

    # Save metrics JSON
    metrics_path = os.path.join(output_dir, 'model_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump({
            'best_model': best_name,
            'models': results,
            'features': FEATURE_NAMES,
            'sample_count': len(df),
            'train_samples': len(X_train),
            'test_samples': len(X_test)
        }, f, indent=4)
    print(f"Saved benchmark metrics to: {metrics_path}")

    # Generate Performance Visualization Plots
    generate_comparison_plots(results, roc_data, rf, plots_dir)
    print(f"Saved benchmark visualization plots to: {plots_dir}")

    # Print summary table
    print("\n--- MODEL PERFORMANCE COMPARISON BENCHMARK ---")
    headers = f"{'Model':<28} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8} | {'ROC-AUC':<8} | {'Time (s)':<8}"
    print(headers)
    print("-" * len(headers))
    for m, met in results.items():
        print(f"{m:<28} | {met['accuracy']:<9.4f} | {met['precision']:<9.4f} | {met['recall']:<8.4f} | {met['f1_score']:<8.4f} | {met['roc_auc']:<8.4f} | {met['training_time']:<8.3f}")

    return results

def evaluate_model(y_true, y_pred, y_prob, train_time):
    """Calculates all authentic classification evaluation metrics and confusion matrix."""
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_prob)
    cm = confusion_matrix(y_true, y_pred).tolist()

    return {
        'accuracy': round(float(acc), 4),
        'precision': round(float(prec), 4),
        'recall': round(float(rec), 4),
        'f1_score': round(float(f1), 4),
        'roc_auc': round(float(auc), 4),
        'training_time': train_time,
        'confusion_matrix': cm  # [[TN, FP], [FN, TP]]
    }

def generate_comparison_plots(results, roc_data, rf_model, output_dir):
    """Generates publication-quality charts for documentation, report, and dashboard."""
    # 1. Grouped Bar Chart: Comparison across 4 key metrics
    models = list(results.keys())
    metrics = ['accuracy', 'precision', 'recall', 'f1_score']
    
    x = np.arange(len(models))
    width = 0.20

    plt.figure(figsize=(13, 6))
    for i, m in enumerate(metrics):
        values = [results[mod][m] for mod in models]
        plt.bar(x + (i - 1.5) * width, values, width, label=m.replace('_', ' ').title())

    plt.title('AI Phishing Detection: Multi-Model Benchmark Comparison', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Algorithms', fontsize=12)
    plt.ylabel('Score (0.0 - 1.0)', fontsize=12)
    plt.xticks(x, models, rotation=15, ha='right', fontsize=10)
    plt.ylim(0.70, 1.02)
    plt.grid(axis='y', linestyle='--', alpha=0.5)
    plt.legend(loc='lower right', frameon=True)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'model_comparison_bar.png'), dpi=200)
    plt.close()

    # 2. Combined ROC Curves
    plt.figure(figsize=(8, 6))
    for mod in models:
        fpr, tpr, _ = roc_data[mod]
        auc = results[mod]['roc_auc']
        plt.plot(fpr, tpr, label=f"{mod} (AUC = {auc:.4f})", linewidth=2)

    plt.plot([0, 1], [0, 1], 'k--', alpha=0.6, label='Random Chance')
    plt.title('Receiver Operating Characteristic (ROC) Curves', fontsize=13, fontweight='bold')
    plt.xlabel('False Positive Rate (1 - Specificity)', fontsize=11)
    plt.ylabel('True Positive Rate (Sensitivity)', fontsize=11)
    plt.legend(loc='lower right', fontsize=9)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'roc_curves.png'), dpi=200)
    plt.close()

    # 3. Top Feature Importance (from Random Forest)
    importances = rf_model.feature_importances_
    indices = np.argsort(importances)[::-1][:12]
    top_features = [FEATURE_NAMES[i] for i in indices]
    top_importances = importances[indices]

    plt.figure(figsize=(9, 6))
    sns.barplot(x=top_importances, y=top_features, palette='mako')
    plt.title('Top 12 Most Influential Features (Random Forest Importance)', fontsize=13, fontweight='bold')
    plt.xlabel('Relative Importance Score', fontsize=11)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'feature_importance.png'), dpi=200)
    plt.close()

if __name__ == '__main__':
    train_all_models()
