"""
ML Model Training Script for Phishing URL Detection
Uses a synthetic dataset based on real phishing URL distributions.
Trains a Random Forest Classifier and saves it with joblib.
"""

import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.pipeline import Pipeline
import joblib

# Feature names matching feature_extractor.py
FEATURE_NAMES = [
    'url_length', 'domain_length', 'path_length', 'num_dots',
    'num_hyphens', 'num_underscores', 'num_slashes', 'num_digits',
    'num_subdomains', 'digit_letter_ratio', 'url_entropy', 'domain_entropy',
    'has_ip_address', 'has_https', 'has_at_symbol', 'has_double_slash_redirect',
    'has_dash_in_domain', 'has_equals', 'has_question_mark', 'has_ampersand',
    'has_tilde', 'has_percent_encoding', 'has_non_standard_port',
    'has_suspicious_tld', 'has_www', 'has_fragment',
    'suspicious_word_count', 'num_query_params', 'query_length',
    'num_path_tokens', 'max_path_token_length', 'special_char_ratio',
]

NUM_FEATURES = len(FEATURE_NAMES)
# Labels: 0 = safe, 1 = suspicious, 2 = phishing
LABEL_MAP = {0: 'Safe', 1: 'Suspicious', 2: 'Phishing'}


def generate_dataset(n_samples=15000, seed=42):
    """
    Generate a synthetic dataset based on statistical distributions
    observed in real phishing URL datasets (UCI/Kaggle).
    """
    np.random.seed(seed)

    samples_per_class = n_samples // 3
    remainder = n_samples - samples_per_class * 3

    data = []
    labels = []

    # --- Safe URLs (class 0) ---
    n_safe = samples_per_class + remainder
    for _ in range(n_safe):
        # ... (standard safe URL logic)
        url_length = int(np.random.normal(45, 15))
        domain_length = int(np.random.normal(15, 5))
        path_length = int(np.random.normal(15, 10))
        num_dots = np.random.choice([1, 2, 3], p=[0.3, 0.5, 0.2])
        num_hyphens = np.random.choice([0, 1], p=[0.8, 0.2])
        num_underscores = np.random.choice([0, 1], p=[0.9, 0.1])
        num_slashes = np.random.choice([2, 3, 4, 5], p=[0.3, 0.4, 0.2, 0.1])
        num_digits = int(np.random.exponential(1.5))
        num_subdomains = np.random.choice([0, 1, 2], p=[0.4, 0.5, 0.1])
        digit_letter_ratio = round(np.random.uniform(0, 0.15), 4)
        url_entropy = round(np.random.normal(3.5, 0.5), 4)
        domain_entropy = round(np.random.normal(2.8, 0.4), 4)
        has_ip_address = 0
        has_https = np.random.choice([0, 1], p=[0.15, 0.85])
        has_at_symbol = 0
        has_double_slash = 0
        has_dash_in_domain = np.random.choice([0, 1], p=[0.85, 0.15])
        has_equals = np.random.choice([0, 1], p=[0.7, 0.3])
        has_question_mark = np.random.choice([0, 1], p=[0.7, 0.3])
        has_ampersand = np.random.choice([0, 1], p=[0.8, 0.2])
        has_tilde = 0
        has_percent = np.random.choice([0, 1], p=[0.9, 0.1])
        has_non_standard_port = 0
        has_suspicious_tld = 0
        has_www = np.random.choice([0, 1], p=[0.4, 0.6])
        has_fragment = np.random.choice([0, 1], p=[0.85, 0.15])
        suspicious_word_count = np.random.choice([0, 1], p=[0.9, 0.1])
        num_query_params = np.random.choice([0, 1, 2], p=[0.6, 0.3, 0.1])
        query_length = int(np.random.exponential(5))
        num_path_tokens = np.random.choice([0, 1, 2, 3], p=[0.2, 0.4, 0.3, 0.1])
        max_path_token_len = int(np.random.normal(8, 3))
        special_char_ratio = round(np.random.uniform(0, 0.1), 4)

        row = [
            max(url_length, 10), max(domain_length, 3), max(path_length, 0),
            num_dots, num_hyphens, num_underscores, num_slashes,
            max(num_digits, 0), num_subdomains, max(digit_letter_ratio, 0),
            max(url_entropy, 0), max(domain_entropy, 0),
            has_ip_address, has_https, has_at_symbol, has_double_slash,
            has_dash_in_domain, has_equals, has_question_mark, has_ampersand,
            has_tilde, has_percent, has_non_standard_port,
            has_suspicious_tld, has_www, has_fragment,
            suspicious_word_count, num_query_params, max(query_length, 0),
            num_path_tokens, max(max_path_token_len, 0), max(special_char_ratio, 0),
        ]
        data.append(row)
        labels.append(0)

    # --- Suspicious/Phishing URLs (including Quishing profile) ---
    for class_label in [1, 2]:
        n_samples = samples_per_class
        for i in range(n_samples):
            # Special profile for 'Quishing' (QR Phishing) URLs - about 30% of malicious samples
            is_quishing = (i < n_samples * 0.3)
            
            if is_quishing:
                # Quishing URLs often use shorteners or redirects
                is_shortener = np.random.choice([True, False], p=[0.7, 0.3])
                url_length = int(np.random.normal(25, 10)) if is_shortener else int(np.random.normal(120, 40))
                domain_length = int(np.random.normal(10, 4)) if is_shortener else int(np.random.normal(35, 12))
                num_dots = np.random.choice([2, 3, 4], p=[0.4, 0.4, 0.2])
                num_slashes = np.random.choice([2, 3, 4, 5, 6], p=[0.1, 0.2, 0.3, 0.2, 0.2])
                has_at_symbol = np.random.choice([0, 1], p=[0.6, 0.4]) # High '@' usage in Quishing
                has_double_slash = np.random.choice([0, 1], p=[0.4, 0.6]) # High redirect usage
                has_ip_address = np.random.choice([0, 1], p=[0.5, 0.5]) # Often use IP instead of host
                url_entropy = round(np.random.normal(4.8, 0.5), 4) # Very high entropy
                suspicious_word_count = np.random.choice([1, 2, 3], p=[0.4, 0.4, 0.2])
            else:
                # Standard Malicious profile
                url_length = int(np.random.normal(80 + (class_label*10), 30))
                domain_length = int(np.random.normal(22 + (class_label*5), 10))
                num_dots = np.random.choice([3, 4, 5, 6], p=[0.2, 0.35, 0.3, 0.15])
                num_slashes = np.random.choice([4, 5, 6, 7], p=[0.2, 0.3, 0.3, 0.2])
                has_at_symbol = np.random.choice([0, 1], p=[0.8, 0.2])
                has_double_slash = np.random.choice([0, 1], p=[0.7, 0.3])
                has_ip_address = np.random.choice([0, 1], p=[0.8, 0.2])
                url_entropy = round(np.random.normal(4.2, 0.4), 4)
                suspicious_word_count = np.random.choice([0, 1, 2], p=[0.3, 0.4, 0.3])

            row = [
                max(url_length, 10), max(domain_length, 3), int(np.random.normal(30, 20)),
                num_dots, int(np.random.normal(2, 2)), int(np.random.normal(1, 1)), num_slashes,
                int(np.random.normal(6, 4)), int(np.random.normal(2, 1)), round(np.random.uniform(0.1, 0.4), 4),
                url_entropy, round(np.random.normal(3.5, 0.5), 4),
                has_ip_address, np.random.choice([0, 1], p=[0.6, 0.4]), has_at_symbol, has_double_slash,
                np.random.choice([0, 1], p=[0.5, 0.5]), 1, 1, 1,
                0, 1, 0, 1, 0, 0,
                suspicious_word_count, 1, 20,
                3, 15, round(np.random.uniform(0.1, 0.3), 4),
            ]
            data.append(row)
            labels.append(class_label)

    return np.array(data, dtype=float), np.array(labels)


def train_model():
    """Train Random Forest model and save it."""
    print("=" * 60)
    print("  Phishing URL Detection - Model Training")
    print("=" * 60)

    # Generate dataset
    print("\n[1/5] Generating training dataset...")
    X, y = generate_dataset(n_samples=15000)
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df['label'] = y
    print(f"  Dataset shape: {X.shape}")
    print(f"  Class distribution:")
    for label_id, label_name in LABEL_MAP.items():
        count = (y == label_id).sum()
        print(f"    {label_name} (class {label_id}): {count} samples")

    # Save dataset to CSV
    dataset_dir = os.path.join(os.path.dirname(__file__), '..', 'dataset')
    os.makedirs(dataset_dir, exist_ok=True)
    dataset_path = os.path.join(dataset_dir, 'phishing_dataset.csv')
    df.to_csv(dataset_path, index=False)
    print(f"\n  Dataset saved to: {dataset_path}")

    # Data cleaning
    print("\n[2/5] Cleaning data...")
    # Replace any NaN/Inf values
    X = np.nan_to_num(X, nan=0.0, posinf=100.0, neginf=0.0)
    print("  Removed NaN and Inf values")

    # Train/test split
    print("\n[3/5] Splitting data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Training set: {X_train.shape[0]} samples")
    print(f"  Test set:     {X_test.shape[0]} samples")

    # Build pipeline with scaler + classifier
    print("\n[4/5] Training Random Forest Classifier...")
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('classifier', RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        ))
    ])

    pipeline.fit(X_train, y_train)
    print("  Training complete!")

    # Cross-validation
    print("\n  Performing 5-fold cross-validation...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring='accuracy')
    print(f"  CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Evaluation
    print("\n[5/5] Evaluating model...")
    y_pred = pipeline.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')

    print(f"\n  Test Accuracy:  {accuracy:.4f}")
    print(f"  Precision:      {precision:.4f}")
    print(f"  Recall:         {recall:.4f}")
    print(f"  F1 Score:       {f1:.4f}")

    print(f"\n  Classification Report:")
    target_names = [LABEL_MAP[i] for i in sorted(LABEL_MAP.keys())]
    print(classification_report(y_test, y_pred, target_names=target_names))

    print(f"  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  {cm}")

    # Save model
    model_dir = os.path.join(os.path.dirname(__file__), 'model')
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, 'phishing_model.joblib')
    joblib.dump(pipeline, model_path)
    print(f"\n  Model saved to: {model_path}")

    # Save feature importance
    rf = pipeline.named_steps['classifier']
    importances = rf.feature_importances_
    importance_df = pd.DataFrame({
        'feature': FEATURE_NAMES,
        'importance': importances
    }).sort_values('importance', ascending=False)

    print("\n  Top 10 Feature Importances:")
    for _, row in importance_df.head(10).iterrows():
        bar = '█' * int(row['importance'] * 50)
        print(f"    {row['feature']:30s} {row['importance']:.4f} {bar}")

    print("\n" + "=" * 60)
    print("  Training Complete! Model is ready for deployment.")
    print("=" * 60)

    return pipeline


if __name__ == '__main__':
    train_model()
