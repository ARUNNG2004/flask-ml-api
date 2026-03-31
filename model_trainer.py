import os
import json
import joblib
import pandas as pd
import numpy as np
from datetime import datetime, timezone
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.impute import SimpleImputer
from imblearn.over_sampling import SMOTE

EXPECTED_COLUMNS = [
    "url_len", "@", "?", "-", "=", ".", "#", "%", "+", "$", "!", "*", ",", "//", "abnormal_url", "https", "digits", "letters",
    "Shortining_Service", "having_ip_address", "web_ext_ratio", "web_unique_domains", "web_favicon",
    "web_csp", "web_xframe", "web_hsts", "web_xcontent", "web_security_score", "web_forms_count",
    "web_password_fields", "web_hidden_inputs", "web_has_login", "web_ssl_valid",
    "phish_urgency_words", "phish_security_words", "phish_brand_mentions", "phish_brand_hijack",
    "phish_multiple_subdomains", "phish_long_path", "phish_many_params", "phish_suspicious_tld",
    "domain_ngram_entropy", "path_depth", "path_entropy", "subdomain_count", "avg_subdomain_len",
    "consonant_ratio", "vowel_ratio", "digit_ratio", "avg_token_length", "token_count", "label"
]

def train_models():
    dataset_path = os.environ.get("DATASET_PATH", "dataset.csv")
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"Dataset completely missing at {dataset_path}")

    # Read CSV
    df = pd.read_csv(dataset_path)

    # Deduplicate column names (BUG 1 fix)
    df = df.loc[:, ~df.columns.duplicated()]

    # Ensure all expected columns are present, dropping unexpected ones
    for col in EXPECTED_COLUMNS:
        if col not in df.columns:
            df[col] = np.nan
    df = df[EXPECTED_COLUMNS]

    # Handle missing values with median imputation
    imputer = SimpleImputer(strategy='median')
    imputed_data = imputer.fit_transform(df)
    df = pd.DataFrame(imputed_data, columns=df.columns)

    # Print class distribution
    print("\n=== CLASS DISTRIBUTION ===")
    print(df['label'].value_counts())
    print(f"Total samples: {len(df)}")

    # Separate features and label
    X = df.drop(columns=['label'])
    y = df['label']

    # Ensure label is integer (0 = safe, 1 = malicious)
    y = y.astype(int)

    # Save class distribution info
    class_dist = y.value_counts().to_dict()
    safe_count = int(class_dist.get(0, 0))
    malicious_count = int(class_dist.get(1, 0))

    # 80/20 train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Apply SMOTE to balance classes
    print("\n=== APPLYING SMOTE ===")
    print(f"Before SMOTE - Train set: {y_train.value_counts().to_dict()}")
    smote = SMOTE(random_state=42)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    print(f"After SMOTE  - Train set: {pd.Series(y_train_resampled).value_counts().to_dict()}")

    # Decision Tree with class_weight='balanced'
    dt_model = DecisionTreeClassifier(
        class_weight='balanced',
        max_depth=20,
        min_samples_leaf=2,
        random_state=42
    )
    dt_model.fit(X_train_resampled, y_train_resampled)
    dt_preds = dt_model.predict(X_test)
    dt_acc = accuracy_score(y_test, dt_preds)
    dt_report = classification_report(y_test, dt_preds, output_dict=True)

    print("\n=== Decision Tree Results ===")
    print(f"Accuracy: {dt_acc}")
    print(classification_report(y_test, dt_preds))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, dt_preds))

    # Random Forest with class_weight='balanced_subsample'
    rf_model = RandomForestClassifier(
        n_estimators=200,
        class_weight='balanced_subsample',
        max_depth=20,
        min_samples_leaf=2,
        random_state=42
    )
    rf_model.fit(X_train_resampled, y_train_resampled)
    rf_preds = rf_model.predict(X_test)
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_report = classification_report(y_test, rf_preds, output_dict=True)

    print("\n=== Random Forest Results ===")
    print(f"Accuracy: {rf_acc}")
    print(classification_report(y_test, rf_preds))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, rf_preds))

    # Verify malicious class detection
    dt_f1_mal = dt_report.get('1', dt_report.get('1.0', {})).get('f1-score', 0.0)
    rf_f1_mal = rf_report.get('1', rf_report.get('1.0', {})).get('f1-score', 0.0)

    if rf_f1_mal < 0.01:
        print("\nWARNING: RF malicious F1 is near zero! Model may still be biased.")
    if dt_f1_mal < 0.01:
        print("\nWARNING: DT malicious F1 is near zero! Model may still be biased.")

    # Save both models
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    os.makedirs(models_dir, exist_ok=True)

    joblib.dump(dt_model, os.path.join(models_dir, 'decision_tree.pkl'))
    joblib.dump(rf_model, os.path.join(models_dir, 'random_forest.pkl'))

    # Save feature column list (guaranteed no duplicates)
    feature_columns = X.columns.tolist()
    # Extra safety: deduplicate feature_columns list
    seen = set()
    unique_columns = []
    for c in feature_columns:
        if c not in seen:
            seen.add(c)
            unique_columns.append(c)
    feature_columns = unique_columns

    with open(os.path.join(models_dir, 'feature_columns.json'), 'w') as f:
        json.dump(feature_columns, f, indent=4)

    # Save training metrics
    training_metrics = {
        "dt_accuracy": float(dt_acc),
        "rf_accuracy": float(rf_acc),
        "dt_f1_malicious": float(dt_f1_mal),
        "rf_f1_malicious": float(rf_f1_mal),
        "class_distribution": {"safe": safe_count, "malicious": malicious_count},
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples_used": int(len(df)),
        "features_used": int(len(feature_columns))
    }

    with open(os.path.join(models_dir, 'training_metrics.json'), 'w') as f:
        json.dump(training_metrics, f, indent=4)

    print(f"\n=== Training Metrics Saved ===")
    print(json.dumps(training_metrics, indent=2))

    return {
        "decision_tree": {
            "accuracy": dt_acc,
            "report": dt_report
        },
        "random_forest": {
            "accuracy": rf_acc,
            "report": rf_report
        },
        "training_metrics": training_metrics
    }

if __name__ == "__main__":
    train_models()
