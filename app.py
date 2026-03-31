import os
import json
import joblib
import numpy as np
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback
import threading

from feature_extractor import extract_features, extract_features_fast
from database import init_db, save_scan, get_history, delete_scan, clear_history
import chatbot

app = Flask(__name__)

CORS(app, resources={r"/api/*": {
    "origins": "*",
    "methods": ["GET", "POST", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type"]
}})

# -------------------------------
# PATHS
# -------------------------------

BASE_DIR = os.path.dirname(__file__)
MODELS_DIR = os.path.join(BASE_DIR, 'models')

DT_PATH = os.path.join(MODELS_DIR, 'decision_tree.pkl')
RF_PATH = os.path.join(MODELS_DIR, 'random_forest.pkl')
COLS_PATH = os.path.join(MODELS_DIR, 'feature_columns.json')
METRICS_PATH = os.path.join(MODELS_DIR, 'training_metrics.json')

init_db()

_training_metrics = None

# -------------------------------
# HELPERS
# -------------------------------

def _load_training_metrics():
    global _training_metrics
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, 'r') as f:
                _training_metrics = json.load(f)
        except Exception:
            _training_metrics = None
    return _training_metrics


def check_models_trained():
    return (
        os.path.exists(DT_PATH) and
        os.path.exists(RF_PATH) and
        os.path.exists(COLS_PATH)
    )


def json_response(data=None, error=None, success=True, status=200):
    return jsonify({
        "success": success,
        "data": data,
        "error": error
    }), status


# -------------------------------
# 🚀 NON-BLOCKING TRAINING
# -------------------------------

def background_train():
    try:
        print("⚠️ Background training started...")
        from model_trainer import train_models
        train_models()
        _load_training_metrics()
        print("✅ Background training completed")
    except Exception as e:
        print("❌ Background training failed:", str(e))


print("🚀 App starting...")

_load_training_metrics()

if not check_models_trained():
    print("⚠️ Models missing → starting background training")
    threading.Thread(target=background_train).start()
else:
    print("✅ Models already available")

# -------------------------------
# ROUTES
# -------------------------------

@app.route('/')
def home():
    return "API is live", 200


@app.before_request
def ensure_models():
    if request.endpoint == 'predict' and not check_models_trained():
        return json_response(
            success=False,
            error="Model not ready yet. Try again shortly.",
            status=503
        )


def _resolve_malicious_idx(model):
    classes = list(model.classes_)
    for candidate in (1, 1.0, '1', '1.0'):
        if candidate in classes:
            return classes.index(candidate)
    for i, c in enumerate(classes):
        if str(c).strip() in ('1', '1.0'):
            return i
    raise ValueError("Malicious class not found")


@app.route('/api/predict', methods=['POST'])
def predict():
    try:
        data = request.json or {}
        url = data.get('url', '').strip()

        if not url:
            return json_response(success=False, error="Missing URL", status=400)

        dt_model = joblib.load(DT_PATH)
        rf_model = joblib.load(RF_PATH)

        with open(COLS_PATH, 'r') as f:
            feature_columns = json.load(f)

        features = extract_features_fast(url)
        X = np.array([[features.get(c, 0) for c in feature_columns]])

        dt_prob = dt_model.predict_proba(X)[0]
        rf_prob = rf_model.predict_proba(X)[0]

        dt_idx = _resolve_malicious_idx(dt_model)
        rf_idx = _resolve_malicious_idx(rf_model)

        dt_score = float(dt_prob[dt_idx])
        rf_score = float(rf_prob[rf_idx])

        risk = int((dt_score * 0.3 + rf_score * 0.7) * 100)

        result = {
            "url": url,
            "risk_score": risk,
            "label": "malicious" if risk >= 50 else "safe",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        save_scan(result)
        return json_response(data=result)

    except Exception as e:
        traceback.print_exc()
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/train', methods=['POST'])
def train():
    try:
        from model_trainer import train_models
        metrics = train_models()
        _load_training_metrics()
        return json_response(data=metrics)
    except Exception as e:
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/health', methods=['GET'])
def health():
    return json_response(data={
        "models_ready": check_models_trained()
    })


@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        message = request.json.get('message', '')
        response = chatbot.get_response(message)
        return json_response(data=response)
    except Exception as e:
        return json_response(success=False, error=str(e), status=500)
