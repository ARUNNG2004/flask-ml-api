import os
import json
import joblib
import numpy as np
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback
import threading

from feature_extractor import extract_features_fast
from database import init_db, save_scan
import chatbot

app = Flask(__name__)

CORS(app)

# -------------------------------
# GLOBAL STATE
# -------------------------------

training_status = {
    "is_training": False,
    "progress": 0,
    "message": "Not started"
}

dt_model = None
rf_model = None
feature_columns = None

# -------------------------------
# PATHS
# -------------------------------

BASE_DIR = os.path.dirname(__file__)
MODELS_DIR = os.path.join(BASE_DIR, 'models')

DT_PATH = os.path.join(MODELS_DIR, 'decision_tree.pkl')
RF_PATH = os.path.join(MODELS_DIR, 'random_forest.pkl')
COLS_PATH = os.path.join(MODELS_DIR, 'feature_columns.json')

init_db()

# -------------------------------
# HELPERS
# -------------------------------

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


def load_models():
    global dt_model, rf_model, feature_columns

    dt_model = joblib.load(DT_PATH)
    rf_model = joblib.load(RF_PATH)

    with open(COLS_PATH, 'r') as f:
        feature_columns = json.load(f)

    print("✅ Models loaded into memory")


# -------------------------------
# 🚀 BACKGROUND TRAINING
# -------------------------------

def background_train():
    global training_status

    try:
        training_status.update({
            "is_training": True,
            "progress": 0,
            "message": "Starting..."
        })

        print("🚀 Training started")

        from model_trainer import train_models

        # Fake progress stages (important)
        for i in range(1, 6):
            training_status["progress"] = i * 10
            training_status["message"] = f"Preparing data {i*10}%"
            print(training_status["message"])

        train_models()

        training_status.update({
            "progress": 70,
            "message": "Training ML models..."
        })
        print("⚙️ Training models...")

        # Load models
        load_models()

        training_status.update({
            "progress": 100,
            "message": "Completed",
            "is_training": False
        })

        print("✅ Training completed")

    except Exception as e:
        training_status.update({
            "is_training": False,
            "message": str(e)
        })
        print("❌ Training error:", str(e))


# -------------------------------
# STARTUP
# -------------------------------

print("🚀 App starting...")

if check_models_trained():
    load_models()
else:
    print("⚠️ Models missing → training in background")
    threading.Thread(target=background_train).start()

# -------------------------------
# ROUTES
# -------------------------------

@app.route('/')
def home():
    return "API is live", 200


@app.route('/api/status')
def status():
    return json_response(data=training_status)


@app.before_request
def check_ready():
    if request.endpoint == "predict" and dt_model is None:
        return json_response(
            success=False,
            error="Model not ready yet",
            status=503
        )


def _resolve_malicious_idx(model):
    classes = list(model.classes_)
    for candidate in (1, 1.0, '1', '1.0'):
        if candidate in classes:
            return classes.index(candidate)
    return 1


@app.route('/api/predict', methods=['POST'])
def predict():
    try:
        data = request.json or {}
        url = data.get("url", "").strip()

        if not url:
            return json_response(success=False, error="URL required", status=400)

        features = extract_features_fast(url)
        X = np.array([[features.get(c, 0) for c in feature_columns]])

        dt_prob = dt_model.predict_proba(X)[0]
        rf_prob = rf_model.predict_proba(X)[0]

        dt_idx = _resolve_malicious_idx(dt_model)
        rf_idx = _resolve_malicious_idx(rf_model)

        score = int((dt_prob[dt_idx] * 0.3 + rf_prob[rf_idx] * 0.7) * 100)

        result = {
            "url": url,
            "risk_score": score,
            "label": "malicious" if score >= 50 else "safe",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        save_scan(result)
        return json_response(data=result)

    except Exception as e:
        traceback.print_exc()
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/train', methods=['POST'])
def train():
    threading.Thread(target=background_train).start()
    return json_response(data={"message": "Training started"})


@app.route('/api/health')
def health():
    return json_response(data={
        "models_ready": dt_model is not None
    })


@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        msg = request.json.get("message", "")
        return json_response(data=chatbot.get_response(msg))
    except Exception as e:
        return json_response(success=False, error=str(e), status=500)
