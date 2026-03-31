import os
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback

from feature_extractor import extract_features, extract_features_fast
from database import init_db, save_scan, get_history, delete_scan, clear_history
import chatbot

app = Flask(__name__)

CORS(app, resources={r"/api/*": {
    "origins": "*",
    "methods": ["GET", "POST", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type"]
}})

MODELS_DIR  = os.path.join(os.path.dirname(__file__), 'models')
DT_PATH     = os.path.join(MODELS_DIR, 'decision_tree.pkl')
RF_PATH     = os.path.join(MODELS_DIR, 'random_forest.pkl')
COLS_PATH   = os.path.join(MODELS_DIR, 'feature_columns.json')
METRICS_PATH = os.path.join(MODELS_DIR, 'training_metrics.json')

init_db()

_training_metrics = None
# -------------------------------
# Helper functions FIRST
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
# Load metrics (safe)
# -------------------------------

_load_training_metrics()


# -------------------------------
# 🚀 STARTUP TRAINING (FIXED)
# -------------------------------

print("🚀 Initializing model loading...")

try:
    if not check_models_trained():
        print("⚠️ Models missing at startup. Training now...")

        from model_trainer import train_models
        train_models()

        _load_training_metrics()

        if not check_models_trained():
            raise RuntimeError("Training completed but model files still missing!")

        print("✅ Models trained successfully at startup.")
    else:
        print("✅ Models already available. Skipping training.")

except Exception as e:
    print("❌ Startup training failed:", str(e))
    import traceback
    traceback.print_exc()

    # 🔴 HARD FAIL (recommended for production)
    raise RuntimeError("App stopped due to model training failure")


# -------------------------------
# Routes
# -------------------------------

@app.route('/')
def home():
    return "API is live"
    
@app.before_request
def check_models_before_predict():
    if (request.endpoint == 'predict'
            and request.method != 'OPTIONS'
            and not check_models_trained()):
        # Try to train if missing
        try:
            print("Models missing! Attempting automatic training...")
            from model_trainer import train_models
            train_models()
            _load_training_metrics()
            print("Automatic training completed.")
            if not check_models_trained():
                raise Exception("Training finished but models still missing.")
        except Exception as e:
            traceback.print_exc()
            return json_response(
                success=False, data=None, status=503,
                error=f"Models not trained and automatic training failed: {str(e)}"
            )


def _resolve_malicious_idx(model):
    """
    Return the index of the MALICIOUS class (label == 1) in model.classes_.
    Handles int, float, and string label variants robustly.
    Raises ValueError if label 1 cannot be found.
    """
    classes = list(model.classes_)
    # Try exact match first (int 1, float 1.0, str '1')
    for candidate in (1, 1.0, '1', '1.0'):
        if candidate in classes:
            return classes.index(candidate)
    # Fallback: pick the class whose string repr is '1'
    for i, c in enumerate(classes):
        if str(c).strip() in ('1', '1.0'):
            return i
    raise ValueError(
        f"Cannot find malicious class (1) in model.classes_: {classes}"
    )


@app.route('/api/predict', methods=['POST'])
def predict():
    try:
        req_data = request.json or {}
        url = (req_data.get('url') or '').strip()
        if not url:
            return json_response(success=False, error="Missing 'url' parameter.", status=400)

        mode = req_data.get('mode', 'fast')

        # ── Load artefacts ────────────────────────────────────────────────────
        dt_model = joblib.load(DT_PATH)
        rf_model = joblib.load(RF_PATH)
        with open(COLS_PATH, 'r') as f:
            feature_columns = json.load(f)

        # ── Extract features ──────────────────────────────────────────────────
        features_dict = (
            extract_features_fast(url) if mode == 'fast'
            else extract_features(url)
        )

        # Fill any missing columns with 0 (safety net)
        missing = [c for c in feature_columns if c not in features_dict]
        if missing:
            app.logger.warning(f"Missing features filled with 0: {missing}")
            for k in missing:
                features_dict[k] = 0

        # Build feature array in EXACT column order
        X = np.array([[features_dict[c] for c in feature_columns]])

        # ── Predict probabilities ─────────────────────────────────────────────
        dt_proba_arr = dt_model.predict_proba(X)[0]
        rf_proba_arr = rf_model.predict_proba(X)[0]

        # Resolve malicious class index for each model independently
        dt_mal_idx = _resolve_malicious_idx(dt_model)
        rf_mal_idx = _resolve_malicious_idx(rf_model)

        dt_mal_proba = float(dt_proba_arr[dt_mal_idx])
        rf_mal_proba = float(rf_proba_arr[rf_mal_idx])

        # ── Labels & confidence ───────────────────────────────────────────────
        #
        # confidence = probability of the PREDICTED class
        # malicious_proba = always probability of class 1 (used for risk score)
        #
        if dt_mal_proba >= 0.5:
            dt_label, dt_confidence = 'malicious', dt_mal_proba
        else:
            dt_label, dt_confidence = 'safe', 1.0 - dt_mal_proba

        if rf_mal_proba >= 0.5:
            rf_label, rf_confidence = 'malicious', rf_mal_proba
        else:
            rf_label, rf_confidence = 'safe', 1.0 - rf_mal_proba

        # ── Ensemble & risk score ─────────────────────────────────────────────
        # RF weighted more (it's an ensemble method, inherently more reliable)
        weighted_mal_proba = (dt_mal_proba * 0.3) + (rf_mal_proba * 0.7)

        # IMPORTANT: also factor in strong heuristic signals so that
        # clearly malicious-pattern URLs are never buried at score 0.
        #
        # Heuristic boost: if lexical features strongly indicate phishing,
        # raise the floor of the risk score.
        heuristic_signals = 0
        f = features_dict
        heuristic_signals += f.get('phish_brand_hijack',     0) * 25
        heuristic_signals += f.get('phish_suspicious_tld',   0) * 20
        heuristic_signals += min(f.get('phish_urgency_words', 0), 3) * 8
        heuristic_signals += f.get('having_ip_address',       0) * 15
        heuristic_signals += f.get('Shortining_Service',      0) * 10
        heuristic_signals += min(f.get('phish_brand_mentions', 0), 2) * 10
        heuristic_signals += min(f.get('subdomain_count', 0), 3) * 5
        heuristic_signals = min(heuristic_signals, 60)  # cap contribution

        # No-HTTPS penalty (only when NOT a known safe domain)
        if f.get('https', 0) == 0:
            heuristic_signals = min(heuristic_signals + 10, 60)

        # Blend ML probability with heuristic floor
        ml_score        = int(round(weighted_mal_proba * 100))
        heuristic_floor = heuristic_signals
        risk_score      = max(ml_score, heuristic_floor)
        risk_score      = min(risk_score, 100)

        ensemble_label = 'malicious' if risk_score >= 50 else 'safe'
        ensemble_conf  = risk_score / 100.0 if ensemble_label == 'malicious' \
                         else (100 - risk_score) / 100.0

        # ── Build response ────────────────────────────────────────────────────
        result_data = {
            "url":       url,
            "scan_mode": mode,
            "decision_tree": {
                "label":           dt_label,
                "confidence":      round(dt_confidence,   4),
                "malicious_proba": round(dt_mal_proba,    4),
            },
            "random_forest": {
                "label":           rf_label,
                "confidence":      round(rf_confidence,   4),
                "malicious_proba": round(rf_mal_proba,    4),
            },
            "ensemble": {
                "label":      ensemble_label,
                "confidence": round(ensemble_conf, 4),
            },
            "risk_score": risk_score,
            "features":   features_dict,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            # debug info
            "_debug": {
                "ml_score":        ml_score,
                "heuristic_floor": heuristic_floor,
                "dt_mal_proba":    round(dt_mal_proba, 4),
                "rf_mal_proba":    round(rf_mal_proba, 4),
                "dt_classes":      [str(c) for c in dt_model.classes_],
                "rf_classes":      [str(c) for c in rf_model.classes_],
            }
        }

        save_scan(result_data)
        return json_response(data=result_data)

    except Exception as e:
        traceback.print_exc()
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/train', methods=['POST'])
def train():
    try:
        from model_trainer import train_models
        metrics = train_models()
        _load_training_metrics()
        tm = metrics.get('training_metrics', {})
        return json_response(data={
            "dt_accuracy":        tm.get('dt_accuracy', 0.0),
            "rf_accuracy":        tm.get('rf_accuracy', 0.0),
            "dt_f1_malicious":    tm.get('dt_f1_malicious', 0.0),
            "rf_f1_malicious":    tm.get('rf_f1_malicious', 0.0),
            "samples":            tm.get('samples_used', 0),
            "features":           tm.get('features_used', 0),
            "class_distribution": tm.get('class_distribution', {}),
            "trained_at":         tm.get('trained_at', None),
        })
    except Exception as e:
        traceback.print_exc()
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/history', methods=['GET'])
def history():
    try:
        page       = int(request.args.get('page', 1))
        per_page   = int(request.args.get('per_page', 20))
        filter_val = request.args.get('filter', 'all')
        return json_response(data=get_history(page, per_page, filter_val))
    except Exception as e:
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/history/<int:record_id>', methods=['DELETE'])
def delete_history_record(record_id):
    try:
        delete_scan(record_id)
        return json_response(data={"deleted_id": record_id})
    except Exception as e:
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/history', methods=['DELETE'])
def clear_all_history():
    try:
        clear_history()
        return json_response(data={"message": "All history cleared."})
    except Exception as e:
        return json_response(success=False, error=str(e), status=500)


@app.route('/api/health', methods=['GET'])
def health():
    trained      = check_models_trained()
    feature_count = 0
    trained_at   = None
    dt_f1_mal    = None
    rf_f1_mal    = None
    class_dist   = None
    dt_loaded    = False
    rf_loaded    = False

    if trained:
        try:
            with open(COLS_PATH, 'r') as f:
                feature_count = len(json.load(f))
            dt_loaded = os.path.exists(DT_PATH)
            rf_loaded = os.path.exists(RF_PATH)
        except Exception:
            pass

        metrics = _training_metrics or _load_training_metrics()
        if metrics:
            trained_at  = metrics.get('trained_at')
            dt_f1_mal   = metrics.get('dt_f1_malicious')
            rf_f1_mal   = metrics.get('rf_f1_malicious')
            class_dist  = metrics.get('class_distribution')
        else:
            try:
                trained_at = datetime.fromtimestamp(
                    os.path.getmtime(DT_PATH), tz=timezone.utc
                ).isoformat()
            except Exception:
                pass

    return json_response(data={
        "models_ready":     trained,
        "dt_loaded":        dt_loaded,
        "rf_loaded":        rf_loaded,
        "feature_count":    feature_count,
        "trained_at":       trained_at,
        "dt_f1_malicious":  dt_f1_mal,
        "rf_f1_malicious":  rf_f1_mal,
        "class_distribution": class_dist,
    })


@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        req_data = request.json or {}
        message  = (req_data.get('message') or '').strip()
        if not message:
            return json_response(success=False, error="Empty message.", status=400)

        if hasattr(chatbot, 'get_response'):
            response = chatbot.get_response(message)
        else:
            response = {
                "response":    "Chatbot module not fully implemented.",
                "category":    "error",
                "suggestions": [],
            }

        if isinstance(response, str):
            response = {"response": response, "category": "unknown", "suggestions": []}

        return json_response(data=response)
    except Exception as e:
        return json_response(success=False, error=str(e), status=500)


if __name__ == '__main__':
    # Auto-train on startup if missing
    if not check_models_trained():
        print("Models not found on startup. Training automatically...")
        try:
            from model_trainer import train_models
            train_models()
            _load_training_metrics()
            print("Startup training completed.")
        except Exception as e:
            print(f"FAILED to train models on startup: {e}")
            import traceback
            traceback.print_exc()

    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'true').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=port)
