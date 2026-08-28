"""
PhishGuard web app + prediction API.

Serves the URL scanner UI and the JSON API that the browser extension can
optionally call for a second opinion from the full Random Forest model (the
extension's own on-device model is a Gradient Boosting export).

    GET  /                    scanner UI
    GET  /report              evaluation report (metrics + all figures)
    POST /api/predict         {"url": "..."}            -> verdict
    POST /api/predict/batch   {"urls": ["...", "..."]}  -> list of verdicts
    GET  /api/model-info      model card + test metrics
    GET  /api/health          liveness probe

Run:  python webapp/app.py      (http://127.0.0.1:5000)
"""

from __future__ import annotations

import json
import os
import sys

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_cors import CORS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ml"))
from features import FEATURE_LABELS, FEATURE_NAMES, extract_features, get_hostname  # noqa: E402

MODEL_DIR = os.path.join(ROOT, "models")
METRIC_DIR = os.path.join(ROOT, "reports", "metrics")
FIG_DIR = os.path.join(ROOT, "reports", "figures")

DEFAULT_THRESHOLD = 0.5
MAX_BATCH = 100

app = Flask(__name__)
CORS(app)   # the extension calls this API from a different origin

_model = None
_meta = None
_metrics = None


def load_artifacts():
    """Load the model and its metrics once, on first use."""
    global _model, _meta, _metrics
    if _model is None:
        path = os.path.join(MODEL_DIR, "phishing_model.joblib")
        if not os.path.exists(path):
            raise RuntimeError(
                "models/phishing_model.joblib is missing - run "
                "`python ml/train_model.py` first.")
        _model = joblib.load(path)
        with open(os.path.join(MODEL_DIR, "model_meta.json"), encoding="utf-8") as fh:
            _meta = json.load(fh)
        metrics_path = os.path.join(METRIC_DIR, "test_metrics.json")
        if os.path.exists(metrics_path):
            with open(metrics_path, encoding="utf-8") as fh:
                _metrics = json.load(fh)
        else:
            _metrics = {}
    return _model, _meta, _metrics


def risk_level(probability: float) -> str:
    if probability >= 0.8:
        return "high"
    if probability >= 0.5:
        return "elevated"
    if probability >= 0.3:
        return "low"
    return "minimal"


def explain(feats: dict) -> list:
    """Plain-English reasons, ordered most alarming first.

    These describe the signals the model actually reads; they are an
    explanation of the URL, not a second classifier.
    """
    reasons = []
    if feats["ip"]:
        reasons.append({
            "level": "bad",
            "text": "Contains a raw IP address or a long random-looking token "
                    "instead of a clean, readable path."})
    if feats["nb_at"]:
        reasons.append({
            "level": "bad",
            "text": "Contains '@' — everything before it is ignored by the "
                    "browser, a classic way to disguise the real destination."})
    if feats["length_url"] > 75:
        reasons.append({
            "level": "warn",
            "text": "Unusually long URL (" + str(feats["length_url"])
                    + " characters) — often used to bury the real domain."})
    if feats["nb_dots"] >= 4:
        reasons.append({
            "level": "warn",
            "text": "Many dots (" + str(feats["nb_dots"]) + ") — suggests a "
                    "deep subdomain chain such as bank.com.attacker.net."})
    if feats["nb_hyphens"] >= 3:
        reasons.append({
            "level": "warn",
            "text": "Many hyphens (" + str(feats["nb_hyphens"]) + ") — brand "
                    "impersonation often looks like secure-login-verify.com."})
    if feats["length_hostname"] > 30:
        reasons.append({
            "level": "warn",
            "text": "Long hostname (" + str(feats["length_hostname"])
                    + " characters)."})
    if feats["nb_qm"] + feats["nb_and"] >= 4:
        reasons.append({
            "level": "info",
            "text": "Heavily parameterised query string."})
    if not reasons:
        reasons.append({
            "level": "good",
            "text": "No individual red flags in the URL structure."})
    return reasons


def predict_url(url: str, threshold: float = DEFAULT_THRESHOLD) -> dict:
    model, meta, _ = load_artifacts()
    feats = extract_features(url)
    row = pd.DataFrame([[feats[n] for n in FEATURE_NAMES]], columns=FEATURE_NAMES)
    probability = float(model.predict_proba(row)[0][1])
    return {
        "url": url,
        "hostname": get_hostname(url),
        "probability": round(probability, 4),
        "confidence": round(max(probability, 1 - probability) * 100, 1),
        "threshold": threshold,
        "is_phishing": bool(probability >= threshold),
        "verdict": "phishing" if probability >= threshold else "legitimate",
        "risk_level": risk_level(probability),
        "risk_score": int(round(probability * 100)),
        "features": feats,
        "feature_labels": FEATURE_LABELS,
        "reasons": explain(feats),
        "model": meta["best_model"],
    }


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    _, meta, metrics = load_artifacts()
    return render_template("index.html", meta=meta, metrics=metrics)


@app.route("/report")
def report():
    _, meta, metrics = load_artifacts()
    comparison = []
    csv_path = os.path.join(METRIC_DIR, "model_comparison.csv")
    if os.path.exists(csv_path):
        comparison = (pd.read_csv(csv_path)
                      .sort_values("roc_auc", ascending=False)
                      .to_dict("records"))
    figures = sorted(f for f in os.listdir(FIG_DIR) if f.endswith(".png")) \
        if os.path.isdir(FIG_DIR) else []
    return render_template("report.html", meta=meta, metrics=metrics,
                           comparison=comparison, figures=figures)


@app.route("/figures/<path:filename>")
def figures(filename):
    return send_from_directory(FIG_DIR, filename)


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
@app.route("/api/predict", methods=["POST"])
def api_predict():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Provide a 'url' field."}), 400
    try:
        threshold = float(payload.get("threshold", DEFAULT_THRESHOLD))
    except (TypeError, ValueError):
        return jsonify({"error": "'threshold' must be a number."}), 400
    if not 0.0 < threshold < 1.0:
        return jsonify({"error": "'threshold' must be between 0 and 1."}), 400
    return jsonify(predict_url(url, threshold))


@app.route("/api/predict/batch", methods=["POST"])
def api_predict_batch():
    payload = request.get_json(silent=True) or {}
    urls = payload.get("urls")
    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "Provide a non-empty 'urls' array."}), 400
    if len(urls) > MAX_BATCH:
        return jsonify({"error": "At most " + str(MAX_BATCH)
                        + " URLs per request."}), 400
    threshold = float(payload.get("threshold", DEFAULT_THRESHOLD))
    results = [predict_url(str(u), threshold) for u in urls if str(u).strip()]
    return jsonify({
        "count": len(results),
        "flagged": sum(1 for r in results if r["is_phishing"]),
        "results": results,
    })


@app.route("/api/model-info")
def api_model_info():
    _, meta, metrics = load_artifacts()
    return jsonify({
        "model": meta["best_model"],
        "features": FEATURE_NAMES,
        "feature_labels": FEATURE_LABELS,
        "trained_at": meta["trained_at"],
        "dataset_rows": meta["n_rows"],
        "train_rows": meta["n_train"],
        "test_rows": meta["n_test"],
        "default_threshold": DEFAULT_THRESHOLD,
        "test_metrics": metrics,
    })


@app.route("/api/health")
def api_health():
    try:
        load_artifacts()
        return jsonify({"status": "ok", "model": _meta["best_model"]})
    except Exception as exc:  # model not trained yet
        return jsonify({"status": "error", "detail": str(exc)}), 503


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    load_artifacts()
    print("PhishGuard running on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
