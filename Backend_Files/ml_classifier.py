# ============================================================
# ml_classifier.py
# Loads trained LightGBM models and runs predictions
# Uses both email model and URL model to produce
# a unified phishing probability score
# ============================================================

import re
import json
import numpy as np
import pandas as pd
import scipy.sparse as sp
import joblib
import lightgbm as lgb
from config import (
    EMAIL_MODEL_PATH,
    URL_MODEL_PATH,
    TFIDF_VECTORIZER_PATH,
    SCALER_PATH,
    URL_FEATURE_NAMES_PATH,
    MODEL_METADATA_PATH,
    ML_THRESHOLD,
    PHISHING_KEYWORDS,
    SUBJECT_KEYWORDS
)

# ──────────────────────────────────────────────────────────
# MODEL LOADER
# Loaded once at startup — not on every request
# ──────────────────────────────────────────────────────────

_email_model    = None
_url_model      = None
_tfidf          = None
_scaler         = None
_url_feat_names = None
_metadata       = None


def load_models():
    """
    Loads all models and vectorizers from disk
    Called once when app.py starts
    """
    global _email_model, _url_model, _tfidf
    global _scaler, _url_feat_names, _metadata

    print("[ml_classifier] Loading models...")

    try:
        _email_model    = joblib.load(EMAIL_MODEL_PATH)
        print(f"  Email model loaded     : {EMAIL_MODEL_PATH}")
    except Exception as e:
        print(f"  ERROR loading email model : {e}")
        raise

    try:
        _url_model      = joblib.load(URL_MODEL_PATH)
        print(f"  URL model loaded       : {URL_MODEL_PATH}")
    except Exception as e:
        print(f"  ERROR loading URL model   : {e}")
        raise

    try:
        _tfidf          = joblib.load(TFIDF_VECTORIZER_PATH)
        print(f"  TF-IDF loaded          : {TFIDF_VECTORIZER_PATH}")
    except Exception as e:
        print(f"  ERROR loading TF-IDF      : {e}")
        raise

    try:
        _scaler         = joblib.load(SCALER_PATH)
        print(f"  Scaler loaded          : {SCALER_PATH}")
    except Exception as e:
        print(f"  ERROR loading scaler      : {e}")
        raise

    try:
        _url_feat_names = joblib.load(URL_FEATURE_NAMES_PATH)
        print(f"  URL feature names loaded : {URL_FEATURE_NAMES_PATH}")
    except Exception as e:
        print(f"  ERROR loading feature names : {e}")
        raise

    try:
        with open(MODEL_METADATA_PATH, 'r') as f:
            _metadata   = json.load(f)
        print(f"  Metadata loaded        : {MODEL_METADATA_PATH}")
    except Exception as e:
        print(f"  ERROR loading metadata    : {e}")
        raise

    print("[ml_classifier] All models loaded successfully")

# ──────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────

def run_ml_classifier(parsed_email):
    """
    Main function called by app.py
    Accepts parsed email object from email_parser.py
    Returns ML scores for both email and URL models
    """
    if _email_model is None:
        raise RuntimeError(
            "Models not loaded. Call load_models() first."
        )

    results = {
        'email_phishing_probability' : 0.0,
        'url_phishing_probability'   : 0.0,
        'email_prediction'           : 0,
        'url_prediction'             : 0,
        'combined_probability'       : 0.0,
        'combined_prediction'        : 0,
        'email_model_used'           : True,
        'url_model_used'             : False,
        'model_info'                 : {},
        'error'                      : None
    }

    # ── Run email model ───────────────────────────────────
    try:
        email_prob = predict_email(parsed_email)
        results['email_phishing_probability'] = round(email_prob, 4)
        results['email_prediction'] = int(email_prob >= ML_THRESHOLD)
    except Exception as e:
        results['error'] = f"Email model error: {str(e)}"
        print(f"[ml_classifier] Email model error: {e}")

    # ── Run URL model if URLs exist ────────────────────────
    urls = parsed_email.get('urls', [])
    if urls:
        try:
            url_prob = predict_url(urls[0])
            results['url_phishing_probability'] = round(url_prob, 4)
            results['url_prediction'] = int(url_prob >= ML_THRESHOLD)
            results['url_model_used'] = True
        except Exception as e:
            results['error'] = f"URL model error: {str(e)}"
            print(f"[ml_classifier] URL model error: {e}")
    else:
        # No URLs — URL model not applicable
        results['url_phishing_probability'] = 0.0
        results['url_model_used']           = False

    # ── Combine scores ────────────────────────────────────
    results['combined_probability'] = calculate_combined_score(
        results['email_phishing_probability'],
        results['url_phishing_probability'],
        results['url_model_used']
    )
    results['combined_prediction'] = int(
        results['combined_probability'] >= ML_THRESHOLD
    )

    # ── Add model info ────────────────────────────────────
    results['model_info'] = build_model_info(results)

    print(
        f"[ml_classifier] "
        f"Email prob: {results['email_phishing_probability']:.4f} | "
        f"URL prob: {results['url_phishing_probability']:.4f} | "
        f"Combined: {results['combined_probability']:.4f}"
    )

    return results



