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

