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


