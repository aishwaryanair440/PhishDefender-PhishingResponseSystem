# ============================================================
# config.py
# Central configuration file for the phishing detector
# DO NOT push this file to GitHub
# ============================================================

# ──────────────────────────────────────────────────────────
# API KEYS
# ──────────────────────────────────────────────────────────

VIRUSTOTAL_API_KEY  = "your_virustotal_api_key_here"
ABUSEIPDB_API_KEY   = "your_abuseipdb_api_key_here"

# ──────────────────────────────────────────────────────────
# API URLS
# ──────────────────────────────────────────────────────────

VIRUSTOTAL_URL_SCAN     = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_IP_SCAN      = "https://www.virustotal.com/api/v3/ip_addresses"
ABUSEIPDB_URL           = "https://api.abuseipdb.com/api/v2/check"

# ──────────────────────────────────────────────────────────
# MODEL FILE PATHS
# ──────────────────────────────────────────────────────────

EMAIL_MODEL_PATH        = "email_model.pkl"
URL_MODEL_PATH          = "url_model.pkl"
TFIDF_VECTORIZER_PATH   = "tfidf_vectorizer.pkl"
SCALER_PATH             = "scaler.pkl"
URL_FEATURE_NAMES_PATH  = "url_feature_names.pkl"
MODEL_METADATA_PATH     = "model_metadata.json"

# ──────────────────────────────────────────────────────────
# THREAT SCORING THRESHOLDS
# ──────────────────────────────────────────────────────────

# ML model prediction threshold
ML_THRESHOLD            = 0.5

# Final unified threat score thresholds (0-100)
THRESHOLD_MALICIOUS     = 70
THRESHOLD_SUSPICIOUS    = 40

# ──────────────────────────────────────────────────────────
# FLASK SERVER SETTINGS
# ──────────────────────────────────────────────────────────

FLASK_HOST              = "127.0.0.1"
FLASK_PORT              = 5000
FLASK_DEBUG             = False

