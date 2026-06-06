import os
from dotenv import load_dotenv

# Load .env file from the project root (one level up from Backend_Files)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))

# --- API Keys (loaded from .env) ---
VIRUSTOTAL_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")

# --- Flask Settings ---
FLASK_ENV  = os.getenv("FLASK_ENV", "development")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
VIRUSTOTAL_API_KEY  = "your_actual_virustotal_key"
ABUSEIPDB_API_KEY   = "your_actual_abuseipdb_key"

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

# ──────────────────────────────────────────────────────────
# REPORT SETTINGS
# ──────────────────────────────────────────────────────────

REPORT_OUTPUT_DIR       = "reports"
REPORT_TITLE            = "Phishing Incident Report"
REPORT_AUTHOR           = "Phishing Detector"

# ──────────────────────────────────────────────────────────
# PHISHING KEYWORDS
# (must match exactly what was used during training)
# ──────────────────────────────────────────────────────────

PHISHING_KEYWORDS = [
    'click', 'verify', 'account', 'password', 'urgent',
    'bank', 'login', 'update', 'confirm', 'secure',
    'winner', 'prize', 'free', 'offer', 'limited',
    'suspend', 'validate', 'expire', 'immediate', 'alert'
]

SUBJECT_KEYWORDS = [
    'urgent', 'verify', 'suspended', 'winner',
    'congratulations', 'alert', 'confirm', 'free'
]


