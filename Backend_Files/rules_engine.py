# ============================================================
# rules_engine.py
# Rule-based triage engine for phishing detection
# Combines parsed email flags, threat intel results,
# and ML scores into a final unified threat decision
# ============================================================

from config import (
    THRESHOLD_MALICIOUS,
    THRESHOLD_SUSPICIOUS,
    PHISHING_KEYWORDS,
    SUBJECT_KEYWORDS
)

# ──────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────

# Individual rule weights (contribute to final score 0-100)
WEIGHTS = {
    # Header-based rules
    'spf_fail'                  : 10,
    'dkim_fail'                 : 10,
    'dmarc_fail'                : 10,
    'reply_to_mismatch'         : 8,
    'auth_fail_all'             : 15,

    # URL-based rules
    'malicious_url'             : 30,
    'suspicious_url'            : 10,
    'ip_as_domain'              : 12,
    'non_https_url'             : 5,
    'excessive_urls'            : 5,
    'suspicious_tld'            : 8,

    # IP-based rules
    'malicious_ip'              : 25,
    'high_abuse_confidence'     : 20,
    'medium_abuse_confidence'   : 10,
    'tor_exit_node'             : 15,

    # Text-based rules
    'high_keyword_count'        : 10,
    'medium_keyword_count'      : 5,
    'suspicious_subject'        : 5,
    'excessive_exclamation'     : 3,
    'high_capital_ratio'        : 3,
    'has_html'                  : 2,

    # ML-based rules
    'ml_email_high'             : 30,
    'ml_email_medium'           : 15,
    'ml_url_high'               : 30,
    'ml_url_medium'             : 15,
}

