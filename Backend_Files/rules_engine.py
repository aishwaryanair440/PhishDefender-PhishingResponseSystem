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


