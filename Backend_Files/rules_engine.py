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

# ──────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────

def run_rules_engine(parsed_email, threat_intel, ml_scores):
    """
    Main function called by app.py
    Combines all signals into a unified threat decision

    Args:
        parsed_email  : output from email_parser.py
        threat_intel  : output from threat_intel.py
        ml_scores     : output from ml_classifier.py

    Returns:
        dict with final verdict, score, triggered rules,
        and full breakdown
    """
    triggered_rules = []
    score_breakdown = {}
    total_score     = 0

    # ── 1. Header rules ───────────────────────────────────
    header_score, header_rules = evaluate_header_rules(
        parsed_email.get('headers', {})
    )
    total_score     += header_score
    triggered_rules += header_rules
    score_breakdown['headers'] = {
        'score' : header_score,
        'rules' : header_rules
    }

    # ── 2. URL rules ──────────────────────────────────────
    url_score, url_rules = evaluate_url_rules(
        parsed_email.get('urls', []),
        threat_intel.get('url_results', [])
    )
    total_score     += url_score
    triggered_rules += url_rules
    score_breakdown['urls'] = {
        'score' : url_score,
        'rules' : url_rules
    }

    # ── 3. IP rules ───────────────────────────────────────
    ip_score, ip_rules = evaluate_ip_rules(
        threat_intel.get('ip_results', [])
    )
    total_score     += ip_score
    triggered_rules += ip_rules
    score_breakdown['ip'] = {
        'score' : ip_score,
        'rules' : ip_rules
    }

    # ── 4. Text rules ─────────────────────────────────────
    text_score, text_rules = evaluate_text_rules(
        parsed_email.get('text_features', {})
    )
    total_score     += text_score
    triggered_rules += text_rules
    score_breakdown['text'] = {
        'score' : text_score,
        'rules' : text_rules
    }

    # ── 5. ML rules ───────────────────────────────────────
    ml_score, ml_rules = evaluate_ml_rules(ml_scores)
    total_score     += ml_score
    triggered_rules += ml_rules
    score_breakdown['ml'] = {
        'score' : ml_score,
        'rules' : ml_rules
    }

    # ── Cap score at 100 ──────────────────────────────────
    total_score = min(total_score, 100)

    # ── Determine verdict ─────────────────────────────────
    verdict = determine_verdict(total_score)

    # ── Build IOC list ────────────────────────────────────
    iocs = build_ioc_list(
        parsed_email,
        threat_intel,
        ml_scores,
        triggered_rules
    )

    # ── Build recommended actions ─────────────────────────
    actions = recommend_actions(verdict, triggered_rules)

    return {
        'verdict'           : verdict,
        'total_score'       : total_score,
        'triggered_rules'   : triggered_rules,
        'score_breakdown'   : score_breakdown,
        'iocs'              : iocs,
        'actions'           : actions,
        'flags'             : parsed_email.get('flags', []),
        'summary'           : build_summary(
                                verdict,
                                total_score,
                                triggered_rules,
                                iocs
                              )
    }

