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

# ──────────────────────────────────────────────────────────
# RULE EVALUATORS
# ──────────────────────────────────────────────────────────

def evaluate_header_rules(headers):
    """
    Evaluates email authentication header signals
    """
    score = 0
    rules = []

    spf   = headers.get('spf',  'unknown')
    dkim  = headers.get('dkim', 'unknown')
    dmarc = headers.get('dmarc','unknown')

    if spf == 'fail':
        score += WEIGHTS['spf_fail']
        rules.append({
            'rule'       : 'spf_fail',
            'description': 'SPF authentication failed',
            'weight'     : WEIGHTS['spf_fail'],
            'severity'   : 'medium'
        })

    if dkim == 'fail':
        score += WEIGHTS['dkim_fail']
        rules.append({
            'rule'       : 'dkim_fail',
            'description': 'DKIM authentication failed',
            'weight'     : WEIGHTS['dkim_fail'],
            'severity'   : 'medium'
        })

    if dmarc == 'fail':
        score += WEIGHTS['dmarc_fail']
        rules.append({
            'rule'       : 'dmarc_fail',
            'description': 'DMARC authentication failed',
            'weight'     : WEIGHTS['dmarc_fail'],
            'severity'   : 'medium'
        })

    # All three failing together is a stronger signal
    if spf == 'fail' and dkim == 'fail' and dmarc == 'fail':
        score += WEIGHTS['auth_fail_all']
        rules.append({
            'rule'       : 'auth_fail_all',
            'description': 'SPF, DKIM and DMARC all failed',
            'weight'     : WEIGHTS['auth_fail_all'],
            'severity'   : 'high'
        })

    if headers.get('reply_to_mismatch'):
        score += WEIGHTS['reply_to_mismatch']
        rules.append({
            'rule'       : 'reply_to_mismatch',
            'description': 'Reply-To address does not match sender',
            'weight'     : WEIGHTS['reply_to_mismatch'],
            'severity'   : 'medium'
        })

    return score, rules


def evaluate_url_rules(urls, url_results):
    """
    Evaluates URL-based signals from both
    local analysis and VirusTotal results
    """
    score = 0
    rules = []

    if not urls:
        return score, rules

    # VirusTotal confirmed malicious URLs
    malicious_urls = [r for r in url_results if r.get('malicious')]
    if malicious_urls:
        added = min(len(malicious_urls) * WEIGHTS['malicious_url'], 60)
        score += added
        rules.append({
            'rule'       : 'malicious_url',
            'description': f'{len(malicious_urls)} URL(s) flagged malicious by VirusTotal',
            'weight'     : added,
            'severity'   : 'critical'
        })

    # VirusTotal suspicious URLs
    suspicious_vt = [r for r in url_results if r.get('suspicious')]
    if suspicious_vt:
        added = min(len(suspicious_vt) * WEIGHTS['suspicious_url'], 20)
        score += added
        rules.append({
            'rule'       : 'suspicious_url',
            'description': f'{len(suspicious_vt)} URL(s) flagged suspicious by VirusTotal',
            'weight'     : added,
            'severity'   : 'medium'
        })

    # IP address used as domain
    ip_domains = [u for u in urls if u.get('has_ip')]
    if ip_domains:
        score += WEIGHTS['ip_as_domain']
        rules.append({
            'rule'       : 'ip_as_domain',
            'description': f'{len(ip_domains)} URL(s) use IP address as domain',
            'weight'     : WEIGHTS['ip_as_domain'],
            'severity'   : 'high'
        })

    # Non-HTTPS URLs
    non_https = [u for u in urls if not u.get('has_https')]
    if non_https:
        score += WEIGHTS['non_https_url']
        rules.append({
            'rule'       : 'non_https_url',
            'description': f'{len(non_https)} non-HTTPS URL(s) found',
            'weight'     : WEIGHTS['non_https_url'],
            'severity'   : 'low'
        })

    # Excessive number of URLs
    if len(urls) > 10:
        score += WEIGHTS['excessive_urls']
        rules.append({
            'rule'       : 'excessive_urls',
            'description': f'Excessive URL count: {len(urls)}',
            'weight'     : WEIGHTS['excessive_urls'],
            'severity'   : 'low'
        })

    # Suspicious TLDs
    suspicious_tlds = [
        '.tk', '.ml', '.ga', '.cf', '.gq',
        '.xyz', '.top', '.club', '.work', '.click'
    ]
    tld_hits = [
        u for u in urls
        if any(u.get('domain', '').endswith(tld)
               for tld in suspicious_tlds)
    ]
    if tld_hits:
        score += WEIGHTS['suspicious_tld']
        rules.append({
            'rule'       : 'suspicious_tld',
            'description': f'{len(tld_hits)} URL(s) use suspicious TLD',
            'weight'     : WEIGHTS['suspicious_tld'],
            'severity'   : 'medium'
        })

    return score, rules


def evaluate_ip_rules(ip_results):
    """
    Evaluates IP reputation signals from
    VirusTotal and AbuseIPDB
    """
    score = 0
    rules = []

    if not ip_results:
        return score, rules

    for ip_result in ip_results:
        abuse_confidence = ip_result.get('abuse_confidence', 0)
        vt_malicious     = ip_result.get('vt_malicious_count', 0)
        is_tor           = ip_result.get('is_tor', False)
        ip               = ip_result.get('ip', 'unknown')

        # VirusTotal flagged IP
        if vt_malicious > 0:
            score += WEIGHTS['malicious_ip']
            rules.append({
                'rule'       : 'malicious_ip',
                'description': f'IP {ip} flagged by {vt_malicious} VT engines',
                'weight'     : WEIGHTS['malicious_ip'],
                'severity'   : 'critical'
            })

        # AbuseIPDB high confidence
        if abuse_confidence >= 75:
            score += WEIGHTS['high_abuse_confidence']
            rules.append({
                'rule'       : 'high_abuse_confidence',
                'description': f'IP {ip} has {abuse_confidence}% abuse confidence',
                'weight'     : WEIGHTS['high_abuse_confidence'],
                'severity'   : 'high'
            })

        # AbuseIPDB medium confidence
        elif abuse_confidence >= 50:
            score += WEIGHTS['medium_abuse_confidence']
            rules.append({
                'rule'       : 'medium_abuse_confidence',
                'description': f'IP {ip} has {abuse_confidence}% abuse confidence',
                'weight'     : WEIGHTS['medium_abuse_confidence'],
                'severity'   : 'medium'
            })

        # Tor exit node
        if is_tor:
            score += WEIGHTS['tor_exit_node']
            rules.append({
                'rule'       : 'tor_exit_node',
                'description': f'IP {ip} is a Tor exit node',
                'weight'     : WEIGHTS['tor_exit_node'],
                'severity'   : 'high'
            })

    return score, rules


def evaluate_text_rules(text_features):
    """
    Evaluates text-based signals from
    extracted email features
    """
    score = 0
    rules = []

    keyword_count      = text_features.get('keyword_count', 0)
    suspicious_subject = text_features.get('suspicious_subject', 0)
    exclamation_count  = text_features.get('exclamation_count', 0)
    capital_ratio      = text_features.get('capital_ratio', 0)
    has_html           = text_features.get('has_html', 0)

    # High phishing keyword count
    if keyword_count >= 5:
        score += WEIGHTS['high_keyword_count']
        rules.append({
            'rule'       : 'high_keyword_count',
            'description': f'{keyword_count} phishing keywords detected in body',
            'weight'     : WEIGHTS['high_keyword_count'],
            'severity'   : 'medium'
        })
    elif keyword_count >= 2:
        score += WEIGHTS['medium_keyword_count']
        rules.append({
            'rule'       : 'medium_keyword_count',
            'description': f'{keyword_count} phishing keywords detected in body',
            'weight'     : WEIGHTS['medium_keyword_count'],
            'severity'   : 'low'
        })

    # Suspicious subject line
    if suspicious_subject:
        score += WEIGHTS['suspicious_subject']
        rules.append({
            'rule'       : 'suspicious_subject',
            'description': 'Phishing keyword found in subject line',
            'weight'     : WEIGHTS['suspicious_subject'],
            'severity'   : 'low'
        })

    # Excessive exclamation marks
    if exclamation_count >= 5:
        score += WEIGHTS['excessive_exclamation']
        rules.append({
            'rule'       : 'excessive_exclamation',
            'description': f'{exclamation_count} exclamation marks detected',
            'weight'     : WEIGHTS['excessive_exclamation'],
            'severity'   : 'low'
        })

    # High capital letter ratio
    if capital_ratio > 0.3:
        score += WEIGHTS['high_capital_ratio']
        rules.append({
            'rule'       : 'high_capital_ratio',
            'description': f'Capital ratio {capital_ratio:.0%} — possible urgency tactic',
            'weight'     : WEIGHTS['high_capital_ratio'],
            'severity'   : 'low'
        })

    # HTML in email body
    if has_html:
        score += WEIGHTS['has_html']
        rules.append({
            'rule'       : 'has_html',
            'description': 'HTML content found in email body',
            'weight'     : WEIGHTS['has_html'],
            'severity'   : 'low'
        })

    return score, rules


def evaluate_ml_rules(ml_scores):
    """
    Evaluates ML model confidence scores
    Converts probabilities into rule weights
    """
    score = 0
    rules = []

    email_prob = ml_scores.get('email_phishing_probability', 0)
    url_prob   = ml_scores.get('url_phishing_probability', 0)

    # Email model score
    if email_prob >= 0.85:
        score += WEIGHTS['ml_email_high']
        rules.append({
            'rule'       : 'ml_email_high',
            'description': f'Email ML model: {email_prob:.1%} phishing probability',
            'weight'     : WEIGHTS['ml_email_high'],
            'severity'   : 'high'
        })
    elif email_prob >= 0.5:
        score += WEIGHTS['ml_email_medium']
        rules.append({
            'rule'       : 'ml_email_medium',
            'description': f'Email ML model: {email_prob:.1%} phishing probability',
            'weight'     : WEIGHTS['ml_email_medium'],
            'severity'   : 'medium'
        })

    # URL model score
    if url_prob >= 0.85:
        score += WEIGHTS['ml_url_high']
        rules.append({
            'rule'       : 'ml_url_high',
            'description': f'URL ML model: {url_prob:.1%} phishing probability',
            'weight'     : WEIGHTS['ml_url_high'],
            'severity'   : 'high'
        })
    elif url_prob >= 0.5:
        score += WEIGHTS['ml_url_medium']
        rules.append({
            'rule'       : 'ml_url_medium',
            'description': f'URL ML model: {url_prob:.1%} phishing probability',
            'weight'     : WEIGHTS['ml_url_medium'],
            'severity'   : 'medium'
        })

    return score, rules

# ──────────────────────────────────────────────────────────
# VERDICT AND ACTIONS
# ──────────────────────────────────────────────────────────

def determine_verdict(score):
    """
    Maps final score to a verdict string
    Thresholds defined in config.py
    """
    if score >= THRESHOLD_MALICIOUS:
        return 'malicious'
    elif score >= THRESHOLD_SUSPICIOUS:
        return 'suspicious'
    else:
        return 'benign'


def recommend_actions(verdict, triggered_rules):
    """
    Recommends actions based on verdict
    and which rules were triggered
    """
    actions = []

    if verdict == 'malicious':
        actions.append('Block sender immediately')
        actions.append('Quarantine email')
        actions.append('Do not click any links')
        actions.append('Do not download attachments')
        actions.append('Report to IT security team')
        actions.append('Generate incident report')

    elif verdict == 'suspicious':
        actions.append('Exercise caution before clicking links')
        actions.append('Verify sender identity independently')
        actions.append('Do not enter credentials on linked pages')
        actions.append('Consider reporting to IT security team')

    else:
        actions.append('Email appears safe')
        actions.append('Standard email precautions apply')

    # Rule-specific additional actions
    rule_names = [r['rule'] for r in triggered_rules]

    if 'malicious_url' in rule_names:
        actions.append('Malicious URLs detected — do not visit')
    if 'malicious_ip' in rule_names:
        actions.append('Sending server IP is flagged malicious')
    if 'tor_exit_node' in rule_names:
        actions.append('Email originated from Tor network')
    if 'auth_fail_all' in rule_names:
        actions.append('Email failed all authentication checks')
    if 'reply_to_mismatch' in rule_names:
        actions.append('Reply-To mismatch — do not reply to this email')

    return list(dict.fromkeys(actions))

# ──────────────────────────────────────────────────────────
# IOC BUILDER
# ──────────────────────────────────────────────────────────

def build_ioc_list(parsed_email, threat_intel, ml_scores, triggered_rules):
    """
    Builds a consolidated list of Indicators of Compromise
    from all sources for the incident report
    """
    iocs = []

    # Malicious URLs from VirusTotal
    for url_result in threat_intel.get('url_results', []):
        if url_result.get('malicious') or url_result.get('suspicious'):
            iocs.append({
                'type'      : 'URL',
                'value'     : url_result.get('url', ''),
                'source'    : 'VirusTotal',
                'severity'  : 'critical' if url_result.get('malicious') else 'medium',
                'detail'    : f"Detected by {url_result.get('malicious_count', 0)} engines"
            })

    # Malicious IPs
    for ip_result in threat_intel.get('ip_results', []):
        if ip_result.get('malicious'):
            iocs.append({
                'type'      : 'IP Address',
                'value'     : ip_result.get('ip', ''),
                'source'    : 'VirusTotal + AbuseIPDB',
                'severity'  : 'critical',
                'detail'    : (
                    f"Abuse confidence: "
                    f"{ip_result.get('abuse_confidence', 0)}% | "
                    f"Country: {ip_result.get('country', 'unknown')}"
                )
            })

    # Sender domain
    sender = parsed_email.get('sender', '')
    if sender:
        iocs.append({
            'type'      : 'Sender',
            'value'     : sender,
            'source'    : 'Email header',
            'severity'  : 'info',
            'detail'    : 'Originating sender address'
        })

    # Originating IP
    origin_ip = parsed_email.get('headers', {}).get('originating_ip')
    if origin_ip:
        iocs.append({
            'type'      : 'Originating IP',
            'value'     : origin_ip,
            'source'    : 'Email header',
            'severity'  : 'info',
            'detail'    : 'IP extracted from Received header'
        })

    # High-severity rule triggers as IOCs
    critical_rules = [
        r for r in triggered_rules
        if r.get('severity') in ('critical', 'high')
    ]
    for rule in critical_rules:
        iocs.append({
            'type'      : 'Behavioral IOC',
            'value'     : rule['rule'],
            'source'    : 'Rules Engine',
            'severity'  : rule['severity'],
            'detail'    : rule['description']
        })

    return iocs


