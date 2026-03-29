# ============================================================
# threat_intel.py
# Handles all external threat intelligence API calls
# VirusTotal — URL and IP reputation
# AbuseIPDB  — IP abuse confidence scoring
# ============================================================

import re
import time
import base64
import requests
from config import (
    VIRUSTOTAL_API_KEY,
    VIRUSTOTAL_URL_SCAN,
    VIRUSTOTAL_IP_SCAN,
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_URL
)

# ──────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────

REQUEST_TIMEOUT     = 10      # seconds per API call
MAX_URLS_TO_SCAN    = 5       # limit to avoid API quota exhaustion
RETRY_ATTEMPTS      = 2       # retries on transient failures

# ──────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────

def run_threat_intelligence(parsed_email):
    """
    Main function called by app.py
    Accepts parsed email object from email_parser.py
    Returns enriched threat intelligence results
    """
    results = {
        'url_results'       : [],
        'ip_results'        : [],
        'overall_malicious' : False,
        'malicious_url_count': 0,
        'malicious_ip_count' : 0,
        'threat_score'      : 0,
        'iocs'              : [],
        'errors'            : []
    }

    urls    = parsed_email.get('urls', [])
    headers = parsed_email.get('headers', {})

    # ── Scan URLs ─────────────────────────────────────────
    if urls:
        urls_to_scan = urls[:MAX_URLS_TO_SCAN]
        print(f"[threat_intel] Scanning {len(urls_to_scan)} URL(s)...")

        for url_obj in urls_to_scan:
            raw_url = url_obj.get('raw', '')
            if not raw_url:
                continue

            vt_result = scan_url_virustotal(raw_url)
            url_obj['virustotal'] = vt_result

            if vt_result.get('malicious', False):
                results['malicious_url_count'] += 1
                results['iocs'].append({
                    'type'      : 'malicious_url',
                    'value'     : raw_url,
                    'source'    : 'VirusTotal',
                    'detections': vt_result.get('malicious_count', 0)
                })

            results['url_results'].append({
                'url'           : raw_url,
                'domain'        : url_obj.get('domain', ''),
                'malicious'     : vt_result.get('malicious', False),
                'suspicious'    : vt_result.get('suspicious', False),
                'malicious_count': vt_result.get('malicious_count', 0),
                'harmless_count' : vt_result.get('harmless_count', 0),
                'detection_ratio': vt_result.get('detection_ratio', '0/0'),
                'categories'    : vt_result.get('categories', []),
                'error'         : vt_result.get('error', None)
            })

            # Small delay to respect VirusTotal rate limits
            # Free tier allows 4 requests per minute
            time.sleep(15)

    # ── Scan originating IP ───────────────────────────────
    origin_ip = headers.get('originating_ip')
    if origin_ip and is_valid_ip(origin_ip):
        print(f"[threat_intel] Scanning IP: {origin_ip}")

        vt_ip_result     = scan_ip_virustotal(origin_ip)
        abuse_ip_result  = scan_ip_abuseipdb(origin_ip)

        ip_malicious = (
            vt_ip_result.get('malicious', False) or
            abuse_ip_result.get('abuse_confidence', 0) > 50
        )

        if ip_malicious:
            results['malicious_ip_count'] += 1
            results['iocs'].append({
                'type'              : 'malicious_ip',
                'value'             : origin_ip,
                'source'            : 'VirusTotal + AbuseIPDB',
                'abuse_confidence'  : abuse_ip_result.get('abuse_confidence', 0),
                'vt_detections'     : vt_ip_result.get('malicious_count', 0)
            })

        results['ip_results'].append({
            'ip'                : origin_ip,
            'malicious'         : ip_malicious,
            'vt_malicious_count': vt_ip_result.get('malicious_count', 0),
            'vt_harmless_count' : vt_ip_result.get('harmless_count', 0),
            'abuse_confidence'  : abuse_ip_result.get('abuse_confidence', 0),
            'country'           : abuse_ip_result.get('country', 'unknown'),
            'isp'               : abuse_ip_result.get('isp', 'unknown'),
            'domain'            : abuse_ip_result.get('domain', 'unknown'),
            'total_reports'     : abuse_ip_result.get('total_reports', 0),
            'error'             : vt_ip_result.get('error', None)
        })

    # ── Calculate overall threat score ────────────────────
    results['threat_score']       = calculate_threat_score(results)
    results['overall_malicious']  = (
        results['malicious_url_count'] > 0 or
        results['malicious_ip_count']  > 0
    )

    print(f"[threat_intel] Scan complete — "
          f"threat score: {results['threat_score']}")

    return results

