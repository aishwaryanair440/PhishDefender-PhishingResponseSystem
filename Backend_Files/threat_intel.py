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

# ──────────────────────────────────────────────────────────
# VIRUSTOTAL — URL SCANNING
# ──────────────────────────────────────────────────────────

def scan_url_virustotal(url):
    """
    Submits a URL to VirusTotal for analysis
    Returns malicious status and detection counts
    """
    headers = {
        'x-apikey'    : VIRUSTOTAL_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    for attempt in range(RETRY_ATTEMPTS):
        try:
            # Step 1 — Submit URL for scanning
            response = requests.post(
                VIRUSTOTAL_URL_SCAN,
                headers = headers,
                data    = {'url': url},
                timeout = REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                scan_data = response.json()
                url_id    = scan_data.get('data', {}).get('id', '')

                if url_id:
                    # Step 2 — Retrieve analysis results
                    return get_virustotal_analysis(url_id, headers)

            elif response.status_code == 429:
                # Rate limit hit — wait and retry
                print(f"[threat_intel] VT rate limit hit, waiting 60s...")
                time.sleep(60)
                continue

            else:
                return _vt_error(f"HTTP {response.status_code}")

        except requests.exceptions.Timeout:
            return _vt_error("Request timed out")
        except requests.exceptions.ConnectionError:
            return _vt_error("Connection error")
        except Exception as e:
            return _vt_error(str(e))

    return _vt_error("Max retries exceeded")


def get_virustotal_analysis(analysis_id, headers):
    """
    Polls VirusTotal analysis endpoint for results
    Waits for analysis to complete
    """
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for attempt in range(RETRY_ATTEMPTS):
        try:
            # Wait for analysis to complete
            time.sleep(5)

            response = requests.get(
                analysis_url,
                headers = headers,
                timeout = REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                data       = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                status     = attributes.get('status', '')

                # If still queued wait longer
                if status == 'queued':
                    time.sleep(10)
                    continue

                stats = attributes.get('stats', {})
                return parse_vt_stats(stats, attributes)

            else:
                return _vt_error(f"Analysis HTTP {response.status_code}")

        except Exception as e:
            return _vt_error(str(e))

    return _vt_error("Analysis polling failed")

# ──────────────────────────────────────────────────────────
# VIRUSTOTAL — IP SCANNING
# ──────────────────────────────────────────────────────────

def scan_ip_virustotal(ip):
    """
    Queries VirusTotal for IP reputation
    Returns malicious status and detection counts
    """
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    url     = f"{VIRUSTOTAL_IP_SCAN}/{ip}"

    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.get(
                url,
                headers = headers,
                timeout = REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                data       = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats      = attributes.get('last_analysis_stats', {})
                return parse_vt_stats(stats, attributes)

            elif response.status_code == 429:
                print(f"[threat_intel] VT IP rate limit, waiting 60s...")
                time.sleep(60)
                continue

            elif response.status_code == 404:
                return _vt_error("IP not found in VirusTotal database")

            else:
                return _vt_error(f"HTTP {response.status_code}")

        except requests.exceptions.Timeout:
            return _vt_error("Request timed out")
        except requests.exceptions.ConnectionError:
            return _vt_error("Connection error")
        except Exception as e:
            return _vt_error(str(e))

    return _vt_error("Max retries exceeded")

# ──────────────────────────────────────────────────────────
# ABUSEIPDB — IP SCANNING
# ──────────────────────────────────────────────────────────

def scan_ip_abuseipdb(ip):
    """
    Queries AbuseIPDB for IP abuse confidence score
    Returns abuse confidence percentage and metadata
    """
    headers = {
        'Key'   : ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }
    params  = {
        'ipAddress'     : ip,
        'maxAgeInDays'  : 90,
        'verbose'       : True
    }

    for attempt in range(RETRY_ATTEMPTS):
        try:
            response = requests.get(
                ABUSEIPDB_URL,
                headers = headers,
                params  = params,
                timeout = REQUEST_TIMEOUT
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'abuse_confidence': data.get('abuseConfidenceScore', 0),
                    'country'         : data.get('countryCode', 'unknown'),
                    'isp'             : data.get('isp', 'unknown'),
                    'domain'          : data.get('domain', 'unknown'),
                    'total_reports'   : data.get('totalReports', 0),
                    'last_reported'   : data.get('lastReportedAt', None),
                    'is_tor'          : data.get('isTor', False),
                    'error'           : None
                }

            elif response.status_code == 429:
                print(f"[threat_intel] AbuseIPDB rate limit, waiting 60s...")
                time.sleep(60)
                continue

            elif response.status_code == 422:
                return _abuse_error("Invalid IP address format")

            else:
                return _abuse_error(f"HTTP {response.status_code}")

        except requests.exceptions.Timeout:
            return _abuse_error("Request timed out")
        except requests.exceptions.ConnectionError:
            return _abuse_error("Connection error")
        except Exception as e:
            return _abuse_error(str(e))

    return _abuse_error("Max retries exceeded")
