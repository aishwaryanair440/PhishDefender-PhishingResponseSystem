# ============================================================
# app.py
# Flask backend server — main entry point
# Receives email data from browser extension
# Orchestrates all modules and returns unified result
# ============================================================

import os
import json
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from config import (
    FLASK_HOST,
    FLASK_PORT,
    FLASK_DEBUG,
    THRESHOLD_MALICIOUS,
    THRESHOLD_SUSPICIOUS,
    REPORT_OUTPUT_DIR
)
from email_parser      import parse_email
from threat_intel      import run_threat_intelligence
from ml_classifier     import run_ml_classifier, load_models
from rules_engine      import run_rules_engine
from report_generator  import generate_report

# ──────────────────────────────────────────────────────────
# APP INITIALIZATION
# ──────────────────────────────────────────────────────────

app = Flask(__name__)

# Allow requests from Chrome extension
CORS(app, resources={
    r"/*": {
        "origins": [
            "chrome-extension://*",
            "http://localhost:*",
            "http://127.0.0.1:*"
        ]
    }
})

# ──────────────────────────────────────────────────────────
# LOAD MODELS ON STARTUP
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("Phishing Detector — Backend Server")
print("=" * 55)

try:
    load_models()
    print("[app] Models loaded successfully")
except Exception as e:
    print(f"[app] CRITICAL — Model loading failed: {e}")
    raise

# ──────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────

@app.route('/ping', methods=['GET'])
def ping():
    """
    Health check endpoint
    Called by extension on startup to confirm server is running
    """
    return jsonify({
        'status'    : 'ok',
        'message'   : 'Phishing Detector backend is running',
        'timestamp' : datetime.now().isoformat()
    }), 200


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Main analysis endpoint
    Called by background.js with raw email data
    Runs full pipeline and returns unified threat result
    """
    print("\n" + "=" * 55)
    print(f"[app] /analyze called at {datetime.now().strftime('%H:%M:%S')}")

    # ── Validate request ──────────────────────────────────
    if not request.is_json:
        return jsonify({
            'error': 'Request must be JSON'
        }), 400

    data = request.get_json()

    if not data:
        return jsonify({
            'error': 'Empty request body'
        }), 400

    # ── Validate required fields ──────────────────────────
    required = ['subject', 'body']
    missing  = [f for f in required if f not in data]
    if missing:
        return jsonify({
            'error'  : f'Missing required fields: {missing}',
            'fields' : missing
        }), 400

    try:
        # ── Step 1: Parse email ───────────────────────────
        print("[app] Step 1 — Parsing email...")
        parsed_email = parse_email(data)
        print(f"  Sender  : {parsed_email.get('sender', 'N/A')}")
        print(f"  Subject : {parsed_email.get('subject', '')[:60]}")
        print(f"  URLs    : {len(parsed_email.get('urls', []))}")
        print(f"  Flags   : {len(parsed_email.get('flags', []))}")

        # ── Step 2: Run ML classifier ─────────────────────
        print("[app] Step 2 — Running ML classifier...")
        ml_scores = run_ml_classifier(parsed_email)
        print(
            f"  Email prob  : {ml_scores['email_phishing_probability']:.4f}"
        )
        print(
            f"  URL prob    : {ml_scores['url_phishing_probability']:.4f}"
        )
        print(
            f"  Combined    : {ml_scores['combined_probability']:.4f}"
        )

        # ── Step 3: Run threat intelligence ──────────────
        print("[app] Step 3 — Running threat intelligence...")
        threat_intel = run_threat_intelligence(parsed_email)
        print(
            f"  Malicious URLs : {threat_intel['malicious_url_count']}"
        )
        print(
            f"  Malicious IPs  : {threat_intel['malicious_ip_count']}"
        )
        print(
            f"  IOCs found     : {len(threat_intel.get('iocs', []))}"
        )

        # ── Step 4: Run rules engine ──────────────────────
        print("[app] Step 4 — Running rules engine...")
        rules_result = run_rules_engine(
            parsed_email,
            threat_intel,
            ml_scores
        )
        print(f"  Verdict     : {rules_result['verdict'].upper()}")
        print(f"  Score       : {rules_result['total_score']}/100")
        print(
            f"  Rules fired : "
            f"{len(rules_result['triggered_rules'])}"
        )

        # ── Step 5: Generate report if malicious ─────────
        report_path = None
        if rules_result['verdict'] in ('malicious', 'suspicious'):
            print("[app] Step 5 — Generating incident report...")
            try:
                report_path = generate_report(
                    parsed_email,
                    threat_intel,
                    ml_scores,
                    rules_result
                )
                print(f"  Report saved : {report_path}")
            except Exception as report_err:
                print(f"  Report error : {report_err}")
                report_path = None

        # ── Build response ────────────────────────────────
        response = build_response(
            parsed_email,
            ml_scores,
            threat_intel,
            rules_result,
            report_path
        )

        print(f"[app] Analysis complete — {rules_result['verdict'].upper()}")
        print("=" * 55)

        return jsonify(response), 200

    except Exception as e:
        print(f"[app] ERROR during analysis: {e}")
        traceback.print_exc()
        return jsonify({
            'error'     : 'Internal server error during analysis',
            'detail'    : str(e)
        }), 500


@app.route('/report/<filename>', methods=['GET'])
def download_report(filename):
    """
    Report download endpoint
    Called by extension popup to download PDF report
    """
    # Sanitize filename — prevent path traversal
    filename    = os.path.basename(filename)
    report_path = os.path.join(REPORT_OUTPUT_DIR, filename)

    if not os.path.exists(report_path):
        return jsonify({
            'error': f'Report not found: {filename}'
        }), 404

    try:
        return send_file(
            report_path,
            mimetype        = 'application/pdf',
            as_attachment   = True,
            download_name   = filename
        )
    except Exception as e:
        return jsonify({
            'error': f'Failed to serve report: {str(e)}'
        }), 500


@app.route('/reports', methods=['GET'])
def list_reports():
    """
    Lists all generated reports
    Called by extension popup to show report history
    """
    try:
        if not os.path.exists(REPORT_OUTPUT_DIR):
            return jsonify({'reports': []}), 200

        reports = []
        for fname in sorted(
            os.listdir(REPORT_OUTPUT_DIR),
            reverse=True
        ):
            if fname.endswith('.pdf'):
                fpath = os.path.join(REPORT_OUTPUT_DIR, fname)
                fsize = os.path.getsize(fpath)
                reports.append({
                    'filename'  : fname,
                    'size_kb'   : round(fsize / 1024, 1),
                    'created'   : datetime.fromtimestamp(
                        os.path.getctime(fpath)
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    'download_url': f'/report/{fname}'
                })

        return jsonify({'reports': reports}), 200

    except Exception as e:
        return jsonify({
            'error': f'Failed to list reports: {str(e)}'
        }), 500


@app.route('/status', methods=['GET'])
def status():
    """
    Detailed status endpoint
    Returns server status and model info
    """
    return jsonify({
        'status'        : 'running',
        'timestamp'     : datetime.now().isoformat(),
        'models_loaded' : True,
        'endpoints'     : [
            'GET  /ping',
            'POST /analyze',
            'GET  /report/<filename>',
            'GET  /reports',
            'GET  /status'
        ],
        'thresholds'    : {
            'malicious' : THRESHOLD_MALICIOUS,
            'suspicious': THRESHOLD_SUSPICIOUS
        },
        'reports_dir'   : REPORT_OUTPUT_DIR
    }), 200



# Ensure reports directory exists
os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
print(f"[app] Reports directory ready : {REPORT_OUTPUT_DIR}")
print(f"[app] Server starting on      : http://{FLASK_HOST}:{FLASK_PORT}")
print("=" * 55)
