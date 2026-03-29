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

