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
