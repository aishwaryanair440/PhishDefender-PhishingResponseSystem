# ============================================================
# report_generator.py
# Generates a professional PDF incident report
# using ReportLab for detected phishing emails
# ============================================================

import os
import json
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    PageBreak
)
from reportlab.platypus.flowables import KeepTogether
from config import (
    REPORT_OUTPUT_DIR,
    REPORT_TITLE,
    REPORT_AUTHOR
)

# ──────────────────────────────────────────────────────────
# COLOUR PALETTE
# ──────────────────────────────────────────────────────────

RED         = colors.HexColor('#C0392B')
ORANGE      = colors.HexColor('#E67E22')
GREEN       = colors.HexColor('#27AE60')
DARK_BLUE   = colors.HexColor('#1A252F')
MID_BLUE    = colors.HexColor('#2C3E50')
LIGHT_BLUE  = colors.HexColor('#2980B9')
LIGHT_GREY  = colors.HexColor('#F2F3F4')
MID_GREY    = colors.HexColor('#BDC3C7')
WHITE       = colors.white
BLACK       = colors.black

VERDICT_COLORS = {
    'malicious' : RED,
    'suspicious': ORANGE,
    'benign'    : GREEN
}
