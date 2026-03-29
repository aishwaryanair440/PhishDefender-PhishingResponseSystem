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

# ──────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────

def generate_report(
    parsed_email,
    threat_intel,
    ml_scores,
    rules_result
):
    """
    Main function called by app.py
    Generates a PDF incident report and returns the file path
    """
    # Ensure output directory exists
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)

    # Generate unique filename using timestamp
    timestamp   = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename    = f"phishing_report_{timestamp}.pdf"
    filepath    = os.path.join(REPORT_OUTPUT_DIR, filename)

    # Build document
    doc = SimpleDocTemplate(
        filepath,
        pagesize        = A4,
        rightMargin     = 1.5 * cm,
        leftMargin      = 1.5 * cm,
        topMargin       = 1.5 * cm,
        bottomMargin    = 1.5 * cm,
        title           = REPORT_TITLE,
        author          = REPORT_AUTHOR
    )

    # Build styles
    styles  = build_styles()

    # Build story (content elements)
    story   = []

    # ── Add sections in order ─────────────────────────────
    story += build_header(styles, rules_result, timestamp)
    story += build_executive_summary(styles, rules_result, parsed_email)
    story += build_email_metadata(styles, parsed_email)
    story += build_threat_score_section(styles, rules_result, ml_scores)
    story += build_ml_analysis(styles, ml_scores)
    story += build_triggered_rules(styles, rules_result)
    story += build_url_analysis(styles, threat_intel)
    story += build_ip_analysis(styles, threat_intel)
    story += build_ioc_section(styles, rules_result)
    story += build_header_analysis(styles, parsed_email)
    story += build_recommended_actions(styles, rules_result)
    story += build_footer_section(styles, timestamp)

    # Build PDF
    doc.build(story)

    print(f"[report_generator] Report saved : {filepath}")
    return filepath

