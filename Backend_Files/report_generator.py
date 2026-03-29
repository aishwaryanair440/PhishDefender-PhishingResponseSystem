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
