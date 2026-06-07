# ============================================================
# report_generator.py
# Generates a professional PDF incident report
# using ReportLab for detected phishing emails
# ============================================================

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)
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
    story += build_executive_summary(styles, rules_result, parsed_email, threat_intel)
    story += build_email_metadata(styles, parsed_email)
    story += build_threat_score_section(styles, rules_result, ml_scores)
    story += build_ml_analysis(styles, ml_scores)
    story += build_triggered_rules(styles, rules_result)
    story += build_url_analysis(styles, threat_intel)
    
    story += build_ip_analysis(styles, threat_intel)
    story += build_error_reporting_section(styles, threat_intel)
    story += build_ioc_section(styles, threat_intel)
    story += build_header_analysis(styles, parsed_email)
    story += build_recommended_actions(styles, rules_result)
    story += build_footer_section(styles, timestamp)

    # Build PDF
    doc.build(story)

    print(f"[report_generator] Report saved : {filepath}")
    return filepath

# ──────────────────────────────────────────────────────────
# STYLES
# ──────────────────────────────────────────────────────────

def build_styles():
    """
    Builds all custom paragraph styles used in the report
    """
    #base    = getSampleStyleSheet()
    styles  = {}

    styles['title'] = ParagraphStyle(
        'title',
        fontSize        = 22,
        fontName        = 'Helvetica-Bold',
        textColor       = WHITE,
        alignment       = TA_CENTER,
        spaceAfter      = 4
    )

    styles['subtitle'] = ParagraphStyle(
        'subtitle',
        fontSize        = 11,
        fontName        = 'Helvetica',
        textColor       = MID_GREY,
        alignment       = TA_CENTER,
        spaceAfter      = 2
    )

    styles['section_heading'] = ParagraphStyle(
        'section_heading',
        fontSize        = 13,
        fontName        = 'Helvetica-Bold',
        textColor       = DARK_BLUE,
        spaceBefore     = 14,
        spaceAfter      = 6,
        borderPad       = 4
    )

    styles['body'] = ParagraphStyle(
        'body',
        fontSize        = 9,
        fontName        = 'Helvetica',
        textColor       = MID_BLUE,
        spaceAfter      = 4,
        leading         = 14
    )

    styles['body_bold'] = ParagraphStyle(
        'body_bold',
        fontSize        = 9,
        fontName        = 'Helvetica-Bold',
        textColor       = DARK_BLUE,
        spaceAfter      = 4
    )

    styles['verdict'] = ParagraphStyle(
        'verdict',
        fontSize        = 18,
        fontName        = 'Helvetica-Bold',
        textColor       = WHITE,
        alignment       = TA_CENTER,
        spaceAfter      = 4
    )

    styles['table_header'] = ParagraphStyle(
        'table_header',
        fontSize        = 9,
        fontName        = 'Helvetica-Bold',
        textColor       = WHITE
    )

    styles['table_cell'] = ParagraphStyle(
        'table_cell',
        fontSize        = 8,
        fontName        = 'Helvetica',
        textColor       = MID_BLUE,
        leading         = 12
    )

    styles['table_cell_bold'] = ParagraphStyle(
        'table_cell_bold',
        fontSize        = 8,
        fontName        = 'Helvetica-Bold',
        textColor       = DARK_BLUE
    )

    styles['small'] = ParagraphStyle(
        'small',
        fontSize        = 7,
        fontName        = 'Helvetica',
        textColor       = MID_GREY,
        alignment       = TA_CENTER
    )

    styles['ioc_critical'] = ParagraphStyle(
        'ioc_critical',
        fontSize        = 8,
        fontName        = 'Helvetica-Bold',
        textColor       = RED
    )

    styles['ioc_high'] = ParagraphStyle(
        'ioc_high',
        fontSize        = 8,
        fontName        = 'Helvetica-Bold',
        textColor       = ORANGE
    )

    styles['ioc_info'] = ParagraphStyle(
        'ioc_info',
        fontSize        = 8,
        fontName        = 'Helvetica',
        textColor       = MID_BLUE
    )

    return styles


# ──────────────────────────────────────────────────────────
# SECTION BUILDERS
# ──────────────────────────────────────────────────────────

def build_header(styles, rules_result, timestamp):
    """
    Builds the report header with title and verdict banner
    """
    elements    = []
    verdict     = rules_result.get('verdict', 'unknown')
    score       = rules_result.get('total_score', 0)
    verdict_col = VERDICT_COLORS.get(verdict, MID_GREY)

    # Title banner
    title_data = [[
        Paragraph(REPORT_TITLE, styles['title'])
    ]]
    title_table = Table(title_data, colWidths=[17 * cm])
    title_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, -1), DARK_BLUE),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [DARK_BLUE]),
        ('TOPPADDING',  (0, 0), (-1, -1), 16),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 16),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING',(0, 0), (-1, -1), 12),
        ('ROUNDEDCORNERS', (0, 0), (-1, -1), 6)
    ]))
    elements.append(title_table)
    elements.append(Spacer(1, 0.2 * cm))

    # Subtitle with timestamp
    sub_text = (
        f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')} | "
        f"Author: {REPORT_AUTHOR} | "
        f"Classification: CONFIDENTIAL"
    )
    elements.append(Paragraph(sub_text, styles['subtitle']))
    elements.append(Spacer(1, 0.3 * cm))

    # Verdict banner
    verdict_label = verdict.upper()
    verdict_data  = [[
        Paragraph(
            f"VERDICT: {verdict_label} — Threat Score: {score}/100",
            styles['verdict']
        )
    ]]
    verdict_table = Table(verdict_data, colWidths=[17 * cm])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, -1), verdict_col),
        ('TOPPADDING',   (0, 0), (-1, -1), 14),
        ('BOTTOMPADDING',(0, 0), (-1, -1), 14),
        ('LEFTPADDING',  (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    elements.append(verdict_table)
    elements.append(Spacer(1, 0.4 * cm))

    return elements


def build_executive_summary(styles, rules_result, parsed_email, threat_intel):
    """
    Builds the executive summary section
    """
    elements = []
    elements.append(
        Paragraph('1. Executive Summary', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    summary = rules_result.get('summary', 'No summary available.')
    elements.append(Paragraph(summary, styles['body']))

    # Key stats table
    verdict     = rules_result.get('verdict', 'unknown')
    score       = rules_result.get('total_score', 0)
    rule_count  = len(rules_result.get('triggered_rules', []))
    ioc_count   = len(threat_intel.get('iocs', []))
    flag_count  = len(rules_result.get('flags', []))

    stats_data = [
        [
            Paragraph('Verdict',          styles['table_header']),
            Paragraph('Threat Score',     styles['table_header']),
            Paragraph('Rules Triggered',  styles['table_header']),
            Paragraph('IOCs Found',       styles['table_header']),
            Paragraph('Flags Raised',     styles['table_header'])
        ],
        [
            Paragraph(verdict.upper(),    styles['table_cell_bold']),
            Paragraph(f'{score}/100',     styles['table_cell_bold']),
            Paragraph(str(rule_count),    styles['table_cell']),
            Paragraph(str(ioc_count),     styles['table_cell']),
            Paragraph(str(flag_count),    styles['table_cell'])
        ]
    ]

    stats_table = Table(
        stats_data,
        colWidths=[3.4 * cm] * 5
    )
    stats_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), DARK_BLUE),
        ('BACKGROUND',    (0, 1), (-1, 1), LIGHT_GREY),
        ('GRID',          (0, 0), (-1, -1), 0.5, MID_GREY),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_email_metadata(styles, parsed_email):
    """
    Builds the email metadata section
    """
    elements = []
    elements.append(
        Paragraph('2. Email Metadata', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    sender  = parsed_email.get('sender', 'N/A')
    subject = parsed_email.get('subject', 'N/A')
    body    = parsed_email.get('body', '')
    body_preview = (body[:300] + '...') if len(body) > 300 else body

    meta_data = [
        [
            Paragraph('Field',   styles['table_header']),
            Paragraph('Value',   styles['table_header'])
        ],
        [
            Paragraph('Sender',  styles['table_cell_bold']),
            Paragraph(str(sender),  styles['table_cell'])
        ],
        [
            Paragraph('Subject', styles['table_cell_bold']),
            Paragraph(str(subject), styles['table_cell'])
        ],
        [
            Paragraph('Body Preview', styles['table_cell_bold']),
            Paragraph(str(body_preview), styles['table_cell'])
        ],
        [
            Paragraph('Body Length', styles['table_cell_bold']),
            Paragraph(f"{len(body):,} characters", styles['table_cell'])
        ],
        [
            Paragraph('URL Count', styles['table_cell_bold']),
            Paragraph(
                str(len(parsed_email.get('urls', []))),
                styles['table_cell']
            )
        ]
    ]

    meta_table = Table(
        meta_data,
        colWidths=[4 * cm, 13 * cm]
    )
    meta_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), DARK_BLUE),
        ('BACKGROUND',    (0, 1), (-1, 1), LIGHT_GREY),
        ('BACKGROUND',    (0, 3), (-1, 3), LIGHT_GREY),
        ('BACKGROUND',    (0, 5), (-1, 5), LIGHT_GREY),
        ('GRID',          (0, 0), (-1, -1), 0.5, MID_GREY),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_threat_score_section(styles, rules_result, ml_scores):
    """
    Builds the threat score breakdown section
    """
    elements = []
    elements.append(
        Paragraph('3. Threat Score Breakdown', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    breakdown   = rules_result.get('score_breakdown', {})
    total_score = rules_result.get('total_score', 0)

    score_data  = [
        [
            Paragraph('Category',       styles['table_header']),
            Paragraph('Score',          styles['table_header']),
            Paragraph('Rules Fired',    styles['table_header'])
        ]
    ]

    category_labels = {
        'headers'   : 'Email Headers',
        'urls'      : 'URL Analysis',
        'ip'        : 'IP Reputation',
        'text'      : 'Text Analysis',
        'ml'        : 'ML Models'
    }

    for key, label in category_labels.items():
        cat_data    = breakdown.get(key, {})
        cat_score   = cat_data.get('score', 0)
        cat_rules   = len(cat_data.get('rules', []))
        score_data.append([
            Paragraph(label,            styles['table_cell_bold']),
            Paragraph(str(cat_score),   styles['table_cell']),
            Paragraph(str(cat_rules),   styles['table_cell'])
        ])

    # Total row
    score_data.append([
        Paragraph('TOTAL',              styles['table_cell_bold']),
        Paragraph(f'{total_score}/100', styles['table_cell_bold']),
        Paragraph(
            str(len(rules_result.get('triggered_rules', []))),
            styles['table_cell_bold']
        )
    ])

    score_table = Table(
        score_data,
        colWidths=[8 * cm, 4 * cm, 5 * cm]
    )
    score_table.setStyle(TableStyle([
        ('BACKGROUND',      (0, 0),  (-1, 0),  DARK_BLUE),
        ('BACKGROUND',      (0, -1), (-1, -1), MID_BLUE),
        ('TEXTCOLOR',       (0, -1), (-1, -1), WHITE),
        ('ROWBACKGROUNDS',  (0, 1),  (-1, -2), [WHITE, LIGHT_GREY]),
        ('GRID',            (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('ALIGN',           (1, 0),  (-1, -1), 'CENTER'),
        ('VALIGN',          (0, 0),  (-1, -1), 'MIDDLE'),
        ('TOPPADDING',      (0, 0),  (-1, -1), 7),
        ('BOTTOMPADDING',   (0, 0),  (-1, -1), 7),
        ('LEFTPADDING',     (0, 0),  (-1, -1), 8),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_ml_analysis(styles, ml_scores):
    """
    Builds the ML model analysis section
    """
    elements = []
    elements.append(
        Paragraph('4. ML Model Analysis', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    model_info  = ml_scores.get('model_info', {})
    email_info  = model_info.get('email_model', {})
    url_info    = model_info.get('url_model', {})
    combined    = model_info.get('combined', {})

    ml_data = [
        [
            Paragraph('Model',          styles['table_header']),
            Paragraph('Probability',    styles['table_header']),
            Paragraph('Prediction',     styles['table_header']),
            Paragraph('Confidence',     styles['table_header']),
            Paragraph('Trained F1',     styles['table_header'])
        ],
        [
            Paragraph('Email Model',    styles['table_cell_bold']),
            Paragraph(
                f"{email_info.get('probability', 0):.4f}",
                styles['table_cell']
            ),
            Paragraph(
                str(email_info.get('prediction', 'N/A')),
                styles['table_cell']
            ),
            Paragraph(
                str(email_info.get('confidence', 'N/A')),
                styles['table_cell']
            ),
            Paragraph(
                str(email_info.get('trained_f1', 'N/A')),
                styles['table_cell']
            )
        ],
        [
            Paragraph('URL Model',      styles['table_cell_bold']),
            Paragraph(
                f"{url_info.get('probability', 0):.4f}",
                styles['table_cell']
            ),
            Paragraph(
                str(url_info.get('prediction', 'N/A')),
                styles['table_cell']
            ),
            Paragraph(
                str(url_info.get('confidence', 'N/A')),
                styles['table_cell']
            ),
            Paragraph(
                str(url_info.get('trained_f1', 'N/A')),
                styles['table_cell']
            )
        ],
        [
            Paragraph('Combined',       styles['table_cell_bold']),
            Paragraph(
                f"{combined.get('probability', 0):.4f}",
                styles['table_cell']
            ),
            Paragraph(
                str(combined.get('prediction', 'N/A')),
                styles['table_cell']
            ),
            Paragraph(
                str(combined.get('confidence', 'N/A')),
                styles['table_cell']
            ),
            Paragraph(
                str(combined.get('weights', 'N/A')),
                styles['table_cell']
            )
        ]
    ]

    ml_table = Table(
        ml_data,
        colWidths=[3.5 * cm, 3 * cm, 3 * cm, 3 * cm, 4.5 * cm]
    )
    ml_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0),  (-1, 0),  DARK_BLUE),
        ('ROWBACKGROUNDS',(0, 1),  (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('ALIGN',         (1, 0),  (-1, -1), 'CENTER'),
        ('VALIGN',        (0, 0),  (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0),  (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0),  (-1, -1), 7),
        ('LEFTPADDING',   (0, 0),  (-1, -1), 8),
    ]))
    elements.append(ml_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_triggered_rules(styles, rules_result):
    """
    Builds the triggered rules section
    """
    elements = []
    elements.append(
        Paragraph('5. Triggered Rules', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    triggered = rules_result.get('triggered_rules', [])

    if not triggered:
        elements.append(
            Paragraph('No rules triggered.', styles['body'])
        )
        return elements

    rules_data = [
        [
            Paragraph('Rule',           styles['table_header']),
            Paragraph('Description',    styles['table_header']),
            Paragraph('Severity',       styles['table_header']),
            Paragraph('Weight',         styles['table_header'])
        ]
    ]

    severity_colors = {
        'critical'  : RED,
        'high'      : ORANGE,
        'medium'    : colors.HexColor('#F39C12'),
        'low'       : LIGHT_BLUE
    }

    for rule in triggered:
        severity    = rule.get('severity', 'low')
        sev_color   = severity_colors.get(severity, MID_GREY)
        rules_data.append([
            Paragraph(
                rule.get('rule', ''),
                styles['table_cell_bold']
            ),
            Paragraph(
                rule.get('description', ''),
                styles['table_cell']
            ),
            Paragraph(
                severity.upper(),
                ParagraphStyle(
                    'sev',
                    fontSize    = 8,
                    fontName    = 'Helvetica-Bold',
                    textColor   = sev_color
                )
            ),
            Paragraph(
                str(rule.get('weight', 0)),
                styles['table_cell']
            )
        ])

    rules_table = Table(
        rules_data,
        colWidths=[4 * cm, 8 * cm, 2.5 * cm, 2.5 * cm]
    )
    rules_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0),  (-1, 0),  DARK_BLUE),
        ('ROWBACKGROUNDS',(0, 1),  (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('VALIGN',        (0, 0),  (-1, -1), 'TOP'),
        ('ALIGN',         (2, 0),  (-1, -1), 'CENTER'),
        ('TOPPADDING',    (0, 0),  (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0),  (-1, -1), 6),
        ('LEFTPADDING',   (0, 0),  (-1, -1), 8),
    ]))
    elements.append(rules_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_url_analysis(styles, threat_intel):
    """
    Builds the URL analysis section
    """
    elements = []
    elements.append(
        Paragraph('6. URL Analysis', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    url_results = threat_intel.get('url_results', [])

    if not url_results:
        elements.append(
            Paragraph('No URLs found in this email.', styles['body'])
        )
        return elements

    url_data = [
        [
            Paragraph('URL',            styles['table_header']),
            Paragraph('Malicious',      styles['table_header']),
            Paragraph('Detections',     styles['table_header']),
            Paragraph('Categories',     styles['table_header'])
        ]
    ]

    for result in url_results:
        url_short   = result.get('url', '')
        url_short   = (url_short[:55] + '...') \
            if len(url_short) > 55 else url_short
        is_malicious= result.get('malicious', False)
        det_ratio   = result.get('detection_ratio', '0/0')
        categories  = ', '.join(result.get('categories', [])[:2]) or 'N/A'

        url_data.append([
            Paragraph(url_short,        styles['table_cell']),
            Paragraph(
                'YES' if is_malicious else 'NO',
                ParagraphStyle(
                    'mal',
                    fontSize    = 8,
                    fontName    = 'Helvetica-Bold',
                    textColor   = RED if is_malicious else GREEN
                )
            ),
            Paragraph(det_ratio,        styles['table_cell']),
            Paragraph(categories,       styles['table_cell'])
        ])

    url_table = Table(
        url_data,
        colWidths=[7 * cm, 2.5 * cm, 3 * cm, 4.5 * cm]
    )
    url_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0),  (-1, 0),  DARK_BLUE),
        ('ROWBACKGROUNDS',(0, 1),  (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('VALIGN',        (0, 0),  (-1, -1), 'TOP'),
        ('ALIGN',         (1, 0),  (-1, -1), 'CENTER'),
        ('TOPPADDING',    (0, 0),  (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0),  (-1, -1), 6),
        ('LEFTPADDING',   (0, 0),  (-1, -1), 8),
    ]))
    elements.append(url_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_ip_analysis(styles, threat_intel):
    """
    Builds the IP analysis section
    """
    elements = []
    elements.append(
        Paragraph('7. IP Reputation Analysis', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    ip_results = threat_intel.get('ip_results', [])

    if not ip_results:
        elements.append(
            Paragraph(
                'No IP address extracted from email headers.',
                styles['body']
            )
        )
        return elements

    ip_data = [
        [
            Paragraph('IP Address',         styles['table_header']),
            Paragraph('Abuse Confidence',   styles['table_header']),
            Paragraph('VT Detections',      styles['table_header']),
            Paragraph('Country',            styles['table_header']),
            Paragraph('ISP',                styles['table_header']),
            Paragraph('Tor Node',           styles['table_header'])
        ]
    ]

    for result in ip_results:
        abuse   = result.get('abuse_confidence', 0)
        ip_data.append([
            Paragraph(
                result.get('ip', 'N/A'),
                styles['table_cell_bold']
            ),
            Paragraph(
                f"{abuse}%",
                ParagraphStyle(
                    'abuse',
                    fontSize    = 8,
                    fontName    = 'Helvetica-Bold',
                    textColor   = RED if abuse >= 75
                                  else ORANGE if abuse >= 50
                                  else GREEN
                )
            ),
            Paragraph(
                str(result.get('vt_malicious_count', 0)),
                styles['table_cell']
            ),
            Paragraph(
                result.get('country', 'N/A'),
                styles['table_cell']
            ),
            Paragraph(
                str(result.get('isp', 'N/A'))[:25],
                styles['table_cell']
            ),
            Paragraph(
                'YES' if result.get('is_tor', False) else 'NO',
                styles['table_cell']
            )
        ])

    ip_table = Table(
        ip_data,
        colWidths=[3 * cm, 3 * cm, 3 * cm, 2.5 * cm, 3.5 * cm, 2 * cm]
    )
    ip_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0),  (-1, 0),  DARK_BLUE),
        ('ROWBACKGROUNDS',(0, 1),  (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('ALIGN',         (1, 0),  (-1, -1), 'CENTER'),
        ('VALIGN',        (0, 0),  (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0),  (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0),  (-1, -1), 7),
        ('LEFTPADDING',   (0, 0),  (-1, -1), 8),
    ]))
    elements.append(ip_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements

def build_error_reporting_section(styles, threat_intel):
    elements = []

    elements.append(
        Paragraph(
            '8. Threat Intelligence Errors',
            styles['section_heading']
        )
    )

    elements.append(HRFlowable(
        width='100%',
        thickness=1,
        color=LIGHT_BLUE,
        spaceAfter=6
    ))

    errors = threat_intel.get('errors', [])

    if not errors:
        elements.append(
            Paragraph('No errors detected.', styles['body'])
        )
        return elements

    error_data = [[
        Paragraph('Source', styles['table_header']),
        Paragraph('Error Message', styles['table_header'])
    ]]

    for err in errors:
        error_data.append([
            Paragraph(
                err.get('source', 'Unknown'),
                styles['table_cell_bold']
            ),
            Paragraph(
                err.get('message', 'N/A'),
                styles['table_cell']
            )
        ])

    table = Table(
        error_data,
        colWidths=[4 * cm, 13 * cm]
    )

    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), DARK_BLUE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID', (0, 0), (-1, -1), 0.5, MID_GREY),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements
    
def build_ioc_section(styles, threat_intel):
    """
    Builds the IOC (Indicators of Compromise) section
    """
    elements = []
    elements.append(
        Paragraph('9. Indicators of Compromise (IOCs)', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    iocs = threat_intel.get('iocs', [])

    if not iocs:
        elements.append(
            Paragraph('No IOCs identified.', styles['body'])
        )
        return elements

    ioc_data = [
        [
            Paragraph('Type',       styles['table_header']),
            Paragraph('Value',      styles['table_header']),
            Paragraph('Source',     styles['table_header']),
            Paragraph('Severity',   styles['table_header']),
            Paragraph('Detail',     styles['table_header'])
        ]
    ]

    for ioc in iocs:
        severity    = ioc.get('severity', 'info')
        sev_style   = (
            styles['ioc_critical'] if severity == 'critical'
            else styles['ioc_high'] if severity == 'high'
            else styles['ioc_info']
        )
        value       = str(ioc.get('value', ''))
        value_short = (value[:50] + '...') if len(value) > 50 else value

        ioc_data.append([
            Paragraph(ioc.get('type', ''),      styles['table_cell_bold']),
            Paragraph(value_short,              styles['table_cell']),
            Paragraph(ioc.get('source', ''),    styles['table_cell']),
            Paragraph(severity.upper(),         sev_style),
            Paragraph(ioc.get('detail', ''),    styles['table_cell'])
        ])

    ioc_table = Table(
        ioc_data,
        colWidths=[3 * cm, 4.5 * cm, 3 * cm, 2 * cm, 4.5 * cm]
    )
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0),  (-1, 0),  DARK_BLUE),
        ('ROWBACKGROUNDS',(0, 1),  (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('VALIGN',        (0, 0),  (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0),  (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0),  (-1, -1), 6),
        ('LEFTPADDING',   (0, 0),  (-1, -1), 8),
    ]))
    elements.append(ioc_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_header_analysis(styles, parsed_email):
    """
    Builds the email header authentication section
    """
    elements = []
    elements.append(
        Paragraph('10. Email Header Analysis', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    headers = parsed_email.get('headers', {})

    def auth_color(result):
        if result == 'pass':
            return GREEN
        elif result == 'fail':
            return RED
        else:
            return ORANGE

    spf     = headers.get('spf',   'unknown')
    dkim    = headers.get('dkim',  'unknown')
    dmarc   = headers.get('dmarc', 'unknown')

    header_data = [
        [
            Paragraph('Check',          styles['table_header']),
            Paragraph('Result',         styles['table_header']),
            Paragraph('Detail',         styles['table_header'])
        ],
        [
            Paragraph('SPF',            styles['table_cell_bold']),
            Paragraph(
                spf.upper(),
                ParagraphStyle(
                    'spf',
                    fontSize    = 8,
                    fontName    = 'Helvetica-Bold',
                    textColor   = auth_color(spf)
                )
            ),
            Paragraph(
                'Sender Policy Framework — validates sending server',
                styles['table_cell']
            )
        ],
        [
            Paragraph('DKIM',           styles['table_cell_bold']),
            Paragraph(
                dkim.upper(),
                ParagraphStyle(
                    'dkim',
                    fontSize    = 8,
                    fontName    = 'Helvetica-Bold',
                    textColor   = auth_color(dkim)
                )
            ),
            Paragraph(
                'DomainKeys Identified Mail — validates email signature',
                styles['table_cell']
            )
        ],
        [
            Paragraph('DMARC',          styles['table_cell_bold']),
            Paragraph(
                dmarc.upper(),
                ParagraphStyle(
                    'dmarc',
                    fontSize    = 8,
                    fontName    = 'Helvetica-Bold',
                    textColor   = auth_color(dmarc)
                )
            ),
            Paragraph(
                'Domain-based Message Authentication — policy enforcement',
                styles['table_cell']
            )
        ],
        [
            Paragraph('Originating IP', styles['table_cell_bold']),
            Paragraph(
                str(headers.get('originating_ip', 'N/A')),
                styles['table_cell']
            ),
            Paragraph(
                'IP extracted from Received header chain',
                styles['table_cell']
            )
        ],
        [
            Paragraph('Reply-To Match', styles['table_cell_bold']),
            Paragraph(
                'MISMATCH' if headers.get('reply_to_mismatch') else 'MATCH',
                ParagraphStyle(
                    'reply',
                    fontSize    = 8,
                    fontName    = 'Helvetica-Bold',
                    textColor   = RED if headers.get('reply_to_mismatch')
                                  else GREEN
                )
            ),
            Paragraph(
                str(headers.get('reply_to', 'N/A')),
                styles['table_cell']
            )
        ]
    ]

    header_table = Table(
        header_data,
        colWidths=[4 * cm, 3 * cm, 10 * cm]
    )
    header_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0),  (-1, 0),  DARK_BLUE),
        ('ROWBACKGROUNDS',(0, 1),  (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('VALIGN',        (0, 0),  (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0),  (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0),  (-1, -1), 7),
        ('LEFTPADDING',   (0, 0),  (-1, -1), 8),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_recommended_actions(styles, rules_result):
    """
    Builds the recommended actions section
    """
    elements = []
    elements.append(
        Paragraph('11. Recommended Actions', styles['section_heading'])
    )
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=LIGHT_BLUE, spaceAfter=6
    ))

    actions = rules_result.get('actions', [])

    if not actions:
        elements.append(
            Paragraph('No actions recommended.', styles['body'])
        )
        return elements

    action_data = [
        [
            Paragraph('#',          styles['table_header']),
            Paragraph('Action',     styles['table_header'])
        ]
    ]

    for i, action in enumerate(actions, 1):
        action_data.append([
            Paragraph(str(i),       styles['table_cell_bold']),
            Paragraph(action,       styles['table_cell'])
        ])

    action_table = Table(
        action_data,
        colWidths=[1.5 * cm, 15.5 * cm]
    )
    action_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0),  (-1, 0),  DARK_BLUE),
        ('ROWBACKGROUNDS',(0, 1),  (-1, -1), [WHITE, LIGHT_GREY]),
        ('GRID',          (0, 0),  (-1, -1), 0.5, MID_GREY),
        ('VALIGN',        (0, 0),  (-1, -1), 'MIDDLE'),
        ('ALIGN',         (0, 0),  (0,  -1), 'CENTER'),
        ('TOPPADDING',    (0, 0),  (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0),  (-1, -1), 7),
        ('LEFTPADDING',   (0, 0),  (-1, -1), 8),
    ]))
    elements.append(action_table)
    elements.append(Spacer(1, 0.3 * cm))

    return elements


def build_footer_section(styles, timestamp):
    """
    Builds the report footer
    """
    elements = []
    elements.append(Spacer(1, 0.5 * cm))
    elements.append(HRFlowable(
        width='100%', thickness=1,
        color=MID_GREY, spaceAfter=6
    ))

    footer_text = (
        f"This report was automatically generated by the "
        f"Phishing Detector platform on "
        f"{datetime.now().strftime('%B %d, %Y at %H:%M:%S')}. "
        f"This document is confidential and intended for "
        f"security personnel only. "
        f"Report ID: PHI-{timestamp}"
    )
    elements.append(Paragraph(footer_text, styles['small']))

    return elements
