"""
Report Generation Module
Produces downloadable forensic CSV summaries and executive PDF threat intelligence reports
using ReportLab with MITRE ATT&CK alignments, evaluation metrics, and cybersecurity disclaimers.
"""

import os
import io
from datetime import datetime
from typing import Dict, Any, Optional
import pandas as pd

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def export_analysis_csv(enriched_df: pd.DataFrame) -> bytes:
    """Export enriched DataFrame with cyber intelligence columns to CSV bytes."""
    buffer = io.BytesIO()
    enriched_df.to_csv(buffer, index=False, encoding='utf-8')
    buffer.seek(0)
    return buffer.getvalue()


def generate_pdf_threat_report(
    dataset_name: str,
    model_bundle: Dict[str, Any],
    inference_summary: Dict[str, Any],
    threat_summary: Dict[str, Any]
) -> bytes:
    """
    Generate professional executive PDF report using ReportLab.
    
    Includes:
    - Executive Threat Summary
    - Dataset Analysis Details
    - Machine Learning Validation Metrics
    - Traffic Classification & Anomaly Breakdown
    - MITRE ATT&CK Mapping Matrix
    - Forensic Evidence & Prediction Disclaimer
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom Cyber Styles
    title_style = ParagraphStyle(
        'CyberTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'CyberSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15
    )

    section_heading = ParagraphStyle(
        'CyberSection',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0284C7'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'CyberBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1E293B')
    )

    disclaimer_style = ParagraphStyle(
        'CyberDisclaimer',
        parent=styles['Italic'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748B')
    )

    story = []

    # Document Header
    story.append(Paragraph("CYBER THREAT INTELLIGENCE & ATTACK PATTERN DISCOVERY", title_style))
    analysis_date = datetime.now().strftime("%B %d, %Y - %H:%M:%S UTC")
    story.append(Paragraph(f"<b>Automated Defense Analysis Report</b> | Generated: {analysis_date} | Source: {dataset_name}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceAfter=12))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Threat Briefing", section_heading))
    exec_summary_text = threat_summary.get("executive_summary", "Traffic flow analysis completed.")
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 10))

    # Key KPI Table
    total_rec = inference_summary.get("total_records", 0)
    normal_cnt = inference_summary.get("normal_count", 0)
    susp_cnt = inference_summary.get("suspicious_count", 0)
    anom_cnt = inference_summary.get("anomaly_count", 0)
    susp_pct = inference_summary.get("suspicious_percentage", 0.0)

    kpi_data = [
        ["Total Analyzed Flows", "Baseline Normal Flows", "Potentially Suspicious", "Statistical Anomalies", "Suspicious %"],
        [f"{total_rec:,}", f"{normal_cnt:,}", f"{susp_cnt:,}", f"{anom_cnt:,}", f"{susp_pct:.1f}%"]
    ]
    kpi_table = Table(kpi_data, colWidths=[110, 110, 110, 110, 90])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8.5),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#F8FAFC')),
        ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor('#DC2626')),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, 1), 11),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94A3B8')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 12))

    # 2. Machine Learning Validation & Metrics
    story.append(Paragraph("2. Machine Learning Model Specifications & Validated Metrics", section_heading))
    metrics = model_bundle.get("metrics", {})
    model_type = model_bundle.get("model_type", "Random Forest Classifier")
    
    ml_data = [
        ["Model Architecture", "Accuracy", "Precision (Macro)", "Recall (Macro)", "F1-Score (Macro)"],
        [
            model_type,
            f"{metrics.get('accuracy', 0.0):.4f}",
            f"{metrics.get('precision_macro', 0.0):.4f}",
            f"{metrics.get('recall_macro', 0.0):.4f}",
            f"{metrics.get('f1_macro', 0.0):.4f}"
        ]
    ]
    ml_table = Table(ml_data, colWidths=[150, 95, 95, 95, 95])
    ml_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8.5),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#F1F5F9')),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, 1), 9),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94A3B8')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ml_table)
    story.append(Spacer(1, 12))

    # 3. Discovered Threat Vectors & MITRE ATT&CK Mapping
    story.append(Paragraph("3. Discovered Attack Patterns & MITRE ATT&CK Alignment", section_heading))
    detected = threat_summary.get("detected_attacks", [])
    
    if detected:
        attack_rows = [["Detected Threat Pattern", "Flow Count", "Traffic %", "MITRE ID", "Technique Name", "Tactic"]]
        for a in detected:
            attack_rows.append([
                a.get("attack_type", "Unknown"),
                f"{a.get('count', 0):,}",
                f"{a.get('percentage', 0):.1f}%",
                a.get("mitre_id", "T1000"),
                a.get("mitre_technique", "Unknown"),
                a.get("mitre_tactic", "Unknown")
            ])
        att_table = Table(attack_rows, colWidths=[110, 60, 50, 65, 150, 95])
        att_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0369A1')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('ALIGN', (1, 0), (2, -1), 'CENTER'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#94A3B8')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(att_table)
    else:
        story.append(Paragraph("No confirmed attack pattern classes identified in current dataset.", body_style))
        
    story.append(Spacer(1, 15))

    # 4. Forensic Disclaimer & Limitations
    story.append(Paragraph("4. Academic & Forensic Integrity Notice", section_heading))
    disclaimer_text = (
        "<b>LEGAL & FORENSIC DISCLAIMER:</b> All classifications, confidence scores, and anomaly ratings "
        "presented in this report are probabilistic outputs generated by Machine Learning models. "
        "Outputs are labeled as <i>'Model Prediction'</i> and <i>'Potentially Suspicious'</i>. These results "
        "do not represent definitive proof of malicious compromise or intentional intrusion without secondary "
        "corroboration through full packet inspection (PCAP), endpoint logs, and qualified cybersecurity analyst triage."
    )
    story.append(Paragraph(disclaimer_text, disclaimer_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
