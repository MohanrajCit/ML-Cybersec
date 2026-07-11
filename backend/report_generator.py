"""
Report Generator
================
Generates CSV and PDF export reports from CVE prediction data.

CSV:  Uses stdlib csv module (no extra dependencies).
PDF:  Uses fpdf2 for lightweight PDF generation.
"""

import csv
import io
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

def generate_csv(records: List[Dict]) -> str:
    """
    Generate a CSV string from prediction records.

    Args:
        records: List of prediction dicts (from CVEPredictionRecord.to_dict())

    Returns:
        CSV content as a string
    """
    output = io.StringIO()
    fieldnames = [
        "id", "cve_id", "risk_level", "confidence", "cvss_predicted",
        "anomalous", "anomaly_score", "source", "description", "created_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for rec in records:
        writer.writerow(rec)
    return output.getvalue()


# ---------------------------------------------------------------------------
# PDF Export
# ---------------------------------------------------------------------------

def generate_pdf(records: List[Dict], stats: Optional[Dict] = None) -> bytes:
    """
    Generate a branded PDF report from prediction records.

    Args:
        records: List of prediction dicts
        stats:   Optional stats dict (risk_distribution, totals, etc.)

    Returns:
        PDF file content as bytes
    """
    try:
        from fpdf import FPDF
    except ImportError:
        raise ImportError(
            "fpdf2 is required for PDF export. Install it with: pip install fpdf2"
        )

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)

    # --- Cover / Header Page ---
    pdf.add_page()
    pdf.set_fill_color(13, 17, 23)  # GitHub dark
    pdf.rect(0, 0, 210, 50, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_y(12)
    pdf.cell(0, 12, "CyberSpec", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(
        0, 8,
        "CVE Risk Assessment Report",
        new_x="LMARGIN", new_y="NEXT", align="C",
    )

    # Date
    pdf.set_y(55)
    pdf.set_text_color(100, 100, 100)
    pdf.set_font("Helvetica", "", 9)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pdf.cell(0, 6, f"Generated: {now}", new_x="LMARGIN", new_y="NEXT", align="R")
    pdf.ln(4)

    # --- Summary Section ---
    if stats:
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(34, 197, 94)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(4)

        pdf.set_font("Helvetica", "", 10)
        dist = stats.get("risk_distribution", {})
        summary_lines = [
            f"Total Predictions: {stats.get('total_predictions', len(records))}",
            f"HIGH Risk: {dist.get('HIGH', 0)}    |    MEDIUM Risk: {dist.get('MEDIUM', 0)}    |    LOW Risk: {dist.get('LOW', 0)}",
            f"Anomalies Detected: {stats.get('anomaly_count', 0)}",
            f"Average Confidence: {stats.get('avg_confidence', 0):.1%}",
        ]
        if stats.get("avg_cvss_predicted"):
            summary_lines.append(
                f"Average Predicted CVSS: {stats['avg_cvss_predicted']:.1f} / 10.0"
            )
        for line in summary_lines:
            pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(6)

    # --- Predictions Table ---
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, "Detailed Predictions", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(34, 197, 94)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    # Table header
    col_widths = [12, 30, 18, 18, 18, 18, 76]
    headers = ["#", "CVE ID", "Risk", "Conf.", "CVSS", "Anomaly", "Description"]

    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(240, 240, 240)
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 7, header, border=1, fill=True)
    pdf.ln()

    # Table rows
    pdf.set_font("Helvetica", "", 7)
    for idx, rec in enumerate(records, 1):
        # Risk color
        risk = rec.get("risk_level", "?")
        if risk == "HIGH":
            pdf.set_text_color(220, 38, 38)
        elif risk == "MEDIUM":
            pdf.set_text_color(245, 158, 11)
        else:
            pdf.set_text_color(34, 197, 94)

        row_data = [
            str(idx),
            str(rec.get("cve_id", "N/A"))[:18],
            risk,
            f"{rec.get('confidence', 0):.1%}",
            f"{rec.get('cvss_predicted', 0):.1f}" if rec.get("cvss_predicted") else "-",
            "YES" if rec.get("anomalous") else "No",
            str(rec.get("description", ""))[:50],
        ]

        for i, val in enumerate(row_data):
            pdf.cell(col_widths[i], 6, val, border=1)
        pdf.ln()
        pdf.set_text_color(0, 0, 0)

    # --- Footer ---
    pdf.ln(10)
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(
        0, 6,
        "This report was generated by CyberSpec ML-Cybersec. "
        "Predictions are ML-based estimates and should not replace professional security assessments.",
        new_x="LMARGIN", new_y="NEXT", align="C",
    )

    return pdf.output()
