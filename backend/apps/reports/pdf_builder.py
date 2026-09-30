"""Builds the PDF security report using ReportLab, from the same payload
dict produced by services.build_report_payload (so JSON and PDF reports
always stay in sync)."""
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#b91c1c"),
    "MEDIUM": colors.HexColor("#b45309"),
    "LOW": colors.HexColor("#0f766e"),
    "INFO": colors.HexColor("#374151"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1Custom", parent=styles["Heading1"], textColor=colors.HexColor("#111827")))
    styles.add(ParagraphStyle(name="H2Custom", parent=styles["Heading2"], textColor=colors.HexColor("#1f2937"), spaceBefore=14))
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["BodyText"], fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="Mono", parent=styles["BodyText"], fontName="Courier", fontSize=8, leading=10))
    return styles


def _text(value, limit=None):
    raw = "-" if value is None or value == "" else str(value)
    if limit:
        raw = raw[:limit]
    return xml_escape(raw)


def _p(value, style, limit=None):
    return Paragraph(_text(value, limit), style)


def _finding_table(findings, styles):
    if not findings:
        return Paragraph("None found.", styles["BodySmall"])
    data = [["Title", "File", "Line", "Category", "Scanner"]]
    for f in findings[:100]:
        data.append([
            _p(f.get("title"), styles["BodySmall"], 80),
            _p(f.get("file_path") or "-", styles["BodySmall"], 60),
            str(f.get("line_start") or "-"),
            _text(f.get("category", "-")),
            _text(f.get("scanner", "-")),
        ])
    table = Table(data, colWidths=[2.2 * inch, 2.0 * inch, 0.5 * inch, 1.2 * inch, 1.0 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]))
    return table


def build_pdf_report(payload: dict, output_path: str):
    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    story = []

    meta = payload["report_metadata"]
    proj = payload["project_information"]
    scan = payload["scan_information"]
    summary = payload["executive_summary"]

    story.append(Paragraph("Security Scan Report", styles["H1Custom"]))
    story.append(_p(f"Project: {proj['name']}", styles["Normal"]))
    story.append(_p(f"Generated: {meta['generated_at']}", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("1. Executive Summary", styles["H2Custom"]))
    story.append(_p(summary["summary_text"], styles["BodySmall"]))
    story.append(Spacer(1, 0.15 * inch))

    score = payload["security_score"]["value"]
    score_label = "-" if score is None else score
    story.append(Paragraph(f"<b>Security Score: {_text(score_label)}/100</b>", styles["Normal"]))
    story.append(Spacer(1, 0.1 * inch))

    vsum = payload["vulnerability_summary"]
    score_table = Table(
        [["Critical", "High", "Medium", "Low", "Info"],
         [vsum.get("CRITICAL", 0), vsum.get("HIGH", 0), vsum.get("MEDIUM", 0), vsum.get("LOW", 0), vsum.get("INFO", 0)]],
        colWidths=[1.3 * inch] * 5,
    )
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(score_table)

    story.append(Paragraph("2. Project Information", styles["H2Custom"]))
    for label, value in [("Name", proj["name"]), ("Description", proj["description"] or "-"),
                          ("Language", proj["language"] or "-"), ("Default Branch", proj["default_branch"])]:
        story.append(Paragraph(f"<b>{label}:</b> {_text(value)}", styles["BodySmall"]))

    story.append(Paragraph("3. Scan Information", styles["H2Custom"]))
    for label, value in [("Scan Type", scan["scan_type"]), ("Status", scan["status"]),
                          ("Files Scanned", scan["total_files"]), ("Duration (s)", scan["duration_seconds"])]:
        story.append(Paragraph(f"<b>{label}:</b> {_text(value)}", styles["BodySmall"]))

    story.append(PageBreak())
    story.append(Paragraph("4. Critical Findings", styles["H2Custom"]))
    story.append(_finding_table(payload["critical_findings"], styles))
    story.append(Paragraph("5. High Findings", styles["H2Custom"]))
    story.append(_finding_table(payload["high_findings"], styles))
    story.append(Paragraph("6. Medium Findings", styles["H2Custom"]))
    story.append(_finding_table(payload["medium_findings"], styles))
    story.append(Paragraph("7. Low Findings", styles["H2Custom"]))
    story.append(_finding_table(payload["low_findings"], styles))

    story.append(PageBreak())
    story.append(Paragraph("8. Secret Findings", styles["H2Custom"]))
    if payload["secret_findings"]:
        data = [["Type", "File", "Line", "Masked Value", "Severity"]]
        for s in payload["secret_findings"][:100]:
            data.append([
                _p(s.get("secret_type"), styles["BodySmall"], 40),
                _p(s.get("file_path") or "-", styles["BodySmall"], 40),
                str(s.get("line_number") or "-"),
                _p(s.get("masked_value"), styles["BodySmall"], 30),
                _text(s.get("severity")),
            ])
        t = Table(data, colWidths=[1.4 * inch, 1.8 * inch, 0.5 * inch, 1.7 * inch, 0.8 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No secrets detected.", styles["BodySmall"]))

    story.append(Paragraph("9. Dependency Findings", styles["H2Custom"]))
    if payload["dependency_findings"]:
        data = [["Package", "Version", "Ecosystem", "Vulnerability", "Severity", "Fixed Version"]]
        for d in payload["dependency_findings"][:100]:
            data.append([
                _p(d.get("package_name"), styles["BodySmall"], 25),
                _text(d.get("version"), 15),
                _text(d.get("ecosystem")),
                _text(d.get("vulnerability_id"), 20),
                _text(d.get("severity") or "-"),
                _text(d.get("fixed_version") or "-"),
            ])
        t = Table(data, colWidths=[1.3 * inch, 0.8 * inch, 0.8 * inch, 1.3 * inch, 0.7 * inch, 1.1 * inch], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No vulnerable dependencies detected.", styles["BodySmall"]))

    story.append(Paragraph("10. Infrastructure-as-Code Findings", styles["H2Custom"]))
    story.append(_finding_table(payload["iac_findings"], styles))
    story.append(Paragraph("11. Container Findings", styles["H2Custom"]))
    story.append(_finding_table(payload["container_findings"], styles))

    story.append(PageBreak())
    story.append(Paragraph("12. Remediation Recommendations", styles["H2Custom"]))
    if payload["remediation_recommendations"]:
        items = [
            ListItem(Paragraph(
                f"<b>[{_text(r.get('severity'))}] {_text(r.get('title'))}:</b> {_text(r.get('remediation'))}",
                styles["BodySmall"],
            ))
            for r in payload["remediation_recommendations"]
        ]
        story.append(ListFlowable(items, bulletType="bullet"))
    else:
        story.append(Paragraph("No specific remediation items to highlight.", styles["BodySmall"]))

    story.append(Paragraph("13. Scanner Information", styles["H2Custom"]))
    sdata = [["Scanner", "Status", "Findings", "Duration (s)"]]
    for s in payload["scanner_information"]:
        sdata.append([
            _text(s.get("scanner_name")),
            _text(s.get("status")),
            s.get("findings_count") if s.get("findings_count") is not None else "-",
            s.get("duration_seconds") if s.get("duration_seconds") is not None else "-",
        ])
    st = Table(sdata, colWidths=[1.8 * inch, 1.6 * inch, 1.2 * inch, 1.4 * inch], repeatRows=1)
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
    ]))
    story.append(st)

    story.append(Paragraph("14. Scan Statistics", styles["H2Custom"]))
    stats = payload["scan_statistics"]
    for label, value in stats.items():
        story.append(Paragraph(
            f"<b>{_text(label.replace('_', ' ').title())}:</b> {_text(value)}",
            styles["BodySmall"],
        ))

    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(
        "This report was generated by an automated defensive security scanning platform. "
        "Automated analysis cannot guarantee the detection of every vulnerability; it should "
        "complement, not replace, manual security review for high-risk systems.",
        styles["BodySmall"],
    ))

    doc.build(story)
