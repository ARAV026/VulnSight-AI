from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from models import ScanResult


def build_pdf_report(result: ScanResult, buffer: BytesIO) -> None:
    doc = SimpleDocTemplate(buffer, pagesize=A4, title="VulnSight AI Report")
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("VulnSight AI Security Assessment", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"Target: {result.target_url}", styles["BodyText"]))
    elements.append(Paragraph(f"Scan ID: {result.scan_id}", styles["BodyText"]))
    elements.append(Paragraph(f"Profile: {result.profile}", styles["BodyText"]))
    elements.append(Paragraph(f"Engine: {result.engine}", styles["BodyText"]))
    elements.append(Paragraph(f"Status: {result.status}", styles["BodyText"]))
    elements.append(Spacer(1, 16))

    if result.analysis is None:
        elements.append(Paragraph("Analysis data is not yet available for this scan.", styles["BodyText"]))
        doc.build(elements)
        return

    summary = result.analysis.summary
    summary_data = [
        ["Metric", "Value"],
        ["Security Score", str(summary.score)],
        ["Total Findings", str(summary.total_findings)],
        ["Exploitability", str(summary.exploitability)],
        ["False Positive Risk", str(summary.false_positive_risk)],
        ["Attack Surface", str(summary.attack_surface)],
    ]
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12263f")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
            ]
        )
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    attack_surface = result.analysis.attack_surface_summary
    attack_data = [
        ["SQLi Attack Surface", "Value"],
        ["Risky Parameters", ", ".join(attack_surface.risky_parameters[:8]) or "None"],
        ["Forms Discovered", str(attack_surface.forms_discovered)],
        ["GET Forms", str(attack_surface.get_forms)],
        [
            "Top Parameter Anomalies",
            "; ".join(f"{item.parameter}:{item.anomaly_score}" for item in attack_surface.anomaly_observations[:5]) or "None",
        ],
    ]
    attack_table = Table(attack_data, hAlign="LEFT")
    attack_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b4332")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f2fbf6")),
            ]
        )
    )
    elements.append(Paragraph("SQL Injection Attack Surface", styles["Heading2"]))
    elements.append(attack_table)
    elements.append(Spacer(1, 16))

    if result.analysis.technologies:
        elements.append(Paragraph("Technology Fingerprints", styles["Heading2"]))
        for tech in result.analysis.technologies:
            elements.append(Paragraph(f"<b>{tech.name}</b> ({tech.category})", styles["BodyText"]))
            elements.append(Paragraph(f"Evidence: {tech.evidence}", styles["BodyText"]))
            elements.append(Paragraph(f"Hardening: {tech.hardening_advice}", styles["BodyText"]))
            elements.append(Spacer(1, 8))

    elements.append(Paragraph("Findings", styles["Heading2"]))
    for finding in result.findings:
        elements.append(Paragraph(f"<b>{finding.title}</b> [{finding.severity.upper()}] - {finding.endpoint}", styles["BodyText"]))
        elements.append(Paragraph(finding.description, styles["BodyText"]))
        elements.append(Paragraph(f"Evidence: {finding.evidence}", styles["BodyText"]))
        elements.append(Paragraph(f"Remediation: {finding.remediation}", styles["BodyText"]))
        elements.append(Spacer(1, 10))

    elements.append(Paragraph("Recommendations", styles["Heading2"]))
    for item in result.analysis.recommendations:
        elements.append(Paragraph(f"{item.priority.upper()}: {item.title}", styles["BodyText"]))
        elements.append(Paragraph(item.action, styles["BodyText"]))
        elements.append(Spacer(1, 8))

    elements.append(Paragraph("AI Detection Summary", styles["Heading2"]))
    elements.append(Paragraph(f"Model Version: {result.analysis.ai_summary.model_version}", styles["BodyText"]))
    elements.append(Paragraph(f"Precision: {result.analysis.ai_summary.precision}", styles["BodyText"]))
    elements.append(Paragraph(f"Recall: {result.analysis.ai_summary.recall}", styles["BodyText"]))
    elements.append(Paragraph(f"F1 Score: {result.analysis.ai_summary.f1_score}", styles["BodyText"]))
    elements.append(Paragraph(f"Confidence Threshold: {result.analysis.ai_summary.threshold}", styles["BodyText"]))
    elements.append(Paragraph(f"High-Confidence Findings: {result.analysis.ai_summary.high_confidence_findings}", styles["BodyText"]))
    for note in result.analysis.ai_summary.notes[:6]:
        elements.append(Paragraph(f"- {note}", styles["BodyText"]))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("Remediation Status", styles["Heading2"]))
    for item in result.analysis.remediation_status:
        elements.append(Paragraph(f"{item.area} [{item.status}]", styles["BodyText"]))
        elements.append(Paragraph(item.note, styles["BodyText"]))
        elements.append(Spacer(1, 8))

    if result.analysis.page_risk_map:
        elements.append(Paragraph("Per-Page Risk Map", styles["Heading2"]))
        for page in result.analysis.page_risk_map[:10]:
            elements.append(Paragraph(f"{page.url}", styles["BodyText"]))
            elements.append(Paragraph(f"Status {page.status_code} | Risk {page.risk_score} | Forms {page.forms}", styles["BodyText"]))
            elements.append(Paragraph(f"Parameters: {', '.join(page.risky_parameters) or 'None'}", styles["BodyText"]))
            elements.append(Spacer(1, 6))

    if result.analysis.assets:
        elements.append(Paragraph("Asset Inventory", styles["Heading2"]))
        for asset in result.analysis.assets[:20]:
            elements.append(Paragraph(f"{asset.asset_type}: {asset.url}", styles["BodyText"]))
            elements.append(Paragraph(f"Source: {asset.source_page} | External: {asset.external}", styles["BodyText"]))
            elements.append(Spacer(1, 6))

    if result.analysis.ports:
        elements.append(Paragraph("Port Exposure Inventory", styles["Heading2"]))
        for port in result.analysis.ports:
            elements.append(Paragraph(f"{port.port}/tcp [{port.state}] {port.service_hint or ''}".strip(), styles["BodyText"]))
            elements.append(Paragraph(port.note, styles["BodyText"]))
            elements.append(Spacer(1, 6))

    if result.analysis.diff is not None:
        elements.append(Paragraph("Scan Diff", styles["Heading2"]))
        elements.append(Paragraph(f"Baseline Scan: {result.analysis.diff.baseline_scan_id}", styles["BodyText"]))
        elements.append(Paragraph(f"Score Delta: {result.analysis.diff.score_delta}", styles["BodyText"]))
        elements.append(Paragraph(f"Findings Delta: {result.analysis.diff.total_findings_delta}", styles["BodyText"]))
        elements.append(Paragraph(f"New Findings: {', '.join(result.analysis.diff.new_findings[:8]) or 'None'}", styles["BodyText"]))
        elements.append(Paragraph(f"Resolved Findings: {', '.join(result.analysis.diff.resolved_findings[:8]) or 'None'}", styles["BodyText"]))
        elements.append(Spacer(1, 8))

    doc.build(elements)
