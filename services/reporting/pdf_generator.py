"""Build masked, deterministic PDF security reports from persisted DataSniff scans."""
from collections import Counter
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import re
import uuid
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Flowable
from reportlab import __path__ as reportlab_paths
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle, KeepTogether)

from .remediation_knowledge_base import guidance_for

NAVY = colors.HexColor("#0B1624")
BLUE = colors.HexColor("#167DB6")
CYAN = colors.HexColor("#24B9D8")
INK = colors.HexColor("#1B2A3A")
MUTED = colors.HexColor("#607386")
PALE = colors.HexColor("#F1F6FA")
SEVERITY = {
    "Critical": colors.HexColor("#B42332"),
    "High": colors.HexColor("#C55315"),
    "Medium": colors.HexColor("#A36B00"),
    "Low": colors.HexColor("#17805C"),
}
SEVERITIES = ("Critical", "High", "Medium", "Low")


def _clean(value, limit=6000):
    """Strip control characters, cap untrusted text, and escape for ReportLab Paragraph XML."""
    value = str(value if value is not None else "")
    value = "".join(ch if ch in "\n\t" or ord(ch) >= 32 else " " for ch in value)
    value = re.sub(r"[\t\r\n]+", " ", value)
    return escape(value[:limit])


def _basename(name):
    # Accept Windows and POSIX paths while never exposing a host-side absolute path.
    return str(name or "Unknown source").replace("\\", "/").split("/")[-1][:180] or "Unknown source"


def _safe_structured_path(value):
    value = str(value or "")[:300]
    if re.fullmatch(r"(?:\$|[A-Za-z_$][\w$]*)(?:(?:\.[A-Za-z_$][\w$]*)|(?:\[\d+\]))*", value):
        return value
    if re.fullmatch(r"(?:/(?:[A-Za-z0-9_.~-]|%[0-9A-Fa-f]{2})*)+", value):
        return value
    return ""


def _masked_evidence(category, evidence):
    value = str(evidence or "Not available")
    if category == "Private key":
        return "Private key marker detected (key material omitted)"
    # Existing detector results already contain a masked representation.
    if re.fullmatch(r".{3}\*{4,12}.{2}", value, re.DOTALL):
        return value[:500]
    if len(value) <= 4:
        return "*" * len(value)
    return value[:3] + "*" * min(16, max(4, len(value) - 5)) + value[-2:]


def _parse_findings(scan):
    raw = scan.get("findings_json", "[]")
    if isinstance(raw, str):
        import json
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raw = []
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        category = str(item.get("category") or "Other")[:100]
        severity = item.get("severity") if item.get("severity") in SEVERITIES else "Low"
        try:
            confidence = max(0, min(100, int(float(item.get("confidence", 0)))))
        except (TypeError, ValueError, OverflowError):
            confidence = 0
        try:
            line = max(1, int(item.get("line", 1)))
        except (TypeError, ValueError, OverflowError):
            line = None
        result.append({
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "file": _basename(item.get("file") or scan.get("filename")),
            "line": line,
            "path": _safe_structured_path(item.get("path")),
            "evidence": _masked_evidence(category, item.get("evidence", "")),
            "explanation": str(item.get("explanation") or "A pattern-based candidate was detected.")[:1200],
            "remediation": str(item.get("remediation") or "Review this candidate and follow the category-specific guidance below.")[:2000],
        })
    return result


def prepare_report(scan):
    """Normalize one actual SQLite scan row into report data; malformed findings are safely empty."""
    if not isinstance(scan, dict):
        scan = {}
    findings = _parse_findings(scan)
    counts = Counter(item["severity"] for item in findings)
    categories = Counter(item["category"] for item in findings)
    top = next((level for level in SEVERITIES if counts[level]), None)
    if not findings:
        risk = "No matching findings"
        summary = "The scan completed and no findings matched the current DataSniff detection rules. This result does not establish that the source is free of sensitive information."
    else:
        risk = top + " candidate findings present"
        parts = [f"{len(findings)} pattern-based finding(s) were identified"]
        parts.extend(f"{counts[s]} {s.lower()}" for s in SEVERITIES if counts[s])
        summary = ". ".join([", ".join(parts), "Review higher-severity findings first and validate each candidate in its source context. A pattern match does not establish that a credential is valid or exploited"] ) + "."
    scan_id = str(scan.get("id", "unknown"))[:80]
    return {
        "report_id": "DSR-" + uuid.uuid4().hex[:12].upper(),
        "generated_at": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z"),
        "scan_id": scan_id,
        "source_file": _basename(scan.get("filename")),
        "scan_date": str(scan.get("scanned_at", "Unknown"))[:80],
        "scan_status": "Complete",
        "findings": findings,
        "severity_counts": {s: counts[s] for s in SEVERITIES},
        "category_counts": dict(sorted(categories.items())),
        "risk": risk,
        "summary": summary,
    }


def _styles():
    font_dir = Path(reportlab_paths[0]) / "fonts"
    if "DS-Vera" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("DS-Vera", str(font_dir / "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("DS-Vera-Bold", str(font_dir / "VeraBd.ttf")))
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitleDS", parent=styles["Title"], fontName="DS-Vera-Bold", fontSize=25, leading=31, textColor=colors.white, alignment=TA_LEFT, spaceAfter=8))
    styles.add(ParagraphStyle(name="CoverSubDS", parent=styles["Normal"], fontName="DS-Vera", fontSize=12, leading=17, textColor=colors.HexColor("#BBD6EA")))
    styles.add(ParagraphStyle(name="SectionDS", parent=styles["Heading1"], fontName="DS-Vera-Bold", fontSize=18, leading=23, textColor=NAVY, spaceBefore=2, spaceAfter=10, keepWithNext=True))
    styles.add(ParagraphStyle(name="FindingDS", parent=styles["Heading2"], fontName="DS-Vera-Bold", fontSize=14, leading=19, textColor=NAVY, spaceBefore=7, spaceAfter=7, keepWithNext=True))
    styles.add(ParagraphStyle(name="BodyDS", parent=styles["BodyText"], fontName="DS-Vera", fontSize=9.2, leading=13, textColor=INK, spaceAfter=5, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="SmallDS", parent=styles["BodyText"], fontName="DS-Vera", fontSize=8, leading=11, textColor=MUTED, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="LabelDS", parent=styles["BodyText"], fontName="DS-Vera-Bold", fontSize=8.5, leading=11, textColor=MUTED))
    styles.add(ParagraphStyle(name="EvidenceDS", parent=styles["Code"], fontName="Courier", fontSize=8.5, leading=12, textColor=INK, backColor=PALE, borderPadding=7, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="WhiteSmallDS", parent=styles["BodyText"], fontName="DS-Vera", fontSize=9, leading=13, textColor=colors.white))
    return styles


def _p(text, style):
    return Paragraph(_clean(text), style)


def _footer(canvas, doc, report):
    canvas.saveState()
    page = canvas.getPageNumber()
    w, h = A4
    if page == 1:
        canvas.setFillColor(NAVY)
        canvas.rect(0, 0, w, h, stroke=0, fill=1)
        canvas.setFillColor(CYAN)
        canvas.rect(0, h - 13 * mm, w, 3 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor("#20374D"))
        canvas.rect(0, 0, w, 22 * mm, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor("#BBD0E0"))
    else:
        canvas.setStrokeColor(colors.HexColor("#D5E0E8"))
        canvas.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
        canvas.setFillColor(BLUE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(18 * mm, h - 11 * mm, "DATASNIFF  /  SECURITY ANALYSIS")
        canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(18 * mm, 11 * mm, f"{report['report_id']}  |  Generated {report['generated_at']}")
    canvas.drawRightString(w - 18 * mm, 11 * mm, f"Page {page}")
    canvas.restoreState()


class SeverityBar(Flowable):
    """Compact count-proportional severity bar for the risk overview."""
    def __init__(self, value, maximum, color, width=72 * mm, height=7 * mm):
        super().__init__()
        self.value = value
        self.maximum = max(1, maximum)
        self.color = color
        self.width = width
        self.height = height

    def draw(self):
        self.canv.setFillColor(PALE)
        self.canv.roundRect(0, 1 * mm, self.width, self.height - 2 * mm, 2 * mm, stroke=0, fill=1)
        if self.value:
            self.canv.setFillColor(self.color)
            self.canv.roundRect(0, 1 * mm, self.width * self.value / self.maximum, self.height - 2 * mm, 2 * mm, stroke=0, fill=1)


def _bullet_list(items, styles, number=False):
    output = []
    for index, value in enumerate(items, 1):
        prefix = f"{index}. " if number else "-  "
        output.append(_p(prefix + str(value), styles["BodyDS"]))
    return output


def _severity_table(report, styles, width):
    rows = [[_p("Severity", styles["LabelDS"]), _p("Findings", styles["LabelDS"]), _p("Relative count", styles["LabelDS"])]]
    total = len(report["findings"])
    maximum = max(report["severity_counts"].values(), default=0)
    for severity in SEVERITIES:
        count = report["severity_counts"][severity]
        color = SEVERITY[severity]
        rows.append([_p(severity, styles["BodyDS"]), _p(str(count), styles["BodyDS"]), SeverityBar(count, maximum, color, width=width * .49)])
    table = Table(rows, colWidths=[width * .25, width * .14, width * .61], repeatRows=1, hAlign="LEFT")
    commands = [("BACKGROUND", (0, 0), (-1, 0), PALE), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#D7E1E9")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    for row, severity in enumerate(SEVERITIES, 1):
        commands.append(("TEXTCOLOR", (0, row), (0, row), SEVERITY[severity]))
    table.setStyle(TableStyle(commands))
    return table


def _finding_section(item, index, styles, width):
    knowledge = guidance_for(item["category"])
    severity_color = SEVERITY[item["severity"]]
    heading = _p(f"Finding DS-{index:03d}  |  {item['category']}", styles["FindingDS"])
    metadata = [
        [_p("SEVERITY", styles["LabelDS"]), _p(item["severity"], styles["BodyDS"]), _p("CONFIDENCE", styles["LabelDS"]), _p(f"{item['confidence']}%", styles["BodyDS"])],
        [_p("SOURCE", styles["LabelDS"]), _p(item["file"], styles["BodyDS"]), _p("LOCATION", styles["LabelDS"]), _p(item["path"] or (f"Line {item['line']}" if item["line"] else "Not available"), styles["BodyDS"])],
    ]
    meta_table = Table(metadata, colWidths=[width * .15, width * .34, width * .16, width * .35], hAlign="LEFT")
    meta_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), PALE), ("BACKGROUND", (2, 0), (2, -1), PALE), ("TEXTCOLOR", (1, 0), (1, 0), severity_color), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#D7E1E9")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    flow = [heading, meta_table, Spacer(1, 7), _p("Masked evidence", styles["LabelDS"]), _p(item["evidence"], styles["EvidenceDS"]), Spacer(1, 6)]
    for label, content in (("Detection explanation", item["explanation"]), ("Why it matters", knowledge["why"]), ("Potential impact", None)):
        flow.append(_p(label, styles["LabelDS"]))
        if content is not None:
            flow.append(_p(content, styles["BodyDS"]))
        else:
            flow.extend(_bullet_list(knowledge["impact"], styles))
    flow.append(_p("Recommended remediation", styles["LabelDS"]))
    flow.extend(_bullet_list(knowledge["immediate"], styles, number=True))
    if item["remediation"]:
        flow.append(_p("Detector recommendation: " + item["remediation"], styles["SmallDS"]))
    flow.append(_p("Prevention", styles["LabelDS"]))
    flow.extend(_bullet_list(knowledge["prevention"], styles))
    flow.extend([_p("Verification", styles["LabelDS"]), _p(knowledge["verification"], styles["BodyDS"])])
    return flow


def build_pdf_report(scan):
    """Return (PDF bytes, report metadata) from one stored scan row."""
    report = prepare_report(scan)
    styles = _styles()
    stream = BytesIO()
    doc = SimpleDocTemplate(stream, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=21 * mm, bottomMargin=20 * mm, title="DataSniff Security Analysis and Remediation Report", author="DataSniff")
    width = A4[0] - 36 * mm
    story = []

    # Page 1: cover and executive summary.
    story.extend([Spacer(1, 28 * mm), _p("DATASNIFF  /  LOG AND DATA DETECTOR", styles["CoverSubDS"]), Spacer(1, 10 * mm), _p("Security Analysis and Remediation Report", styles["CoverTitleDS"]), Spacer(1, 7 * mm), _p(f"Scan {report['scan_id']}  |  {report['generated_at']}", styles["CoverSubDS"]), Spacer(1, 18 * mm)])
    cover_rows = [
        [_p("SOURCE FILE", styles["WhiteSmallDS"]), _p(report["source_file"], styles["WhiteSmallDS"])],
        [_p("SCAN STATUS", styles["WhiteSmallDS"]), _p(report["scan_status"], styles["WhiteSmallDS"])],
        [_p("TOTAL FINDINGS", styles["WhiteSmallDS"]), _p(str(len(report["findings"])), styles["WhiteSmallDS"])],
        [_p("OVERALL RISK", styles["WhiteSmallDS"]), _p(report["risk"], styles["WhiteSmallDS"])],
    ]
    cover = Table(cover_rows, colWidths=[width * .28, width * .72], hAlign="LEFT")
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#172A3D")), ("BOX", (0, 0), (-1, -1), .6, colors.HexColor("#31536D")), ("INNERGRID", (0, 0), (-1, -1), .35, colors.HexColor("#31536D")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 9)]))
    story.extend([cover, Spacer(1, 11 * mm), _p("EXECUTIVE SUMMARY", styles["CoverSubDS"]), Spacer(1, 3 * mm), _p(report["summary"], styles["WhiteSmallDS"]), Spacer(1, 5 * mm), _p("Pattern-based results are candidates for review. A match does not prove that a credential is valid, active, or exploited.", styles["CoverSubDS"]), PageBreak()])

    # Page 2: risk overview and data-driven counts.
    story.extend([_p("Risk Overview", styles["SectionDS"]), _p(f"Assessment: {report['risk']}", styles["BodyDS"]), _severity_table(report, styles, width), Spacer(1, 9), _p("Findings by category", styles["FindingDS"])])
    if report["category_counts"]:
        category_rows = [[_p("Category", styles["LabelDS"]), _p("Count", styles["LabelDS"])]]
        for name, count in report["category_counts"].items():
            category_rows.append([_p(name, styles["BodyDS"]), _p(str(count), styles["BodyDS"])])
        categories = Table(category_rows, colWidths=[width * .78, width * .22], repeatRows=1, hAlign="LEFT")
        categories.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), PALE), ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#D7E1E9")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.extend([categories, Spacer(1, 8)])
    else:
        story.append(_p("No categories matched the current detection rules.", styles["BodyDS"]))
    story.append(_p("Priority attention", styles["FindingDS"]))
    priority = sorted(enumerate(report["findings"], 1), key=lambda pair: (SEVERITIES.index(pair[1]["severity"]), pair[0]))
    urgent = [item for _, item in priority if item["severity"] in ("Critical", "High")][:5]
    if urgent:
        story.extend(_bullet_list([f"{item['severity']} - {item['category']} in {item['file']} ({item['path'] or ('line ' + str(item['line']) if item['line'] else 'location unavailable')})" for item in urgent], styles))
    else:
        story.append(_p("No Critical or High findings were reported. Review Medium and Low findings according to context and policy.", styles["BodyDS"]))
    story.append(PageBreak())

    # Page 3 onward: category-specific, masked finding details.
    story.append(_p("Detailed Findings", styles["SectionDS"]))
    if not report["findings"]:
        story.append(_p("No findings were returned for this scan. DataSniff detection is heuristic and does not prove the source contains no sensitive information.", styles["BodyDS"]))
    else:
        for index, item in enumerate(report["findings"], 1):
            if index > 1:
                story.append(Spacer(1, 12))
            story.extend(_finding_section(item, index, styles, width))
            if index < len(report["findings"]):
                story.append(Spacer(1, 12))
    story.extend([PageBreak(), _p("Final Security Assessment", styles["SectionDS"]), _p(f"{len(report['findings'])} pattern-based finding(s) were included in this report.", styles["BodyDS"]), _p("Highest-priority actions", styles["FindingDS"])])
    actions = []
    for _, item in priority:
        if item["severity"] in ("Critical", "High"):
            first = guidance_for(item["category"])["immediate"][0]
            action = f"{item['category']}: {first}"
            if action not in actions:
                actions.append(action)
    if not actions:
        actions = ["Validate any context-sensitive candidates and apply remediation according to organizational policy."]
    story.extend(_bullet_list(actions[:8], styles, number=True))
    story.extend([_p("Outstanding issues", styles["FindingDS"]), _p("Findings should be validated by an authorized reviewer. This report does not establish credential validity, exploitation, or that all sensitive data has been detected.", styles["BodyDS"]), _p("Suggested follow-up", styles["FindingDS"]), _p("Apply relevant fixes, generate fresh logs through the affected application paths, and run a follow-up DataSniff scan. Review results against source context and your retention and access policies.", styles["BodyDS"]), _p("Limitations and disclaimer", styles["FindingDS"]), _p("DataSniff uses pattern-based detection. It may miss formats or report benign matches. A matching pattern does not prove a credential is valid, active, or compromised, and remediation does not guarantee that a system is secure. Treat exposed credentials as sensitive according to your incident-response procedures.", styles["BodyDS"])])

    doc.build(story, onFirstPage=lambda canvas, current_doc: _footer(canvas, current_doc, report), onLaterPages=lambda canvas, current_doc: _footer(canvas, current_doc, report))
    return stream.getvalue(), report
