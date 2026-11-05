"""JSON and PDF report generation."""
from __future__ import annotations

import io
from datetime import UTC, datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .. import __version__
from ..core.findings import CLASSIFICATION_LABELS, SEVERITY_ORDER
from ..models import Scan

DISCLAIMER = (
    "This report is produced by automated static analysis. 'Detected' findings are backed by concrete evidence "
    "in the firmware, but exploitability has not been verified. 'Suspicious' findings are heuristic pattern "
    "matches and may be false positives. 'Unverified' findings (version-based matches, static-analysis warnings) "
    "require manual confirmation. Absence of findings does not imply absence of vulnerabilities. Uploaded "
    "firmware was never executed.")

SEV_COLORS = {"critical": colors.HexColor("#b4183d"), "high": colors.HexColor("#d9480f"),
              "medium": colors.HexColor("#c08b00"), "low": colors.HexColor("#1c7ed6"),
              "info": colors.HexColor("#5c6b7a")}


def scan_to_dict(scan: Scan, include_findings: bool = True) -> dict:
    d = {
        "id": scan.id, "status": scan.status, "stage": scan.stage, "progress": scan.progress,
        "error": scan.error.split("\n", 1)[0] if scan.error else None,
        "created_at": _iso(scan.created_at), "started_at": _iso(scan.started_at),
        "finished_at": _iso(scan.finished_at), "original_filename": scan.original_filename, "size": scan.size,
        "sha256": scan.sha256, "isolation": scan.isolation, "identification": scan.identification,
        "extraction_summary": scan.extraction_summary, "components": scan.components or [],
        "packages": _packages_summary(scan.packages),
        "severity_counts": scan.severity_counts, "classification_counts": scan.classification_counts,
        "risk_score": scan.risk_score,
    }
    if include_findings:
        d["findings"] = [finding_to_dict(f) for f in sorted(scan.findings, key=lambda f: (f.severity_rank, f.title))]
        d["tool_runs"] = [tool_run_to_dict(t) for t in scan.tool_runs]
    return d


def _packages_summary(p: dict | None) -> dict | None:
    if not p:
        return None
    pk = p.get("packages", [])
    return {"distro": p.get("distro"), "managers": p.get("managers", []), "count": len(pk),
            "vulnerable": sum(1 for x in pk if x.get("vulnerabilities"))}


def finding_to_dict(f) -> dict:
    return {"id": f.id, "fingerprint": f.fingerprint, "title": f.title, "description": f.description,
            "severity": f.severity, "classification": f.classification, "confidence": f.confidence,
            "source_tool": f.source_tool, "rule_id": f.rule_id, "affected_component": f.affected_component,
            "remediation": f.remediation, "evidence": f.evidence, "cwe": f.cwe, "references": f.references,
            "tags": f.tags, "package": getattr(f, "package", None)}


def tool_run_to_dict(t) -> dict:
    return {"tool": t.tool, "display_name": t.display_name, "status": t.status, "message": t.message,
            "started_at": _iso(t.started_at), "finished_at": _iso(t.finished_at), "duration_s": t.duration_s,
            "findings_count": t.findings_count, "details": t.details}


def _iso(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def json_report(scan: Scan) -> dict:
    return {
        "report_format": "drone-firmware-analyzer/1",
        "generator": f"Drone Firmware Analyzer {__version__}",
        "generated_at": datetime.now(UTC).isoformat(),
        "disclaimer": DISCLAIMER,
        "classification_legend": CLASSIFICATION_LABELS,
        "scan": scan_to_dict(scan),
    }


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "-")).replace("\n", "<br/>"), style)


def pdf_report(scan: Scan) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm,
                            bottomMargin=16 * mm, title=f"Firmware security report - {scan.original_filename}",
                            author="Drone Firmware Analyzer")
    ss = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=18, textColor=colors.HexColor("#0b2540"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, textColor=colors.HexColor("#0b2540"),
                        spaceBefore=10)
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=8.5, leading=11, alignment=TA_LEFT)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9.5, textColor=colors.HexColor("#33414f"))
    mono = ParagraphStyle("m", parent=small, fontName="Courier", fontSize=7, leading=9)
    story = [_p("Drone Firmware Analyzer - Security Report", h1), _p(DISCLAIMER, small), Spacer(1, 6)]
    ident = scan.identification or {}
    meta_rows = [
        ("File", scan.original_filename), ("SHA-256", scan.sha256), ("Size", f"{scan.size:,} bytes"),
        ("Scan ID", scan.id), ("Status", scan.status), ("Completed", _iso(scan.finished_at)),
        ("Format", ident.get("format_description")), ("Platform",
         f"{ident.get('platform')} ({ident.get('platform_confidence') or 'n/a'} confidence)"),
        ("Platform version", ident.get("platform_version")), ("Architecture", ident.get("architecture")),
        ("OS", ident.get("os_hint")), ("Board ID", ident.get("board_id")),
        ("Isolation", (scan.extraction_summary or {}).get("isolation_detail") or scan.isolation),
        ("Risk score", f"{scan.risk_score}/100 (heuristic)" if scan.risk_score is not None else "-"),
    ]
    t = Table([[_p(k, small), _p(v, mono if k == "SHA-256" else small)] for k, v in meta_rows],
              colWidths=[35 * mm, 143 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c5ced8")),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f6")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [_p("Firmware", h2), t]

    sev = scan.severity_counts or {}
    cls = scan.classification_counts or {}
    white = ParagraphStyle("w", parent=small, textColor=colors.white, fontName="Helvetica-Bold")
    summ = Table([[_p(s.upper(), white) for s in SEVERITY_ORDER] + [_p(c, small) for c in cls],
                  [_p(sev.get(s, 0), body) for s in SEVERITY_ORDER] + [_p(v, body) for v in cls.values()]])
    style = [("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c5ced8")), ("ALIGN", (0, 0), (-1, -1), "CENTER")]
    for i, s in enumerate(SEVERITY_ORDER):
        style.append(("BACKGROUND", (i, 0), (i, 0), SEV_COLORS[s]))
        style.append(("TEXTCOLOR", (i, 0), (i, 0), colors.white))
    summ.setStyle(TableStyle(style))
    story += [_p("Summary", h2), summ]

    story += [_p("Analysis tools", h2)]
    rows = [[_p("Tool", small), _p("Status", small), _p("Findings", small), _p("Message", small)]]
    for tr in scan.tool_runs:
        rows.append([_p(tr.display_name, small), _p(tr.status, small), _p(tr.findings_count, small),
                     _p((tr.message or "")[:400], small)])
    tt = Table(rows, colWidths=[38 * mm, 20 * mm, 15 * mm, 105 * mm], repeatRows=1)
    tt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c5ced8")),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f6")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(tt)

    grid = TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#c5ced8")),
                       ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f6")), ("VALIGN", (0, 0), (-1, -1), "TOP")])
    if scan.components:
        story += [_p("Identified software components", h2)]
        crow = [[_p("Component", small), _p("Version", small), _p("Identified by / found in", small),
                 _p("Known vulnerabilities (version match, unverified)", small)]]
        for c in scan.components[:80]:
            vulns = c.get("vulnerabilities") or []
            vtxt = (f"{len(vulns)}: " + ", ".join(v["id"] for v in vulns[:8]) + (" ..." if len(vulns) > 8 else "")
                    if vulns else c.get("vulnerabilities_note") or ("none listed" if "vulnerabilities" in c else "-"))
            crow.append([_p(c["name"] + (f" ({c['variant']})" if c.get("variant") else ""), small),
                         _p(c["version"], small),
                         _p(f"{c.get('method', '')}: " + "; ".join(c.get("sources", []))[:180], small), _p(vtxt, small)])
        ct = Table(crow, colWidths=[30 * mm, 28 * mm, 65 * mm, 55 * mm], repeatRows=1)
        ct.setStyle(grid)
        story.append(ct)

    inv = scan.packages or {}
    vulnerable = [p for p in inv.get("packages", []) if p.get("vulnerabilities")]
    if inv.get("packages"):
        distro = inv.get("distro") or {}
        story += [_p("Installed packages with known vulnerabilities", h2),
                  _p(f"{len(inv['packages'])} packages were read from the package manager database"
                     + (f" ({distro.get('name') or distro.get('id', '')})" if distro else "")
                     + f"; {len(vulnerable)} are listed as affected in the distribution's security data (OSV). "
                     "Fixed versions are compared with the exact installed version, so backported fixes are "
                     "accounted for. Exploitability in this firmware was not verified.", body)]
        if vulnerable:
            prow = [[_p("Package", small), _p("Installed version", small), _p("Advisories", small),
                     _p("Fixed in (highest)", small)]]
            for pk in sorted(vulnerable, key=lambda x: -len(x["vulnerabilities"]))[:60]:
                vs = pk["vulnerabilities"]
                fixed = sorted({v["fixed"] for v in vs if v.get("fixed")})
                prow.append([_p(pk["name"], small), _p(pk["version"], small),
                             _p(f"{len(vs)}: " + ", ".join(f"{v['id']} ({v.get('severity') or 'n/a'})" for v in vs[:6])
                                + (" ..." if len(vs) > 6 else ""), small),
                             _p(fixed[-1] if fixed else "no fix listed", small)])
            pt = Table(prow, colWidths=[35 * mm, 35 * mm, 80 * mm, 28 * mm], repeatRows=1)
            pt.setStyle(grid)
            story.append(pt)

    ghidra = next((t for t in scan.tool_runs if t.tool == "ghidra" and t.status == "completed"), None)
    bins = ((ghidra.details or {}).get("binaries") or []) if ghidra else []
    if bins:
        story += [_p("Binary analysis (Ghidra headless)", h2),
                  _p("Disassembly and function recovery of the analysed binaries. Call sites of risky library "
                     "functions are static-analysis observations, not confirmed vulnerabilities.", body)]
        brow = [[_p("Binary", small), _p("Functions", small), _p("Instructions", small), _p("Risky call sites", small)]]
        for b in bins[:10]:
            if b.get("status") != "completed":
                brow.append([_p(b.get("binary", ""), small), _p("failed", small), _p("-", small),
                             _p(str(b.get("error", ""))[:200], small)])
                continue
            risky = b.get("risky_call_sites") or {}
            rtxt = ", ".join(f"{k} x{v}" for k, v in sorted(risky.items(), key=lambda kv: -kv[1])[:8]) \
                if isinstance(risky, dict) else str(risky)[:200]
            brow.append([_p(b.get("binary", ""), small), _p(b.get("function_count", "-"), small),
                         _p(b.get("instruction_count", "-"), small), _p(rtxt or "none", small)])
        bt = Table(brow, colWidths=[70 * mm, 22 * mm, 26 * mm, 60 * mm], repeatRows=1)
        bt.setStyle(grid)
        story.append(bt)

    story += [PageBreak(), _p("Findings", h2)]
    findings = sorted(scan.findings, key=lambda f: (f.severity_rank, f.title))
    if not findings:
        story.append(_p("No findings were produced. This does not imply the firmware is free of vulnerabilities.", body))
    for i, f in enumerate(findings, 1):
        head = Table([[_p(f.severity.upper(), ParagraphStyle("sv", parent=small, textColor=colors.white)),
                       _p(f"{i}. {f.title}", ParagraphStyle("ft", parent=body, fontName="Helvetica-Bold"))]],
                     colWidths=[20 * mm, 158 * mm])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), SEV_COLORS.get(f.severity, colors.grey)),
                                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        ev = "<br/>".join(escape(f"{e.get('value', '')}" + (f"  [{e['location']}]" if e.get("location") else ""))
                          for e in (f.evidence or [])[:8])
        rows = [
            ("Classification", CLASSIFICATION_LABELS.get(f.classification, f.classification)
             + f"; confidence: {f.confidence}"
             + "".join(f"; corroborated by {t.split(':', 1)[1]}" for t in (f.tags or [])
                       if t.startswith("corroborated-by:"))),
            ("Source", f"{f.source_tool} ({f.rule_id})" + (f" - {f.cwe}" if f.cwe else "")),
            ("Component", f.affected_component), *([("Package", f.package)] if getattr(f, "package", None) else []),
            ("Description", f.description), ("Remediation", f.remediation),
        ]
        dt = Table([[_p(k, small), _p(v, small)] for k, v in rows] + [[_p("Evidence", small),
                    Paragraph(ev or "-", mono)]], colWidths=[25 * mm, 153 * mm])
        dt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#dde3ea")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [KeepTogether([head, dt]), Spacer(1, 5)]

    def footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#5c6b7a"))
        canvas.drawString(16 * mm, 9 * mm, f"Drone Firmware Analyzer {__version__} - {scan.original_filename[:60]} "
                                            f"- sha256 {scan.sha256[:16]}...")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
