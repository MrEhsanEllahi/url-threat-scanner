from __future__ import annotations

import io
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    Image,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

W, H = A4
MARGIN = 18 * mm

# ── Palette ─────────────────────────────────────────────────────────────────
C_BG_HEADER = colors.HexColor("#0f0f1a")
C_ACCENT = colors.HexColor("#7c3aed")
C_ACCENT2 = colors.HexColor("#06b6d4")
C_DANGER = colors.HexColor("#ef4444")
C_WARNING = colors.HexColor("#f59e0b")
C_SAFE = colors.HexColor("#10b981")
C_NEUTRAL = colors.HexColor("#6b7280")
C_TEXT = colors.HexColor("#1e1b4b")
C_TEXT_MUTED = colors.HexColor("#6b7280")
C_SECTION_BG = colors.HexColor("#f5f3ff")
C_ROW_ALT = colors.HexColor("#fafafa")
C_BORDER = colors.HexColor("#e5e7eb")
C_WHITE = colors.white
C_BLACK = colors.HexColor("#111827")

SIGNAL_LABELS = {
    "HTTPS": "Uses Secure HTTPS",
    "AnchorURL": "Anchor Link Ratio",
    "RequestURL": "Request URL Ratio",
    "LinksInScriptTags": "Script Tag Sources",
    "SubDomains": "Subdomain Depth",
    "ShortURL": "URL Shortener Pattern",
    "Symbol@": "@ Symbol in URL",
    "PrefixSuffix-": "Hyphen in Domain",
    "WebsiteTraffic": "Domain Visibility",
    "AgeofDomain": "Domain Age",
    "DNSRecording": "DNS/WHOIS Records",
    "UsingIP": "IP Address as Host",
    "WebsiteForwarding": "Redirect Behaviour",
    "AbnormalURL": "Domain Identity Match",
    "DomainRegLen": "Domain Reg. Length",
    "Favicon": "Favicon Source",
    "NonStdPort": "Standard Port",
    "HTTPSDomainURL": "HTTPS in Hostname",
    "ServerFormHandler": "Form Submission Target",
    "InfoEmail": "Mailto Links",
    "StatusBarCust": "Status Bar Behaviour",
    "DisableRightClick": "Right-click Blocking",
    "UsingPopupWindow": "Popup Behaviour",
    "IframeRedirection": "Suspicious iFrames",
    "PageRank": "Page Authority",
    "GoogleIndex": "Site Indexability",
    "LinksPointingToPage": "Inbound Links",
    "StatsReport": "Domain Reputation",
    "LongURL": "URL Length",
    "Redirecting//": "Double-slash Redirect",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _verdict_color(level: str) -> colors.Color:
    if level == "High Risk":
        return C_DANGER
    if level in ("Needs Caution", "Content Risk"):
        return C_WARNING
    if level == "Likely Safe":
        return C_SAFE
    return C_NEUTRAL


def _direction_color(d: str) -> colors.Color:
    if d == "riskier":
        return C_DANGER
    if d == "safer":
        return C_SAFE
    return C_NEUTRAL


def _direction_label(d: str) -> str:
    if d == "riskier":
        return "Risk"
    if d == "safer":
        return "Safe"
    return "Neutral"


def _safe(val: Any, fallback: str = "—") -> str:
    if val is None:
        return fallback
    s = str(val).strip()
    return s if s else fallback


def _pct(val: Any) -> str:
    try:
        return f"{float(val):.1f}%"
    except Exception:
        return "—"


# ── Page template (header + footer on every page) ────────────────────────────

def _make_page_template(doc, scan_url: str, scan_ts: str):
    frame = Frame(MARGIN, MARGIN, W - 2 * MARGIN, H - 2 * MARGIN - 28 * mm,
                  leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

    def on_page(canvas, doc):
        canvas.saveState()

        # ── Top header bar ──
        canvas.setFillColor(C_BG_HEADER)
        canvas.rect(0, H - 22 * mm, W, 22 * mm, fill=1, stroke=0)

        # Shield icon placeholder (filled circle)
        canvas.setFillColor(C_ACCENT)
        canvas.roundRect(MARGIN, H - 17 * mm, 9 * mm, 9 * mm, 2 * mm, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawCentredString(MARGIN + 4.5 * mm, H - 12 * mm, "S")

        # Brand name
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 13)
        canvas.drawString(MARGIN + 12 * mm, H - 11.5 * mm, "ShieldScan")
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(MARGIN + 12 * mm, H - 16 * mm, "Threat Intelligence Report")

        # Right side: date
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawRightString(W - MARGIN, H - 11 * mm, scan_ts)
        canvas.drawRightString(W - MARGIN, H - 16 * mm, "CONFIDENTIAL")

        # ── Bottom footer ──
        canvas.setFillColor(colors.HexColor("#f1f5f9"))
        canvas.rect(0, 0, W, 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 4.5 * mm, f"Scanned URL: {scan_url}")
        canvas.drawRightString(W - MARGIN, 4.5 * mm, f"Page {doc.page}")

        canvas.restoreState()

    return PageTemplate(id="main", frames=[frame], onPage=on_page)


# ── Style helpers ─────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "section_title": ps("ST",
            fontName="Helvetica-Bold", fontSize=11, textColor=C_ACCENT,
            spaceBefore=10, spaceAfter=4, leading=14),
        "body": ps("BD",
            fontName="Helvetica", fontSize=9, textColor=C_BLACK,
            spaceBefore=2, spaceAfter=2, leading=13),
        "body_muted": ps("BM",
            fontName="Helvetica", fontSize=8.5, textColor=C_TEXT_MUTED,
            spaceBefore=1, spaceAfter=1, leading=12),
        "verdict_level": ps("VL",
            fontName="Helvetica-Bold", fontSize=22, textColor=C_TEXT,
            alignment=TA_CENTER, spaceBefore=4, spaceAfter=2),
        "verdict_headline": ps("VH",
            fontName="Helvetica", fontSize=11, textColor=C_TEXT_MUTED,
            alignment=TA_CENTER, spaceBefore=0, spaceAfter=6),
        "fact_val": ps("FV",
            fontName="Helvetica-Bold", fontSize=9.5, textColor=C_BLACK,
            alignment=TA_RIGHT),
        "fact_key": ps("FK",
            fontName="Helvetica", fontSize=9, textColor=C_TEXT_MUTED,
            alignment=TA_LEFT),
        "table_header": ps("TH",
            fontName="Helvetica-Bold", fontSize=8.5, textColor=C_WHITE,
            alignment=TA_LEFT),
        "table_cell": ps("TC",
            fontName="Helvetica", fontSize=8.5, textColor=C_BLACK,
            leading=12),
        "table_cell_muted": ps("TCM",
            fontName="Helvetica", fontSize=8, textColor=C_TEXT_MUTED,
            leading=11),
        "warning_text": ps("WT",
            fontName="Helvetica-Oblique", fontSize=8.5, textColor=colors.HexColor("#92400e"),
            leading=12),
        "caption": ps("CAP",
            fontName="Helvetica-Oblique", fontSize=8, textColor=C_TEXT_MUTED,
            alignment=TA_CENTER, spaceBefore=2, spaceAfter=4),
    }


def _hr(color=C_BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=4, spaceBefore=4)


def _section(title: str, s: dict) -> list:
    return [
        Spacer(1, 6),
        Paragraph(title.upper(), s["section_title"]),
        _hr(C_ACCENT, 1.5),
    ]


def _kv_table(rows: list[tuple[str, str]], s: dict, col_widths=None) -> Table:
    usable = W - 2 * MARGIN
    cw = col_widths or [usable * 0.42, usable * 0.58]
    data = []
    for k, v in rows:
        data.append([
            Paragraph(k, s["fact_key"]),
            Paragraph(v, s["fact_val"]),
        ])
    t = Table(data, colWidths=cw)
    style = [
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_WHITE, C_ROW_ALT]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, C_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    t.setStyle(TableStyle(style))
    return t


# ── Main build function ───────────────────────────────────────────────────────

def build_pdf(scan: dict, friendly: dict, input_url: str) -> bytes:
    buf = io.BytesIO()
    scan_ts = datetime.now().strftime("%d %b %Y  %H:%M UTC")
    s = _styles()
    usable_w = W - 2 * MARGIN

    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=24 * mm,
        bottomMargin=14 * mm,
        title="ShieldScan Threat Report",
        author="ShieldScan",
    )
    doc.addPageTemplates([_make_page_template(doc, input_url, scan_ts)])

    story = []

    level = friendly.get("level", "Unknown")
    headline = friendly.get("headline", "")
    verdict = friendly.get("verdict", "Unknown")
    risk_score = None
    confidence = None
    prediction = scan.get("prediction") or {}
    if isinstance(prediction.get("risk_score"), (int, float)):
        risk_score = float(prediction["risk_score"])
    if isinstance(prediction.get("confidence"), (int, float)):
        confidence = float(prediction["confidence"])

    vc = _verdict_color(level)

    # ════════════════════════════════════════════════════════════
    # SECTION 0 — Verdict Hero Block
    # ════════════════════════════════════════════════════════════
    story.append(Spacer(1, 4))

    verdict_data = [[
        Paragraph(level, ParagraphStyle("VL2", fontName="Helvetica-Bold", fontSize=26,
                                         textColor=vc, alignment=TA_CENTER)),
        Paragraph(headline, ParagraphStyle("VH2", fontName="Helvetica", fontSize=10.5,
                                            textColor=C_TEXT_MUTED, alignment=TA_CENTER,
                                            leading=15)),
    ]]
    vt = Table(verdict_data, colWidths=[usable_w * 0.35, usable_w * 0.65])
    vt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#faf5ff")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, vc),
        ("LINEAFTER", (0, 0), (0, 0), 0.5, vc),
        ("TOPPADDING", (0, 0), (-1, -1), 14),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(vt)
    story.append(Spacer(1, 10))

    # ── Score + Confidence quick row ──
    quick_rows = []
    if risk_score is not None:
        quick_rows.append(("Phishing Risk Score", _pct(risk_score)))
    if confidence is not None:
        quick_rows.append(("Model Confidence", _pct(confidence)))
    quick_rows.append(("ML Verdict", _safe(verdict)))
    quick_rows.append(("Scan Timestamp", scan_ts))
    story.append(_kv_table(quick_rows, s))

    if friendly.get("confidence_text"):
        story.append(Spacer(1, 4))
        story.append(Paragraph(friendly["confidence_text"], s["body_muted"]))

    # Warnings
    for w in (friendly.get("warnings") or []):
        if w:
            wt = Table([[Paragraph(f"⚠  {w}", s["warning_text"])]],
                       colWidths=[usable_w])
            wt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fffbeb")),
                ("BOX", (0, 0), (-1, -1), 0.75, C_WARNING),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(Spacer(1, 4))
            story.append(wt)

    # ════════════════════════════════════════════════════════════
    # SECTION 1 — Scan Overview
    # ════════════════════════════════════════════════════════════
    story += _section("Scan Overview", s)

    validation = scan.get("validation") or {}
    reachability = scan.get("reachability") or {}
    domain_host = (scan.get("features") or {}).get("domain_host") or {}

    final_url_raw = reachability.get("final_url") or ""
    if final_url_raw.startswith("data:"):
        final_url_display = "Page content could not be loaded — no valid final URL recorded."
    else:
        final_url_display = _safe(final_url_raw)

    reach_state = _safe(reachability.get("state", "")).lower()
    reach_label = {
        "reachable": "Reachable",
        "timeout": "Timed Out",
        "unreachable": "Unreachable",
        "setup_required": "Could Not Reach",
    }.get(reach_state, _safe(reachability.get("state", "")).title())

    if reach_state == "unreachable":
        reach_label += " — only URL-level signals were available."

    overview_rows = [
        ("Submitted URL", _safe(input_url)),
        ("Normalised URL", _safe(validation.get("normalized_url"))),
        ("Reachability", reach_label),
        ("Final URL After Redirects", final_url_display),
        ("Page Title", _safe(reachability.get("title"))),
        ("Load Time", _safe(reachability.get("load_time"))),
        ("Redirect Hops", _safe(reachability.get("redirect_hops"))),
        ("Browser Engine Used", _safe(reachability.get("engine"))),
    ]
    story.append(_kv_table(overview_rows, s))

    # ════════════════════════════════════════════════════════════
    # SECTION 2 — Evidence & Signal Analysis
    # ════════════════════════════════════════════════════════════
    evidence_items = friendly.get("evidence_items") or []
    if evidence_items:
        story += _section("Evidence & Signal Analysis", s)

        col_w = [usable_w * 0.26, usable_w * 0.48, usable_w * 0.13, usable_w * 0.13]
        header_row = [
            Paragraph("Signal", s["table_header"]),
            Paragraph("Finding", s["table_header"]),
            Paragraph("Impact", s["table_header"]),
            Paragraph("Direction", s["table_header"]),
        ]
        ev_data = [header_row]
        for item in evidence_items:
            dc = _direction_color(item.get("direction", "neutral"))
            dl = _direction_label(item.get("direction", "neutral"))
            impact_str = item.get("impact", "—")
            try:
                impact_str = f"{float(impact_str):.4f}"
            except Exception:
                pass
            ev_data.append([
                Paragraph(_safe(item.get("title")), s["table_cell"]),
                Paragraph(_safe(item.get("finding")), s["table_cell_muted"]),
                Paragraph(impact_str, s["table_cell"]),
                Paragraph(dl, ParagraphStyle("DIR", fontName="Helvetica-Bold",
                                              fontSize=8, textColor=dc, leading=11)),
            ])

        et = Table(ev_data, colWidths=col_w, repeatRows=1)
        row_bgs = []
        for i in range(1, len(ev_data)):
            direction = evidence_items[i - 1].get("direction", "neutral")
            if direction == "riskier":
                bg = colors.HexColor("#fff1f2")
            elif direction == "safer":
                bg = colors.HexColor("#f0fdf4")
            else:
                bg = C_ROW_ALT if i % 2 else C_WHITE
            row_bgs.append(("BACKGROUND", (0, i), (-1, i), bg))

        et.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_ACCENT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, C_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ] + row_bgs))
        story.append(et)

    # ════════════════════════════════════════════════════════════
    # SECTION 3 — Top ML Signals (raw feature importance)
    # ════════════════════════════════════════════════════════════
    top_signals = scan.get("top_signals") or []
    if top_signals:
        story += _section("Top Model Signals (Feature Importance)", s)

        sig_col_w = [usable_w * 0.34, usable_w * 0.22, usable_w * 0.22, usable_w * 0.22]
        sig_header = [
            Paragraph("Feature", s["table_header"]),
            Paragraph("Value", s["table_header"]),
            Paragraph("Importance", s["table_header"]),
            Paragraph("Note", s["table_header"]),
        ]
        sig_data = [sig_header]
        for sig in top_signals[:12]:
            feat = sig.get("feature", "")
            label = SIGNAL_LABELS.get(feat, feat)
            val = sig.get("value", "—")
            imp = sig.get("importance", 0)
            note = _safe(sig.get("note"))
            sig_data.append([
                Paragraph(label, s["table_cell"]),
                Paragraph(str(val), s["table_cell"]),
                Paragraph(f"{float(imp):.5f}" if imp else "—", s["table_cell"]),
                Paragraph(note, s["table_cell_muted"]),
            ])

        st = Table(sig_data, colWidths=sig_col_w, repeatRows=1)
        st.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e1b4b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_WHITE, C_ROW_ALT]),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, C_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(st)
        story.append(Paragraph(
            "Importance values are normalised feature weights from the trained ML model. "
            "Higher = more influential in the phishing decision.",
            s["body_muted"],
        ))

    # ════════════════════════════════════════════════════════════
    # SECTION 4 — URL Lexical Analysis
    # ════════════════════════════════════════════════════════════
    url_lexical = (scan.get("features") or {}).get("url_lexical") or {}
    if url_lexical:
        story += _section("URL Lexical Analysis", s)

        def yn(v):
            if v is True or v == 1:
                return "Yes"
            if v is False or v == 0:
                return "No"
            return _safe(v)

        lex_rows = [
            ("URL Length (chars)", _safe(url_lexical.get("url_len"))),
            ("Domain / Host", _safe(url_lexical.get("host"))),
            ("Top-Level Domain (TLD)", _safe(url_lexical.get("tld"))),
            ("Uses HTTPS", yn(url_lexical.get("https"))),
            ("Raw IP as Host", yn(url_lexical.get("has_ip_host"))),
            ("URL Shortener Detected", yn(url_lexical.get("shortener_hint"))),
            ("Subdomain Depth", _safe(url_lexical.get("subdomain_depth"))),
            ("Path Depth", _safe(url_lexical.get("path_depth"))),
            ("Query Parameter Count", _safe(url_lexical.get("query_param_count"))),
            ("Non-standard Port", yn(url_lexical.get("has_non_standard_port"))),
            ("Suspicious Token Count", _safe(url_lexical.get("suspicious_token_count"))),
            ("Hyphen Count in Domain", _safe(url_lexical.get("hyphen_count"))),
            ("Digit Count in URL", _safe(url_lexical.get("digit_count"))),
        ]
        # Filter out empty rows
        lex_rows = [(k, v) for k, v in lex_rows if v != "—"]
        if lex_rows:
            story.append(_kv_table(lex_rows, s))
        else:
            story.append(Paragraph("No lexical data was extracted for this URL.", s["body_muted"]))

    # ════════════════════════════════════════════════════════════
    # SECTION 5 — Domain & WHOIS
    # ════════════════════════════════════════════════════════════
    story += _section("Domain & WHOIS Intelligence", s)

    whois_rows = [
        ("DNS Resolved", "Yes" if domain_host.get("dns_resolved") else "No"),
        ("WHOIS Data Available", "Yes" if domain_host.get("whois_available") else "No"),
        ("Resolved IP", _safe(domain_host.get("resolved_ip"))),
        ("Domain Registrar", _safe(domain_host.get("registrar"))),
        ("Creation Date", _safe(domain_host.get("creation_date"))),
        ("Expiry Date", _safe(domain_host.get("expiry_date"))),
        ("Domain Age (days)", _safe(domain_host.get("domain_age_days"))),
        ("Name Servers", _safe(domain_host.get("name_servers"))),
        ("Registrant Country", _safe(domain_host.get("country"))),
        ("TLD", _safe(domain_host.get("tld"))),
    ]
    whois_rows = [(k, v) for k, v in whois_rows if v != "—"]
    if whois_rows:
        story.append(_kv_table(whois_rows, s))
    else:
        story.append(Paragraph("No WHOIS or domain data was available for this URL.", s["body_muted"]))

    # ════════════════════════════════════════════════════════════
    # SECTION 6 — Content Threat Analysis
    # ════════════════════════════════════════════════════════════
    content_analysis = scan.get("content_analysis") or {}
    content_threats = content_analysis.get("threats_detected") or []
    content_verdict = content_analysis.get("content_verdict", "")
    content_severity = content_analysis.get("content_severity", "safe")

    story += _section("Content Threat Analysis (Layer 2)", s)

    cv_color = C_SAFE if content_severity == "safe" else (C_DANGER if content_severity == "danger" else C_WARNING)
    content_meta = [
        ("Content Layer Verdict", _safe(content_verdict)),
        ("Severity", content_severity.upper()),
        ("Threats Detected", str(len(content_threats))),
    ]
    story.append(_kv_table(content_meta, s))

    if content_threats:
        story.append(Spacer(1, 6))
        ct_col_w = [usable_w * 0.22, usable_w * 0.58, usable_w * 0.20]
        ct_header = [
            Paragraph("Category", s["table_header"]),
            Paragraph("Description", s["table_header"]),
            Paragraph("Score", s["table_header"]),
        ]
        ct_data = [ct_header]
        for t in content_threats:
            ct_data.append([
                Paragraph(_safe(t.get("label")), s["table_cell"]),
                Paragraph(_safe(t.get("description")), s["table_cell_muted"]),
                Paragraph(str(t.get("score", "—")), s["table_cell"]),
            ])
        ctt = Table(ct_data, colWidths=ct_col_w, repeatRows=1)
        ctt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c2d12")),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#fff7ed"), C_WHITE]),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, C_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ctt)
    else:
        if content_verdict == "Not analyzed":
            story.append(Paragraph("Content analysis was not performed — the site was unreachable or page content could not be extracted.", s["body_muted"]))
        else:
            story.append(Paragraph("No specific content threats were detected by the content analysis layer.", s["body_muted"]))

    # ════════════════════════════════════════════════════════════
    # SECTION 7 — Rule-based Notes
    # ════════════════════════════════════════════════════════════
    rule_notes = prediction.get("rule_notes") or []
    if rule_notes:
        story += _section("Rule-Based Risk Flags", s)
        for note in rule_notes:
            story.append(Paragraph(f"• {note}", s["body"]))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "Rule-based flags are applied before the ML model and act as hard-coded heuristic checks "
            "for common phishing patterns (raw IPs, URL shorteners, suspicious keywords, etc.).",
            s["body_muted"],
        ))

    # ════════════════════════════════════════════════════════════
    # SECTION 8 — Model & System Statistics
    # ════════════════════════════════════════════════════════════
    story += _section("Model & System Statistics", s)

    features_meta = scan.get("features") or {}
    stat_rows = [
        ("Extraction Status", _safe(features_meta.get("status"))),
        ("Extraction Note", _safe(features_meta.get("note"))),
        ("Total ML Features Used", str(len([k for k, v in (features_meta.get("model_vector") or {}).items()]))),
        ("Prediction Verdict (Raw)", _safe(verdict)),
    ]
    if risk_score is not None:
        stat_rows.append(("Phishing Probability (raw)", f"{risk_score / 100:.4f}"))
        stat_rows.append(("Safe Probability (raw)", f"{(100 - risk_score) / 100:.4f}"))
    if confidence is not None:
        stat_rows.append(("Model Confidence", _pct(confidence)))

    stat_rows = [(k, v) for k, v in stat_rows if v != "—"]
    story.append(_kv_table(stat_rows, s))

    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "The ML model uses a Random Forest / Gradient Boosting classifier trained on URL, DOM, and domain "
        "features extracted from labelled phishing datasets. Feature importance values reflect global "
        "model weights, not instance-specific SHAP values.",
        s["body_muted"],
    ))

    # ════════════════════════════════════════════════════════════
    # SECTION 9 — Screenshot (if available)
    # ════════════════════════════════════════════════════════════
    screenshot_path = reachability.get("screenshot_path", "")
    if screenshot_path:
        # Convert URL path to local filesystem path
        local_path = screenshot_path.lstrip("/")
        if os.path.exists(local_path):
            story += _section("Page Screenshot", s)
            try:
                from PIL import Image as PILImage
                pil_img = PILImage.open(local_path)
                img_w, img_h = pil_img.size
                max_w = usable_w
                max_h = 80 * mm
                ratio = min(max_w / img_w, max_h / img_h)
                display_w = img_w * ratio
                display_h = img_h * ratio
                img = Image(local_path, width=display_w, height=display_h)
                img.hAlign = "CENTER"
                story.append(img)
                story.append(Paragraph(
                    f"Screenshot captured during headless browser scan of {_safe(reachability.get('final_url', input_url))}",
                    s["caption"],
                ))
            except Exception as e:
                story.append(Paragraph(f"Screenshot available but could not be embedded: {e}", s["body_muted"]))

    # ════════════════════════════════════════════════════════════
    # SECTION 10 — Disclaimer
    # ════════════════════════════════════════════════════════════
    story.append(Spacer(1, 10))
    story.append(_hr())
    story.append(Paragraph(
        "DISCLAIMER: This report is generated automatically by the ShieldScan threat intelligence system. "
        "It is intended for informational and research purposes only. Results reflect heuristic and ML-based "
        "analysis and should not be used as the sole basis for legal or security decisions. Always verify "
        "independently before taking action.",
        ParagraphStyle("DISC", fontName="Helvetica-Oblique", fontSize=7.5, textColor=C_TEXT_MUTED,
                       leading=11, spaceBefore=4),
    ))

    doc.build(story)
    return buf.getvalue()
