from __future__ import annotations

import json
import os
import threading
import uuid
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for, make_response

from scan_engine import empty_scan_response, normalize_and_validate_url, run_canonical_scan, quick_reachability_precheck
from scan_engine import is_domain_reputable, _load_tranco_domains, domain_reputation_rank
from pdf_report import build_pdf

app = Flask(__name__)
job_store = {}

# Warm up the domain reputation index on startup (async, non-blocking)
def _warmup_reputation():
    try:
        _load_tranco_domains()
    except Exception:
        pass

threading.Thread(target=_warmup_reputation, daemon=True).start()

CACHE_DIR = "static/cache"

def cleanup_cache_task():
    """Background task to delete old screenshots from static/cache."""
    cache_path = Path(CACHE_DIR)
    # Ensure cache directory exists
    cache_path.mkdir(parents=True, exist_ok=True)

    while True:
        try:
            now = time.time()
            # Delete files older than 1 hour (3600 seconds)
            for f in cache_path.glob("*.png"):
                if f.is_file():
                    if now - f.stat().st_mtime > 3600:
                        try:
                            f.unlink()
                        except Exception:
                            pass
        except Exception:
            pass
        time.sleep(600)  # Run every 10 minutes

# Start the cleanup thread
threading.Thread(target=cleanup_cache_task, daemon=True).start()

HISTORY_FILE = "scan_history.json"

def get_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def add_to_history(url, level, verdict):
    hist = get_history()
    hist.insert(0, {
        "url": url,
        "level": level,
        "verdict": verdict,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    hist = hist[:50]
    with open(HISTORY_FILE, "w") as f:
        json.dump(hist, f)


SIGNAL_LABELS = {
    "HTTPS": "Uses secure HTTPS connection",
    "AnchorURL": "Links mostly point to trusted domains",
    "RequestURL": "Page requests mostly come from trusted domains",
    "LinksInScriptTags": "Script sources look normal",
    "SubDomains": "Subdomain structure looks normal",
    "ShortURL": "No suspicious URL shortener pattern",
    "Symbol@": "No suspicious @ symbol in URL",
    "PrefixSuffix-": "Domain naming pattern",
    "WebsiteTraffic": "Domain/host visibility signal",
    "AgeofDomain": "Domain age signal",
    "DNSRecording": "WHOIS/registration signal",
    "UsingIP": "URL uses domain instead of raw IP",
    "WebsiteForwarding": "Redirect behavior",
    "AbnormalURL": "URL matches registered domain identity",
    "DomainRegLen": "Domain registration length",
    "Favicon": "Favicon source looks normal",
    "NonStdPort": "Standard port used",
    "HTTPSDomainURL": "HTTPS not embedded in hostname",
    "ServerFormHandler": "Form submission target",
    "InfoEmail": "No mailto links detected",
    "StatusBarCust": "Status bar behavior",
    "DisableRightClick": "Right-click not blocked",
    "UsingPopupWindow": "No suspicious popup behavior",
    "IframeRedirection": "No suspicious iframes",
    "PageRank": "Page authority signal",
    "GoogleIndex": "Site indexing signal",
    "LinksPointingToPage": "Inbound link signal",
    "StatsReport": "Domain reputation report",
    "LongURL": "URL length signal",
    "Redirecting//": "Double-slash redirect signal",
}

SIGNAL_EXPLANATIONS = {
    "HTTPS": {
        "positive": "The scanned URL used HTTPS encryption.",
        "negative": "The scanned URL did not use HTTPS.",
        "neutral": "HTTPS signal was neutral for this scan.",
        "fact": "HTTPS lowers interception risk, but phishing pages can still use HTTPS certificates.",
    },
    "AnchorURL": {
        "positive": "Most page links looked internal/consistent.",
        "negative": "Many page links pointed to external or mixed destinations.",
        "neutral": "Link destination pattern was mixed.",
        "fact": "Phishing pages often embed many external or mismatched links to mimic trusted brands.",
    },
    "RequestURL": {
        "positive": "Resource requests looked mostly consistent with the page domain.",
        "negative": "Page resources were pulled from suspicious or unrelated domains.",
        "neutral": "Resource request pattern was unclear.",
        "fact": "A high ratio of external resource calls is a common phishing signal in URL/content-based detection studies.",
    },
    "LinksInScriptTags": {
        "positive": "Script sources looked normal for this page.",
        "negative": "Script source pattern looked abnormal.",
        "neutral": "Script source signal was neutral.",
        "fact": "Suspicious script/link embedding behavior is frequently used in phishing feature engineering.",
    },
    "SubDomains": {
        "positive": "Subdomain structure looked normal.",
        "negative": "Subdomain depth looked unusual.",
        "neutral": "Subdomain signal was neutral.",
        "fact": "Excessive or deceptive subdomain structure is a known lexical phishing indicator.",
    },
    "AbnormalURL": {
        "positive": "The URL hostname matches the registered domain identity.",
        "negative": "The URL hostname could not be verified against WHOIS records.",
        "neutral": "Domain identity signal was inconclusive.",
        "fact": "Phishing sites often use hostnames that don't match any registered domain identity.",
    },
    "DomainRegLen": {
        "positive": "Domain registration is long-term, suggesting legitimate intent.",
        "negative": "Domain registration is short-term or unknown — common for throwaway phishing infrastructure.",
        "neutral": "Domain registration length signal was neutral.",
        "fact": "Phishing domains are typically registered for very short periods to minimize cost.",
    },
    "PageRank": {
        "positive": "Domain appears to have established authority.",
        "negative": "Domain shows no signs of established web authority — common for newly created phishing sites.",
        "neutral": "Page authority signal was neutral.",
        "fact": "Phishing sites typically have zero external links pointing to them and very low authority.",
    },
    "GoogleIndex": {
        "positive": "Site appears reachable and indexable.",
        "negative": "Site was unreachable — common for short-lived or suspended phishing infrastructure.",
        "neutral": "Site reachability signal was neutral.",
        "fact": "Legitimate sites are generally reachable; phishing infrastructure is often unstable.",
    },
    "PrefixSuffix-": {
        "positive": "Domain naming pattern looked clean.",
        "negative": "Domain naming pattern included risky separators/hyphen usage.",
        "neutral": "Domain naming signal was neutral.",
        "fact": "Brand-like domains with unusual separators are frequently used in phishing impersonation attempts.",
    },
    "ShortURL": {
        "positive": "No short-link masking pattern was detected.",
        "negative": "Short-link masking pattern was detected.",
        "neutral": "Short-link signal was neutral.",
        "fact": "URL shorteners can hide final destinations and are commonly abused in phishing campaigns.",
    },
    "UsingIP": {
        "positive": "A domain name was used instead of a raw IP.",
        "negative": "The link used a raw IP address instead of a domain.",
        "neutral": "IP/hostname signal was neutral.",
        "fact": "Raw IP URLs are often flagged as high-risk in phishing detection rulesets.",
    },
    "WebsiteForwarding": {
        "positive": "Redirect behavior looked limited/normal.",
        "negative": "Redirect behavior looked heavy or suspicious.",
        "neutral": "Redirect behavior was moderate.",
        "fact": "Multiple redirects are frequently used to hide the final malicious destination.",
    },
    "WebsiteTraffic": {
        "positive": "Domain visibility signal looked normal.",
        "negative": "Domain visibility signal looked weak or unavailable.",
        "neutral": "Domain visibility signal was neutral.",
        "fact": "Low reputation/traffic visibility is often used as supporting evidence in phishing scoring.",
    },
    "AgeofDomain": {
        "positive": "Domain age looked mature.",
        "negative": "Domain looked recently created or age was unavailable.",
        "neutral": "Domain age signal was neutral.",
        "fact": "Newly registered domains are overrepresented in phishing infrastructure.",
    },
    "DNSRecording": {
        "positive": "Registration/DNS records were available.",
        "negative": "Registration/DNS records were unavailable or weak.",
        "neutral": "Registration/DNS signal was neutral.",
        "fact": "Missing or inconsistent domain records are common risk indicators in phishing heuristics.",
    },
}

RULE_NOTE_FACTS = {
    "URL host is a raw IP address.": "Attackers often use raw IP links to avoid obvious brand-domain checks.",
    "Shortened URL pattern detected.": "Shortened links can conceal where a user will actually land.",
    "Suspicious URL keywords detected.": "Terms like login/verify/update are frequently used in credential theft messages.",
    "Non-standard port detected in URL.": "Unusual ports are uncommon for normal public login pages and increase caution.",
    "Website reachability is unstable or failed.": "Unstable endpoints are common in disposable malicious infrastructure.",
    "WHOIS metadata unavailable for domain.": "Missing ownership metadata reduces trust and should increase caution.",
}


def _friendly_rule_note(note: str) -> str:
    mapping = {
        "URL host is a raw IP address.": "The link uses a numeric IP address instead of a normal domain name.",
        "Shortened URL pattern detected.": "This looks like a shortened URL, which can hide the real destination.",
        "Suspicious URL keywords detected.": "The link contains high-risk words often used in scam messages.",
        "Non-standard port detected in URL.": "The link uses an uncommon network port.",
        "Website reachability is unstable or failed.": "The website was unstable or could not be reached during checks.",
        "WHOIS metadata unavailable for domain.": "Domain ownership information could not be verified.",
    }
    return mapping.get(note, note)


def _friendly_scan_warning(error_text: str) -> str:
    text = (error_text or "").strip()
    lowered = text.lower()

    if "no module named 'sklearn'" in lowered:
        return "Model files were found, but required ML libraries are missing in this Python environment."
    if "redirect pre-check skipped due to network error" in lowered:
        return "Network-based redirect checks were limited; result was calculated from available signals."
    if "selenium is not installed" in lowered:
        return "Browser automation is not installed, so page-content checks were skipped."
    if "browser/driver setup is required" in lowered or "driver startup failed" in lowered:
        return "Browser driver setup is incomplete, so full page checks could not run."
    if "model bundle not found" in lowered:
        return "Model file is missing. Train or copy the model bundle before scanning."
    return text


def _extract_final_exception_line(text: str) -> str:
    """Given text containing newlines, walk backward to find the last meaningful line.

    Skips traceback frame headers (``File "..."``, indented lines) and the
    ``Traceback (most recent call last):`` preamble.  Returns the original
    string unchanged if no newlines are present.
    """
    if "\n" not in text:
        return text

    for line in reversed(text.strip().split("\n")):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("File ") or stripped.startswith("  "):
            continue
        if "Traceback" in stripped:
            continue
        return stripped

    return text


def _sanitize_error_message(error_text: str) -> str:
    """Convert an internal error string into a short, user-safe message.

    Routes through the existing friendly-warning mapper first.  If no match
    is found, strips traceback frames, file paths, and overly long text so
    the UI never shows raw internal diagnostics.
    """
    text = (error_text or "").strip()
    if not text:
        return "An internal processing error occurred."

    # Defer to the existing friendly mapper when it knows this error
    known = _friendly_scan_warning(text)
    if known and known != text:
        return known

    # Looks like a full traceback -- keep only the final exception line
    text = _extract_final_exception_line(text)

    # Truncate anything still unreasonably long
    if len(text) > 200:
        text = text[:197] + "..."

    # If the result is still a raw file-path dump, replace it entirely
    if "/" in text and (".py" in text or "site-packages" in text):
        return "An internal processing error occurred."

    return text


def compute_scan_confidence(scan: dict) -> dict:
    """Compute a 0-100 data-completeness score and per-layer breakdown."""
    reachability = scan.get("reachability", {}) or {}
    reach_state = str(reachability.get("state", "") or "").lower()
    features = scan.get("features", {}) or {}
    domain_host = features.get("domain_host", {}) or {}
    extraction_status = str(features.get("status", "") or "").lower()
    prediction = scan.get("prediction", {}) or {}
    verdict = prediction.get("verdict", "Unavailable")
    ml_conf = prediction.get("confidence")
    content = scan.get("content_analysis", {}) or {}
    content_verdict = content.get("content_verdict", "Not analyzed")
    text_len = int(content.get("text_length_analyzed", 0) or 0)

    score = 0
    layers = []

    # Layer 1 — URL structure (always available)
    score += 20
    layers.append({"name": "URL Structure", "status": "done",
                   "desc": "30+ lexical features extracted from the URL string"})

    # Layer 1b — Domain Reputation Index (daily-updated global top-sites)
    host = (features.get("url_lexical", {}) or {}).get("host", "")
    if host and is_domain_reputable(host):
        rank = domain_reputation_rank(host)
        rank_str = f" — ranked #{rank:,} globally" if rank else ""
        score += 15
        layers.append({"name": "Domain Reputation Index", "status": "done",
                       "desc": f"Domain appears in top 100K most-visited sites worldwide{rank_str}"})
    else:
        layers.append({"name": "Domain Reputation Index", "status": "partial" if host else "failed",
                       "desc": "Domain not found in global top-sites index"})

    # Layer 2 — Domain & WHOIS (15 pts)
    whois_ok = bool(domain_host.get("whois_available"))
    dns_ok = bool(domain_host.get("dns_resolved"))
    if whois_ok:
        score += 15
        layers.append({"name": "Domain & WHOIS", "status": "done",
                        "desc": "Domain age, registrar, and WHOIS metadata retrieved"})
    elif dns_ok:
        score += 7
        layers.append({"name": "Domain & WHOIS", "status": "partial",
                        "desc": "DNS resolved but WHOIS data was unavailable"})
    else:
        layers.append({"name": "Domain & WHOIS", "status": "failed",
                        "desc": "DNS and WHOIS lookup failed"})

    # Layer 3 — Site reachability (20 pts)
    if reach_state == "reachable":
        score += 20
        layers.append({"name": "Site Reachability", "status": "done",
                        "desc": "Site responded successfully during scan"})
    elif reach_state in ("timeout",):
        score += 5
        layers.append({"name": "Site Reachability", "status": "partial",
                        "desc": "Site timed out — partial data may be available"})
    else:
        layers.append({"name": "Site Reachability", "status": "failed",
                        "desc": "Site was unreachable — content layers skipped"})

    # Layer 4 — DOM analysis (20 pts)
    if "full" in extraction_status:
        score += 20
        layers.append({"name": "DOM Analysis", "status": "done",
                        "desc": "Full page structure, forms, and scripts analysed"})
    elif "partial" in extraction_status:
        score += 8
        layers.append({"name": "DOM Analysis", "status": "partial",
                        "desc": "Partial DOM extracted — some features missing"})
    else:
        layers.append({"name": "DOM Analysis", "status": "failed",
                        "desc": "DOM not available — page could not be loaded"})

    # Layer 5 — ML classifier (15 pts)
    if verdict not in ("Unavailable", "", None):
        ml_pts = 15
        if isinstance(ml_conf, (int, float)):
            ml_pts = max(5, int(15 * min(float(ml_conf) / 100.0, 1.0)))
        score += ml_pts
        layers.append({"name": "ML Classifier", "status": "done",
                        "desc": f"Phishing model returned verdict: {verdict}"})
    else:
        layers.append({"name": "ML Classifier", "status": "failed",
                        "desc": "Model unavailable — no trained classifier loaded"})

    # Layer 6 — Content analysis (10 pts)
    if content_verdict != "Not analyzed" and text_len > 50:
        score += 10
        layers.append({"name": "Content Analysis", "status": "done",
                        "desc": f"Analysed {text_len:,} characters of page text"})
    elif content_verdict != "Not analyzed":
        score += 3
        layers.append({"name": "Content Analysis", "status": "partial",
                        "desc": "Content check ran but page text was minimal"})
    else:
        layers.append({"name": "Content Analysis", "status": "failed",
                        "desc": "No page text available for content analysis"})

    score = min(100, max(0, score))

    if score >= 75:
        tier, tier_color = "High", "green"
        tier_desc = "All major scan layers completed — verdict is well-supported."
    elif score >= 45:
        tier, tier_color = "Medium", "amber"
        tier_desc = "Partial scan — verdict is based on URL structure and domain data."
    else:
        tier, tier_color = "Low", "red"
        tier_desc = "Limited data — only surface-level features were available."

    return {
        "score": score,
        "tier": tier,
        "tier_color": tier_color,
        "tier_desc": tier_desc,
        "layers": layers,
    }


def build_user_friendly_summary(scan: dict) -> dict:
    prediction = scan.get("prediction", {}) or {}
    verdict = prediction.get("verdict", "Unavailable")
    risk_score = prediction.get("risk_score")
    confidence = prediction.get("confidence")
    reachability = scan.get("reachability", {}) or {}
    reachability_state = str(reachability.get("state", "") or "").lower()

    if verdict == "Phishing":
        level = "High Risk"
        headline = "This link is likely unsafe."
    elif verdict == "Suspicious":
        level = "Needs Caution"
        headline = "This link has mixed signals."
    elif verdict == "Legitimate":
        if reachability_state in {"timeout", "unreachable", "setup_required"}:
            level = "Check Incomplete"
            headline = "Full risk decision is not available because the site was unreachable."
        else:
            level = "Likely Safe"
            headline = "This link appears mostly safe."
    else:
        level = "Check Incomplete"
        headline = "Full risk decision is not available yet."

    quick_facts: list[str] = []
    # Domain reputation check
    host = ((scan.get("features") or {}).get("url_lexical") or {}).get("host", "")
    if host and is_domain_reputable(host):
        rank = domain_reputation_rank(host)
        if rank:
            quick_facts.append(f"Domain ranked #{rank:,} among top global sites — daily-updated reputation index.")
        else:
            quick_facts.append("Domain verified against daily-updated global top-sites reputation index.")
    if isinstance(risk_score, (int, float)):
        quick_facts.append(f"Estimated phishing risk: {float(risk_score):.2f}%")
    if isinstance(confidence, (int, float)):
        quick_facts.append(f"Model confidence: {float(confidence):.2f}%")
    if reachability_state == "reachable":
        quick_facts.append("Website responded during scan.")
    elif reachability_state in {"timeout", "unreachable"}:
        quick_facts.append("Website was unstable or unreachable during scan.")
    elif reachability_state == "setup_required":
        quick_facts.append("Browser automation setup is required for full page checks.")

    reasons: list[str] = []
    for note in prediction.get("rule_notes", []) or []:
        reasons.append(_friendly_rule_note(str(note)))

    for signal in (scan.get("top_signals", []) or [])[:3]:
        name = SIGNAL_LABELS.get(signal.get("feature", ""), signal.get("feature", "Signal"))
        note = str(signal.get("note", "")).lower()
        if "risk" in note:
            reasons.append(f"{name} increased risk in this scan.")
        elif "safe" in note:
            reasons.append(f"{name} looked normal in this scan.")
        else:
            reasons.append(f"{name} had a neutral effect in this scan.")

    if not reasons:
        reasons.append("Limited indicators were available for explanation.")

    evidence_items: list[dict[str, str]] = []

    # Domain reputation check (daily-updated global index)
    host = ((scan.get("features") or {}).get("url_lexical") or {}).get("host", "")
    if host and is_domain_reputable(host):
        rank = domain_reputation_rank(host)
        rank_desc = f" — ranked #{rank:,} globally" if rank else ""
        evidence_items.append({
            "title": "Global Domain Authority",
            "feature": "reputation_index",
            "value": "Verified" if rank else "Listed",
            "impact": "+trust",
            "direction": "safer",
            "finding": f"This domain appears in a daily-updated index of the top 100,000 most-visited websites worldwide{rank_desc}.",
            "fact": "Legitimate sites consistently rank among the world's most-visited domains; phishing sites rarely appear in top-sites indices.",
        })

    for signal in (scan.get("top_signals", []) or [])[:4]:
        feature = str(signal.get("feature", "Signal"))
        value = int(signal.get("value", 0))
        impact = float(signal.get("impact", 0.0) or 0.0)
        signed_impact = float(signal.get("signed_impact", impact if value >= 0 else -impact))
        detail = SIGNAL_EXPLANATIONS.get(feature)

        if detail:
            if value > 0:
                finding = detail["positive"]
                direction = "safer"
            elif value < 0:
                finding = detail["negative"]
                direction = "riskier"
            else:
                finding = detail["neutral"]
                direction = "neutral"
            fact = detail["fact"]
        else:
            finding = "This feature influenced the model result."
            direction = "riskier" if signed_impact < 0 else ("neutral" if signed_impact == 0 else "safer")
            fact = "Feature-based phishing models combine multiple weak signals into one final risk score."

        evidence_items.append(
            {
                "title": SIGNAL_LABELS.get(feature, feature),
                "feature": feature,
                "value": str(value),
                "impact": f"{impact:.6f}",
                "direction": direction,
                "finding": finding,
                "fact": fact,
            }
        )

    for note in (prediction.get("rule_notes", []) or [])[:2]:
        clean_note = str(note)
        evidence_items.append(
            {
                "title": "Risk Rule Trigger",
                "feature": "rule_note",
                "value": "-",
                "impact": "-",
                "direction": "riskier",
                "finding": _friendly_rule_note(clean_note),
                "fact": RULE_NOTE_FACTS.get(
                    clean_note,
                    "Rule-based checks are used as supporting evidence alongside ML output.",
                ),
            }
        )

    confidence_text = "Model confidence is high for this specific prediction."
    if isinstance(confidence, (int, float)):
        conf = float(confidence)
        if conf < 70:
            confidence_text = "Model confidence is moderate, so treat this as caution guidance."
        elif conf < 85:
            confidence_text = "Model confidence is good, but still verify before sharing sensitive data."

    warnings = [_sanitize_error_message(str(err)) for err in (scan.get("errors", []) or [])]

    # --- Content-based threat analysis (Layer 2) ---
    content_analysis = scan.get("content_analysis") or {}
    content_threats = content_analysis.get("threats_detected", [])
    content_verdict = content_analysis.get("content_verdict", "Not analyzed")
    content_severity = content_analysis.get("content_severity", "safe")

    # If content layer detected something dangerous and ML says Legitimate,
    # upgrade the overall level shown to user
    effective_level = level
    effective_headline = headline
    if content_severity == "danger" and verdict == "Legitimate":
        effective_level = "Content Risk"
        effective_headline = "URL structure looks clean, but page content is suspicious."
    elif content_severity == "warning" and verdict == "Legitimate":
        effective_level = "Needs Caution"
        effective_headline = "Page content contains potentially unsafe material."

    for threat in reversed(content_threats):
        evidence_items.insert(0, {
            "title": threat.get("label", "Content Threat"),
            "feature": "content_rule",
            "value": "Detected",
            "impact": str(threat.get("score", 0)),
            "direction": "riskier",
            "finding": threat.get("description", ""),
            "fact": "Matches: " + ", ".join(threat.get("sample_matches", [])),
        })

    if effective_level == "Check Incomplete":
        evidence_items = [{
            "title": "Analysis Incomplete",
            "feature": "reachability",
            "value": "Unreachable",
            "impact": "-",
            "direction": "neutral",
            "finding": "The website could not be reached to perform a full content and structural scan.",
            "fact": "Models rely on default values when content is unreachable, which skews the evidence provided."
        }]

    return {
        "level": effective_level,
        "headline": effective_headline,
        "quick_facts": quick_facts,
        "reasons": reasons[:6],
        "confidence_text": confidence_text,
        "evidence_items": evidence_items[:8],
        "warnings": warnings,
        "verdict": verdict,
        "content_verdict": content_verdict,
        "content_severity": content_severity,
        "content_threats": content_threats,
        "confidence_meter": compute_scan_confidence(scan),
    }


@app.route("/favicon.ico")
def favicon():
    return redirect(url_for('static', filename='icons/favicon-32.png'))

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        input_url = request.form.get("url", "").strip()
        job_id = str(uuid.uuid4())
        job_store[job_id] = {
            "status": "Initializing...",
            "done": False,
            "scan": None,
            "friendly": None,
            "input_url": input_url
        }

        def background_scan(jid, url):
            def cb(msg):
                if jid in job_store:
                    job_store[jid]["status"] = msg
            try:
                # Fast pre-check: DNS + HEAD before the full scan starts
                if jid in job_store:
                    job_store[jid]["status"] = "Checking if site is reachable..."
                precheck = quick_reachability_precheck(url, timeout=4)
                if jid in job_store:
                    job_store[jid]["precheck"] = precheck

                scan = run_canonical_scan(url, status_callback=cb, job_id=jid, precheck_result=precheck)
                friendly = build_user_friendly_summary(scan)
                if jid in job_store:
                    job_store[jid]["scan"] = scan
                    job_store[jid]["friendly"] = friendly

                    if scan.get("validation", {}).get("ok"):
                        add_to_history(url, friendly.get("level"), scan.get("prediction", {}).get("verdict", "Unknown"))
            except Exception as e:
                if jid in job_store:
                    scan = empty_scan_response()
                    scan["validation"] = {"ok": False, "normalized_url": url, "error": str(e)}
                    scan["errors"] = [str(e)]
                    job_store[jid]["scan"] = scan
                    job_store[jid]["friendly"] = build_user_friendly_summary(scan)
            finally:
                if jid in job_store:
                    job_store[jid]["done"] = True

        t = threading.Thread(target=background_scan, args=(job_id, input_url))
        t.start()

        return redirect(url_for("result_page", job_id=job_id))

    return render_template(
        "index.html",
        input_url="",
        status="",
        message="",
        scan=empty_scan_response(),
        friendly={},
        loading=False,
        history=get_history()
    )

@app.route("/result/<job_id>", methods=["GET"])
def result_page(job_id):
    job = job_store.get(job_id)
    if not job:
        return redirect(url_for("index"))
        
    if not job["done"]:
        return render_template(
            "report.html",
            input_url=job["input_url"],
            status="",
            message="",
            scan=empty_scan_response(),
            friendly={},
            loading=True,
            job_id=job_id,
            current_status=job["status"]
        )
        
    scan = job["scan"]
    friendly = job["friendly"]
    status_str = "ok" if scan and scan.get("validation", {}).get("ok") else "error"
    message = (
        "Scan completed successfully."
        if status_str == "ok"
        else _sanitize_error_message(scan.get("validation", {}).get("error") or "Validation failed.")
    )

    return render_template(
        "report.html",
        input_url=job["input_url"],
        status=status_str,
        message=message,
        scan=scan,
        friendly=friendly,
        loading=False,
        job_id=job_id,
        history=get_history()
    )

@app.route("/api/scan/status/<job_id>", methods=["GET"])
def api_scan_status(job_id):
    job = job_store.get(job_id)
    if not job:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status": job["status"],
        "done": job["done"],
        "precheck": job.get("precheck")
    })

@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(silent=True) or {}
    input_url = str(payload.get("url", "")).strip()

    scan = run_canonical_scan(input_url)
    status_code = 200 if scan["validation"]["ok"] else 400
    return jsonify(scan), status_code


EXPORTABLE_LEVELS = {"High Risk", "Needs Caution", "Likely Safe", "Content Risk"}

@app.route("/pdf/<job_id>", methods=["GET"])
def export_pdf(job_id):
    job = job_store.get(job_id)
    if not job or not job.get("done"):
        return "Scan not found or not yet complete.", 404

    scan = job.get("scan")
    friendly = job.get("friendly")
    if not scan or not friendly:
        return "No scan data available.", 404

    level = friendly.get("level", "")
    if level not in EXPORTABLE_LEVELS:
        return "PDF export is only available for completed scans with a definitive result.", 400

    try:
        input_url = job.get("input_url", "")
        pdf_bytes = build_pdf(scan, friendly, input_url)
    except Exception as e:
        return f"PDF generation failed: {e}", 500

    safe_host = (scan.get("validation") or {}).get("normalized_url", "scan")
    safe_host = safe_host.replace("https://", "").replace("http://", "").split("/")[0]
    safe_host = "".join(c if c.isalnum() or c in "-_." else "_" for c in safe_host)[:40]
    filename = f"shieldscan_{safe_host}.pdf"

    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
