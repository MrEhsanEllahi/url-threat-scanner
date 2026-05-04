from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from typing import Any
import ipaddress
import math
import pickle
import re
import socket
from urllib.parse import parse_qsl, urljoin, urlparse


FEATURE_COLUMNS = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport",
]

SUSPICIOUS_TOKENS = {
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "wallet",
    "invoice",
    "bank",
    "password",
    "auth",
    "support",
}


# ---------------------------------------------------------------------------
# Content-based Threat Classification (Layer 2)
# No external API — pure keyword/pattern scoring on extracted page text + DOM
# ---------------------------------------------------------------------------

CONTENT_THREAT_CATEGORIES: dict[str, dict] = {
    "betting_gambling": {
        "keywords": [
            "bet", "betting", "sportsbook", "odds", "casino", "poker", "roulette",
            "blackjack", "slot", "slots", "jackpot", "wager", "wagering", "bookie",
            "bookmaker", "gambling", "gamble", "esports bet", "cricket bet",
            "football bet", "live bet", "accumulator", "parlay", "1xbet", "betway",
            "melbet", "mostbet", "parimatch", "bc game", "stake casino",
            "place your bet", "deposit to win", "withdraw winnings",
            "free spins", "bonus bet", "no deposit bonus", "welcome bonus casino",
        ],
        "url_keywords": [
            "bet", "casino", "poker", "slots", "gambl", "wager", "bookie",
            "sportsbook", "odds", "jackpot",
        ],
        "weight": 2.5,
        "max_score": 100,
        "label": "Betting / Gambling",
        "description": "This site appears to offer online gambling or sports betting services.",
        "severity": "warning",
    },
    "financial_scam": {
        "keywords": [
            "guaranteed profit", "guaranteed returns", "100% profit", "risk free profit",
            "double your money", "triple your investment", "get rich quick",
            "passive income daily", "earn daily", "earn from home", "unlimited earning",
            "investment scheme", "ponzi", "pyramid scheme", "mlm scheme",
            "refer and earn", "unlimited referral", "multi-level marketing",
            "crypto investment", "bitcoin investment", "forex signal",
            "forex robot", "trading robot", "auto trading", "copy trading profit",
            "withdraw anytime", "instant withdrawal", "no risk investment",
            "roi guaranteed", "high returns guaranteed",
            "make money online fast", "zero risk", "financial freedom fast",
        ],
        "url_keywords": [
            "invest", "profit", "earn", "income", "forex", "crypto-earn",
            "richfast", "doublebtc", "getrich",
        ],
        "weight": 4.0,
        "max_score": 100,
        "label": "Financial Scam / Fraud",
        "description": "This site shows strong indicators of investment fraud or financial scam.",
        "severity": "danger",
    },
    "fake_shop": {
        "keywords": [
            "limited time offer", "flash sale", "mega discount",
            "90% off", "95% off", "clearance sale everything must go",
            "luxury brand replica", "first copy", "aaa grade replica",
            "original copy", "master copy", "super clone",
            "pay via western union", "pay via gift card", "pay bitcoin only",
            "no refund policy", "all sales final", "whatsapp to order",
        ],
        "url_keywords": [
            "replica", "outlet", "clearance", "cheap-brand", "fake-shop",
        ],
        "weight": 3.0,
        "max_score": 100,
        "label": "Fake / Scam Online Shop",
        "description": "This site shows patterns consistent with fake or fraudulent online shops.",
        "severity": "danger",
    },
    "adult_illegal": {
        "keywords": [
            "18+ only", "adults only", "xxx", "escort service", "call girls",
            "drug buy online", "buy weed online", "buy cocaine",
            "darkweb market", "dark web shop", "tor market",
        ],
        "url_keywords": [
            "xxx", "adult", "escort", "nude", "drug", "weed",
        ],
        "weight": 5.0,
        "max_score": 100,
        "label": "Adult / Illegal Content",
        "description": "This site appears to contain adult content or links to illegal services.",
        "severity": "danger",
    },
    "crypto_scam": {
        "keywords": [
            "send crypto to receive more", "send bitcoin get double",
            "elon musk giveaway", "crypto giveaway", "free bitcoin giveaway",
            "send eth receive back", "mining profit daily",
            "cloud mining guaranteed", "free crypto airdrop claim now",
            "connect wallet to claim", "approve transaction",
            "unlimited token approval", "presale now", "buy before listing",
            "100x coin", "next bitcoin", "telegram pump group",
        ],
        "url_keywords": [
            "giveaway", "airdrop", "freecrypto", "doublebtc", "mining-profit",
            "claim-token", "crypto-reward",
        ],
        "weight": 4.5,
        "max_score": 100,
        "label": "Crypto Scam",
        "description": "This site shows strong signals of a cryptocurrency scam or wallet draining scheme.",
        "severity": "danger",
    },
}

CONTENT_THREAT_WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "wikipedia.org", "reddit.com", "linkedin.com", "github.com",
    "amazon.com", "ebay.com", "microsoft.com", "apple.com",
    "bbc.com", "cnn.com", "reuters.com", "nytimes.com",
    "dawn.com", "geo.tv", "arynews.tv",
}

def classify_content_threats(
    page_text: str,
    page_title: str,
    url: str,
    url_lexical: dict,
) -> dict:
    """Rule-based content threat classifier. No external API."""
    from urllib.parse import urlparse as _urlparse

    host = (_urlparse(url).hostname or "").lower().removeprefix("www.")
    is_whitelisted = any(
        host == wl or host.endswith("." + wl)
        for wl in CONTENT_THREAT_WHITELIST_DOMAINS
    )

    text_lower = (page_text or "").lower()
    title_lower = (page_title or "").lower()
    url_lower = url.lower()

    detected: list[dict] = []

    for cat_key, cat in CONTENT_THREAT_CATEGORIES.items():
        score = 0.0
        matched_keywords: list[str] = []

        if not is_whitelisted:
            for kw in cat["keywords"]:
                if kw.lower() in text_lower:
                    score += cat["weight"]
                    matched_keywords.append(kw)
                    if kw.lower() in title_lower:
                        score += cat["weight"]  # title match = double weight

            for ukw in cat.get("url_keywords", []):
                if ukw.lower() in url_lower:
                    score += cat["weight"] * 1.5
                    matched_keywords.append(f"[URL] {ukw}")

        score = min(score, cat["max_score"])

        if score >= 10:
            detected.append({
                "category": cat_key,
                "label": cat["label"],
                "description": cat["description"],
                "severity": cat["severity"],
                "score": round(score, 1),
                "matched_count": len(matched_keywords),
                "sample_matches": list(dict.fromkeys(matched_keywords))[:5],
            })

    detected.sort(key=lambda x: x["score"], reverse=True)

    if not detected:
        content_verdict = "Clean"
        content_severity = "safe"
    elif any(d["severity"] == "danger" for d in detected):
        content_verdict = "Dangerous Content Detected"
        content_severity = "danger"
    else:
        content_verdict = "Suspicious Content Detected"
        content_severity = "warning"

    return {
        "content_verdict": content_verdict,
        "content_severity": content_severity,
        "threats_detected": detected,
        "is_whitelisted": is_whitelisted,
        "text_length_analyzed": len(page_text),
    }


def extract_page_text_from_dom(driver) -> str:
    """Extract visible page text from Selenium driver for content analysis."""
    try:
        body_text = driver.execute_script(
            "return document.body ? document.body.innerText : '';"
        )
        if body_text:
            return str(body_text)[:8000]
    except Exception:
        pass
    try:
        source = driver.page_source or ""
        clean = re.sub(r"<[^>]+>", " ", source)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean[:8000]
    except Exception:
        return ""


SHORTENER_PATTERN = re.compile(
    r"bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|"
    r"tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|snipurl\\.com|short\\.to|budurl\\.com|"
    r"ping\\.fm|post\\.ly|snipr\\.com|doiop\\.com|short\\.ie|kl\\.am|wp\\.me|"
    r"rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|lnkd\\.in|db\\.tt|qr\\.ae|adf\\.ly|"
    r"q\\.gs|po\\.st|bc\\.vc|u\\.to|j\\.mp|cutt\\.us|yourls\\.org|v\\.gd|link\\.zip\\.net",
    re.IGNORECASE,
)

PRIVATE_SUFFIXES = {
    "local",
    "localhost",
    "internal",
    "intranet",
    "corp",
    "home",
    "lan",
    "localdomain",
}

BROWSER_TIMEOUT_SECONDS = 12
MODEL_BUNDLE_PATH = Path(__file__).resolve().parent / "artifacts" / "phishing_model_bundle.pkl"
USER_AGENT = "Mozilla/5.0 (compatible; FYP-URL-Threat-Scanner/1.0)"

_MODEL_CACHE: dict[str, Any] = {"bundle": None, "error": ""}


def compute_schema_hash(columns: list[str]) -> str:
    payload = "|".join(columns)
    return sha256(payload.encode("utf-8")).hexdigest()


def empty_reachability() -> dict[str, Any]:
    return {
        "state": "",
        "label": "",
        "detail": "",
        "engine": "",
        "final_url": "",
        "title": "",
        "load_time": "",
        "redirect_hops": 0,
    }


def empty_features() -> dict[str, Any]:
    return {
        "status": "",
        "note": "",
        "url_lexical": {},
        "page_dom": {},
        "domain_host": {},
        "model_vector": {},
        "schema_hash": compute_schema_hash(FEATURE_COLUMNS),
    }


def empty_prediction() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "verdict": "Unavailable",
        "risk_score": None,
        "confidence": None,
        "phishing_probability": None,
        "safe_probability": None,
        "model_version": "",
        "top_signals": [],
        "rule_notes": [],
        "error": "Model not available.",
    }


def empty_scan_response() -> dict[str, Any]:
    prediction = empty_prediction()
    return {
        "validation": {"ok": False, "normalized_url": "", "error": ""},
        "reachability": empty_reachability(),
        "features": empty_features(),
        "prediction": prediction,
        "content_analysis": {
            "content_verdict": "Not analyzed",
            "content_severity": "safe",
            "threats_detected": [],
            "is_whitelisted": False,
            "text_length_analyzed": 0,
        },
        "confidence": prediction["confidence"],
        "top_signals": prediction["top_signals"],
        "errors": [],
    }


def is_valid_public_hostname(host: str) -> bool:
    if not host or host.startswith(".") or host.endswith("."):
        return False
    if len(host) > 253 or "." not in host:
        return False

    labels = host.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False

    tld = labels[-1].lower()
    if tld in PRIVATE_SUFFIXES:
        return False
    if len(tld) < 2 or tld.isdigit():
        return False
    return True


def normalize_and_validate_url(raw_url: str) -> tuple[str, str]:
    candidate = (raw_url or "").strip()
    if not candidate:
        return "", "Please enter a URL."
    if "\\" in candidate:
        return "", "URL must not contain backslashes."
    if re.search(r"\s", candidate):
        return "", "URL must not contain spaces."

    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", candidate):
        return "", "Please enter a website URL, not an email address."

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"

    if len(candidate) > 2048:
        return "", "URL is too long."

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        return "", "Only http/https URLs are allowed."
    if not parsed.netloc:
        return "", "Please enter a valid URL with a domain."
    if parsed.username or parsed.password:
        return "", "URL must not contain username/password or email-style credentials."

    try:
        port = parsed.port
    except ValueError:
        return "", "Invalid port number."

    if port == 0:
        return "", "Invalid port number."

    if port is not None and port not in {80, 443}:
        # Non-standard ports are allowed but explicitly tracked in risk features.
        pass

    host = parsed.hostname
    if not host:
        return "", "Please enter a valid hostname."

    if host.lower() == "localhost":
        return "", "Localhost URLs are not allowed for this scanner."

    try:
        host_ascii = host.encode("idna").decode("ascii")
    except Exception:
        return "", "Please enter a valid public domain."

    try:
        ip = ipaddress.ip_address(host_ascii)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return "", "Private/local IP addresses are not allowed for this scanner."
    except ValueError:
        if not is_valid_public_hostname(host_ascii):
            return "", "Please enter a valid public domain."

    return candidate, ""


def validate_redirect_chain(url: str, max_hops: int = 8, timeout_seconds: int = 5) -> dict[str, Any]:
    result = {
        "ok": True,
        "error": "",
        "warning": "",
        "hops": [],
        "final_url": url,
    }

    try:
        import requests
    except ModuleNotFoundError:
        result["warning"] = "requests library unavailable; redirect pre-check skipped."
        return result

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    current_url = url
    seen: set[str] = set()

    for hop in range(1, max_hops + 1):
        if current_url in seen:
            result["ok"] = False
            result["error"] = "Redirect loop detected."
            result["final_url"] = current_url
            return result
        seen.add(current_url)

        try:
            response = session.get(current_url, allow_redirects=False, timeout=timeout_seconds)
        except requests.RequestException as ex:
            result["warning"] = f"Redirect pre-check skipped due to network error: {ex.__class__.__name__}."
            result["final_url"] = current_url
            return result

        status_code = int(response.status_code)
        location = response.headers.get("Location", "")
        result["hops"].append(
            {
                "hop": hop,
                "url": current_url,
                "status_code": status_code,
                "location": location,
            }
        )

        if status_code not in {301, 302, 303, 307, 308} or not location:
            result["final_url"] = current_url
            return result

        next_url = urljoin(current_url, location)
        normalized_next, validation_error = normalize_and_validate_url(next_url)
        if validation_error:
            result["ok"] = False
            result["error"] = f"Blocked redirect target: {validation_error}"
            result["final_url"] = next_url
            return result

        current_url = normalized_next

    result["ok"] = False
    result["error"] = "Too many redirects in pre-check."
    result["final_url"] = current_url
    return result


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_url_lexical_features(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    host_ascii = host.encode("idna").decode("ascii") if host else ""
    path = parsed.path or ""
    query = parsed.query or ""
    subdomain_depth = max(0, len(host_ascii.split(".")) - 2) if host_ascii and "." in host_ascii else 0

    special_char_count = len(re.findall(r"[^A-Za-z0-9]", url))
    query_keys = [k for k, _ in parse_qsl(query, keep_blank_values=True)]

    host_digits = sum(1 for ch in host_ascii if ch.isdigit())
    host_alpha_num = sum(1 for ch in host_ascii if ch.isalnum())
    host_digit_ratio = round(host_digits / host_alpha_num, 4) if host_alpha_num else 0.0

    lowered = url.lower()
    suspicious_token_count = sum(1 for token in SUSPICIOUS_TOKENS if token in lowered)

    has_ip_host = False
    try:
        ipaddress.ip_address(host_ascii)
        has_ip_host = True
    except ValueError:
        pass

    return {
        "scheme": parsed.scheme,
        "host": host_ascii,
        "url_length": len(url),
        "special_char_count": special_char_count,
        "subdomain_depth": subdomain_depth,
        "path_depth": path.count("/") if path else 0,
        "query_param_count": len(query_keys),
        "query_entropy": round(shannon_entropy(query), 4),
        "suspicious_token_count": suspicious_token_count,
        "has_ip_host": has_ip_host,
        "has_at_symbol": "@" in url,
        "has_credentials": bool(parsed.username or parsed.password),
        "has_hyphenated_domain": "-" in host_ascii,
        "host_digit_ratio": host_digit_ratio,
        "has_non_standard_port": parsed.port not in (None, 80, 443),
        "shortener_hint": bool(SHORTENER_PATTERN.search(url)),
        "double_slash_redirect_hint": url.rfind("//") > 7,
        "https_in_hostname": "https" in host_ascii.lower(),
    }


def _safe_date(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, list):
        for item in value:
            dt_value = _safe_date(item)
            if dt_value is not None:
                return dt_value
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return None


def extract_domain_host_features(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    host_ascii = host.encode("idna").decode("ascii") if host else ""
    output: dict[str, Any] = {
        "host": host_ascii,
        "tld": host_ascii.split(".")[-1] if host_ascii and "." in host_ascii else "",
        "dns_resolved": False,
        "resolved_ips": [],
        "asn": "",
        "whois_available": False,
        "domain_age_days": None,
        "domain_expires_in_days": None,
        "registrar": "",
        "status": "partial",
        "note": "Domain metadata partially available.",
    }

    try:
        addr_info = socket.getaddrinfo(host_ascii, None)
        ips = sorted({item[4][0] for item in addr_info if item and item[4]})
        output["resolved_ips"] = ips[:5]
        output["dns_resolved"] = bool(ips)
    except Exception:
        output["dns_resolved"] = False

    try:
        import whois

        whois_data = whois.whois(host_ascii)
        created = _safe_date(getattr(whois_data, "creation_date", None))
        expires = _safe_date(getattr(whois_data, "expiration_date", None))
        registrar = getattr(whois_data, "registrar", "") or ""

        now = datetime.now(timezone.utc)
        if created is not None:
            output["domain_age_days"] = max(0, (now - created).days)
        if expires is not None:
            output["domain_expires_in_days"] = (expires - now).days

        output["registrar"] = str(registrar)
        output["whois_available"] = True
    except Exception:
        output["whois_available"] = False

    if output["dns_resolved"] and output["whois_available"]:
        output["status"] = "full"
        output["note"] = "Domain metadata fully available."
    elif output["dns_resolved"]:
        output["status"] = "partial"
        output["note"] = "DNS available; WHOIS unavailable."
    else:
        output["status"] = "partial"
        output["note"] = "DNS and WHOIS lookups unavailable."

    return output


def _classify_driver_error(error_text: str) -> tuple[str, str]:
    text = (error_text or "").lower()
    if "permission denied" in text or "operation not permitted" in text:
        return "setup_required", "Browser automation is blocked by system permissions."
    if "too many redirects" in text or "err_too_many_redirects" in text:
        return "unreachable", "Too many redirects were detected."
    if "name not resolved" in text or "err_name_not_resolved" in text:
        return "unreachable", "DNS resolution failed."
    if "connection refused" in text or "err_connection_refused" in text:
        return "unreachable", "Connection refused by host."
    if "err_connection_timed_out" in text or "timed out" in text:
        return "timeout", "Website response timed out."
    if (
        "unable to obtain driver" in text
        or "cannot find chrome binary" in text
        or "browser binary" in text
        or ("driver" in text and "not found" in text)
        or "session not created" in text
    ):
        return "setup_required", "Browser/driver setup is required on this machine."
    return "driver_error", "Browser automation failed to start."


def _dom_safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(float(numerator) / float(denominator), 4)


def _collect_dom_features(driver, final_url: str) -> dict[str, Any]:
    from selenium.webdriver.common.by import By

    parsed_final = urlparse(final_url)
    final_host = (parsed_final.hostname or "").lower()

    anchors = driver.find_elements(By.TAG_NAME, "a")
    scripts = driver.find_elements(By.TAG_NAME, "script")
    forms = driver.find_elements(By.TAG_NAME, "form")

    anchor_hrefs = [a.get_attribute("href") or "" for a in anchors]
    script_src = [s.get_attribute("src") or "" for s in scripts]
    form_actions = [f.get_attribute("action") or "" for f in forms]

    def _is_external(link: str) -> bool:
        if not link:
            return False
        parsed = urlparse(link)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        return host != final_host

    external_anchor_count = sum(1 for href in anchor_hrefs if _is_external(href))
    external_script_count = sum(1 for src in script_src if _is_external(src))
    external_form_count = sum(1 for action in form_actions if _is_external(action))

    mailto_links = sum(1 for href in anchor_hrefs if href.lower().startswith("mailto:"))
    password_inputs = len(driver.find_elements(By.CSS_SELECTOR, "input[type='password']"))
    iframe_count = len(driver.find_elements(By.TAG_NAME, "iframe"))

    page_source = driver.page_source or ""
    page_source_lower = page_source.lower()

    hidden_elements = driver.execute_script(
        "return document.querySelectorAll('[type=\"hidden\"],[hidden],[style*=\"display:none\"],[style*=\"visibility:hidden\"]').length;"
    )
    right_click_blocked = bool(driver.execute_script("return !!document.oncontextmenu;"))

    popup_signals = page_source_lower.count("window.open")
    statusbar_signals = page_source_lower.count("window.status")

    favicon_links = driver.find_elements(By.CSS_SELECTOR, "link[rel*='icon']")
    external_favicon_count = sum(1 for link in favicon_links if _is_external(link.get_attribute("href") or ""))

    return {
        "title": (driver.title or "").strip(),
        "title_length": len((driver.title or "").strip()),
        "form_count": len(forms),
        "password_input_count": password_inputs,
        "iframe_count": iframe_count,
        "script_count": len(scripts),
        "anchor_count": len(anchors),
        "hidden_element_count": int(hidden_elements or 0),
        "external_anchor_ratio": _dom_safe_ratio(external_anchor_count, len(anchors)),
        "external_script_ratio": _dom_safe_ratio(external_script_count, len(scripts)),
        "external_form_action_ratio": _dom_safe_ratio(external_form_count, len(forms)),
        "mailto_links": mailto_links,
        "popup_signal_count": popup_signals,
        "statusbar_signal_count": statusbar_signals,
        "right_click_blocked": right_click_blocked,
        "page_source_length": len(page_source),
        "external_favicon_ratio": _dom_safe_ratio(external_favicon_count, len(favicon_links)),
    }


def run_selenium_reachability_and_dom(url: str, timeout_seconds: int = BROWSER_TIMEOUT_SECONDS, job_id: str = None) -> dict[str, Any]:
    start = perf_counter()
    try:
        from selenium import webdriver
        from selenium.common.exceptions import TimeoutException, WebDriverException
    except ModuleNotFoundError:
        return {
            "reachability": {
                "state": "setup_required",
                "label": "Setup Required",
                "detail": "Selenium is not installed. Run: pip install -r requirements.txt",
                "engine": "",
                "final_url": "",
                "title": "",
                "load_time": "",
                "redirect_hops": 0,
            },
            "dom_status": "skipped",
            "dom_note": "Selenium unavailable; DOM extraction skipped.",
            "dom_features": {},
        }

    browser_attempts: list[str] = []
    driver = None
    engine_name = ""

    for engine in ("chrome", "firefox"):
        try:
            if engine == "chrome":
                options = webdriver.ChromeOptions()
                options.add_argument("--headless=new")
                options.add_argument("--disable-gpu")
                options.add_argument("--no-sandbox")
                options.add_argument("--window-size=1280,900")
                driver = webdriver.Chrome(options=options)
            else:
                options = webdriver.FirefoxOptions()
                options.add_argument("-headless")
                driver = webdriver.Firefox(options=options)
            engine_name = engine
            break
        except Exception as ex:
            browser_attempts.append(f"{engine}: {ex}")

    if driver is None:
        state, detail = _classify_driver_error(" | ".join(browser_attempts))
        return {
            "reachability": {
                "state": state,
                "label": "Setup Required" if state == "setup_required" else "Driver Error",
                "detail": detail,
                "engine": "",
                "final_url": "",
                "title": "",
                "load_time": "",
                "redirect_hops": 0,
            },
            "dom_status": "skipped",
            "dom_note": "Browser driver startup failed.",
            "dom_features": {},
        }

    try:
        driver.set_page_load_timeout(timeout_seconds)
        driver.get(url)
        elapsed = round(perf_counter() - start, 2)
        final_url = driver.current_url or url
        dom_features = _collect_dom_features(driver, final_url)
        page_text = extract_page_text_from_dom(driver)
        
        screenshot_path = ""
        if job_id:
            try:
                cache_dir = Path("static/cache")
                cache_dir.mkdir(parents=True, exist_ok=True)
                screen_file = cache_dir / f"{job_id}.png"
                driver.save_screenshot(str(screen_file))
                screenshot_path = f"/static/cache/{job_id}.png"
            except Exception:
                pass

        return {
            "reachability": {
                "state": "reachable",
                "label": "Reachable",
                "detail": "Website opened successfully in headless browser.",
                "engine": engine_name,
                "final_url": final_url,
                "title": (driver.title or "").strip(),
                "load_time": f"{elapsed}s",
                "redirect_hops": 0,
                "screenshot_path": screenshot_path,
            },
            "dom_status": "full",
            "dom_note": "DOM features extracted successfully.",
            "dom_features": dom_features,
            "page_text": page_text,
        }
    except TimeoutException:
        elapsed = round(perf_counter() - start, 2)
        return {
            "reachability": {
                "state": "timeout",
                "label": "Timed Out",
                "detail": "Website did not finish loading within timeout.",
                "engine": engine_name,
                "final_url": driver.current_url or "",
                "title": (driver.title or "").strip(),
                "load_time": f"{elapsed}s",
                "redirect_hops": 0,
            },
            "dom_status": "partial",
            "dom_note": "DOM partially available due to timeout.",
            "dom_features": {},
        }
    except WebDriverException as ex:
        elapsed = round(perf_counter() - start, 2)
        state, detail = _classify_driver_error(str(ex))
        return {
            "reachability": {
                "state": state,
                "label": "Unreachable" if state in {"unreachable", "timeout"} else "Driver Error",
                "detail": detail,
                "engine": engine_name,
                "final_url": driver.current_url or "",
                "title": (driver.title or "").strip(),
                "load_time": f"{elapsed}s",
                "redirect_hops": 0,
            },
            "dom_status": "partial",
            "dom_note": "DOM extraction not available for this browser state.",
            "dom_features": {},
        }
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def _threshold_map(value: float, low: float, high: float) -> int:
    if value < low:
        return 1
    if value < high:
        return 0
    return -1


def build_ml_feature_vector(
    normalized_url: str,
    url_lexical: dict[str, Any],
    page_dom: dict[str, Any],
    domain_host: dict[str, Any],
    reachability: dict[str, Any],
    redirect_check: dict[str, Any],
) -> dict[str, int]:
    hops = len(redirect_check.get("hops", []))
    external_anchor_ratio = float(page_dom.get("external_anchor_ratio", 0.0) or 0.0)
    external_script_ratio = float(page_dom.get("external_script_ratio", 0.0) or 0.0)
    external_form_ratio = float(page_dom.get("external_form_action_ratio", 0.0) or 0.0)

    anchor_count = int(page_dom.get("anchor_count", 0) or 0)
    iframe_count = int(page_dom.get("iframe_count", 0) or 0)

    domain_age_days = domain_host.get("domain_age_days")
    expires_in_days = domain_host.get("domain_expires_in_days")

    feature_vector = {
        "UsingIP": -1 if url_lexical.get("has_ip_host") else 1,
        "LongURL": _threshold_map(float(url_lexical.get("url_length", 0)), 54, 75),
        "ShortURL": -1 if url_lexical.get("shortener_hint") else 1,
        "Symbol@": -1 if url_lexical.get("has_at_symbol") else 1,
        "Redirecting//": -1 if url_lexical.get("double_slash_redirect_hint") else 1,
        "PrefixSuffix-": -1 if url_lexical.get("has_hyphenated_domain") else 1,
        "SubDomains": 1 if url_lexical.get("subdomain_depth", 0) <= 1 else (0 if url_lexical.get("subdomain_depth", 0) == 2 else -1),
        "HTTPS": 1 if url_lexical.get("scheme") == "https" else -1,
        "DomainRegLen": 1 if (expires_in_days is not None and expires_in_days >= 365) else (-1 if expires_in_days is None or expires_in_days < 90 else 0),
        "Favicon": 1 if float(page_dom.get("external_favicon_ratio", 0.0) or 0.0) <= 0.3 else -1,
        "NonStdPort": -1 if url_lexical.get("has_non_standard_port") else 1,
        "HTTPSDomainURL": -1 if url_lexical.get("https_in_hostname") else 1,
        "RequestURL": _threshold_map(external_anchor_ratio, 0.22, 0.61),
        "AnchorURL": _threshold_map(external_anchor_ratio, 0.31, 0.67),
        "LinksInScriptTags": _threshold_map(external_script_ratio, 0.17, 0.81),
        "ServerFormHandler": -1 if external_form_ratio > 0.5 else 1,
        "InfoEmail": -1 if int(page_dom.get("mailto_links", 0) or 0) > 0 else 1,
        # AbnormalURL: in training data, -1 means the URL hostname doesn't match WHOIS registrant.
        # We approximate: if WHOIS is unavailable OR domain is very new, treat as -1 (suspicious).
        # If WHOIS confirms a mature domain, treat as 1 (normal).
        "AbnormalURL": 1 if (domain_host.get("whois_available") and domain_age_days is not None and domain_age_days >= 30) else -1,
        "WebsiteForwarding": 1 if hops <= 1 else (0 if hops <= 3 else -1),
        "StatusBarCust": -1 if int(page_dom.get("statusbar_signal_count", 0) or 0) > 0 else 1,
        "DisableRightClick": -1 if bool(page_dom.get("right_click_blocked")) else 1,
        "UsingPopupWindow": -1 if int(page_dom.get("popup_signal_count", 0) or 0) > 0 else 1,
        "IframeRedirection": 1 if iframe_count == 0 else (0 if iframe_count <= 2 else -1),
        "AgeofDomain": 1 if (domain_age_days is not None and domain_age_days >= 180) else -1,
        "DNSRecording": 1 if domain_host.get("whois_available") else -1,
        # WebsiteTraffic: training dataset used Alexa rank. -1 = no rank (low traffic / unknown).
        # We approximate: if DNS resolves AND whois available AND domain is mature = known site.
        "WebsiteTraffic": 1 if (domain_host.get("dns_resolved") and domain_host.get("whois_available") and domain_age_days is not None and domain_age_days >= 365) else (0 if domain_host.get("dns_resolved") else -1),
        # PageRank: training data had -1 for low/no PageRank (most phishing sites).
        # We can't query Google PageRank live, so we use a heuristic proxy:
        # mature domain (2+ years) + WHOIS available = likely has some rank.
        "PageRank": 1 if (domain_age_days is not None and domain_age_days >= 730 and domain_host.get("whois_available")) else (-1 if (domain_age_days is None or domain_age_days < 180) else 0),
        "GoogleIndex": 1 if reachability.get("state") == "reachable" else (0 if reachability.get("state") == "timeout" else -1),
        "LinksPointingToPage": 1 if anchor_count >= 2 else (0 if anchor_count == 1 else -1),
        "StatsReport": 1,
    }

    for name in FEATURE_COLUMNS:
        if name not in feature_vector:
            feature_vector[name] = 0
        feature_vector[name] = int(feature_vector[name])

    return feature_vector


def load_model_bundle(force_reload: bool = False) -> tuple[dict[str, Any] | None, str]:
    if _MODEL_CACHE["bundle"] is not None and not force_reload:
        return _MODEL_CACHE["bundle"], ""

    if not MODEL_BUNDLE_PATH.exists():
        _MODEL_CACHE["bundle"] = None
        _MODEL_CACHE["error"] = (
            f"Model bundle not found at {MODEL_BUNDLE_PATH.name}. "
            "Run: python train_model.py --dataset ../../phishing.csv"
        )
        return None, _MODEL_CACHE["error"]

    try:
        with MODEL_BUNDLE_PATH.open("rb") as f:
            bundle = pickle.load(f)
        _MODEL_CACHE["bundle"] = bundle
        _MODEL_CACHE["error"] = ""
        return bundle, ""
    except Exception as ex:
        _MODEL_CACHE["bundle"] = None
        _MODEL_CACHE["error"] = f"Failed to load model bundle: {ex}"
        return None, _MODEL_CACHE["error"]


def _rule_notes(url_lexical: dict[str, Any], reachability: dict[str, Any], domain_host: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    if url_lexical.get("has_ip_host"):
        notes.append("URL host is a raw IP address.")
    if url_lexical.get("shortener_hint"):
        notes.append("Shortened URL pattern detected.")
    if url_lexical.get("suspicious_token_count", 0) > 0:
        notes.append("Suspicious URL keywords detected.")
    if url_lexical.get("has_non_standard_port"):
        notes.append("Non-standard port detected in URL.")
    if reachability.get("state") in {"timeout", "unreachable"}:
        notes.append("Website reachability is unstable or failed.")
    if not domain_host.get("whois_available"):
        notes.append("WHOIS metadata unavailable for domain.")
    return notes


def predict_with_model(
    model_vector: dict[str, int],
    url_lexical: dict[str, Any],
    reachability: dict[str, Any],
    domain_host: dict[str, Any],
) -> dict[str, Any]:
    bundle, bundle_error = load_model_bundle()
    if bundle is None:
        result = empty_prediction()
        result["error"] = bundle_error
        result["rule_notes"] = _rule_notes(url_lexical, reachability, domain_host)
        return result

    expected_columns = bundle.get("feature_columns")
    if expected_columns != FEATURE_COLUMNS:
        result = empty_prediction()
        result["error"] = "Model feature schema mismatch. Retrain model bundle."
        result["rule_notes"] = _rule_notes(url_lexical, reachability, domain_host)
        return result

    if bundle.get("schema_hash") != compute_schema_hash(FEATURE_COLUMNS):
        result = empty_prediction()
        result["error"] = "Model schema hash mismatch. Retrain model bundle."
        result["rule_notes"] = _rule_notes(url_lexical, reachability, domain_host)
        return result

    try:
        import pandas as pd

        model = bundle["model"]
        row = [[model_vector[col] for col in FEATURE_COLUMNS]]
        frame = pd.DataFrame(row, columns=FEATURE_COLUMNS)

        probs = model.predict_proba(frame)[0]
        classes = list(model.classes_)
        phishing_index = classes.index(1) if 1 in classes else int(len(classes) - 1)
        phishing_prob = float(probs[phishing_index])
        safe_prob = 1.0 - phishing_prob

        if phishing_prob >= 0.70:
            verdict = "Phishing"
        elif phishing_prob >= 0.40:
            verdict = "Suspicious"
        else:
            verdict = "Legitimate"

        confidence = round(max(phishing_prob, safe_prob) * 100.0, 2)

        top_signals: list[dict[str, Any]] = []
        for item in bundle.get("top_global_features", [])[:15]:
            name = item.get("feature")
            if name not in model_vector:
                continue
            value = model_vector[name]
            importance = float(item.get("importance", 0.0) or 0.0)
            # Signed impact: negative value on an important feature = risk contribution.
            # We use signed_impact to sort so risk signals surface properly.
            signed_impact = value * importance  # negative = risk, positive = safe
            abs_impact = round(abs(signed_impact), 6)
            note = "Risk-leaning" if value < 0 else ("Neutral" if value == 0 else "Safe-leaning")
            top_signals.append(
                {
                    "feature": name,
                    "value": int(value),
                    "importance": round(importance, 6),
                    "impact": abs_impact,
                    "signed_impact": round(signed_impact, 6),
                    "note": note,
                }
            )

        # Sort: if verdict is phishing/suspicious, surface risk signals first.
        # If legitimate, surface safe signals first (most impactful either way).
        if verdict in {"Phishing", "Suspicious"}:
            top_signals = sorted(top_signals, key=lambda x: x["signed_impact"])[:5]
        else:
            top_signals = sorted(top_signals, key=lambda x: x["impact"], reverse=True)[:5]

        return {
            "status": "ok",
            "verdict": verdict,
            "risk_score": round(phishing_prob * 100.0, 2),
            "confidence": confidence,
            "phishing_probability": round(phishing_prob, 6),
            "safe_probability": round(safe_prob, 6),
            "model_version": str(bundle.get("model_version", "1.0")),
            "top_signals": top_signals,
            "rule_notes": _rule_notes(url_lexical, reachability, domain_host),
            "error": "",
        }
    except Exception as ex:
        result = empty_prediction()
        result["status"] = "error"
        result["error"] = f"Model inference failed: {ex}"
        result["rule_notes"] = _rule_notes(url_lexical, reachability, domain_host)
        return result


def build_extraction_payload(
    url_lexical: dict[str, Any],
    page_dom: dict[str, Any],
    domain_host: dict[str, Any],
    model_vector: dict[str, int],
    status: str,
    note: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "note": note,
        "url_lexical": url_lexical,
        "page_dom": page_dom,
        "domain_host": domain_host,
        "model_vector": model_vector,
        "schema_hash": compute_schema_hash(FEATURE_COLUMNS),
    }


def run_canonical_scan(raw_url: str, status_callback=None, job_id: str = None) -> dict[str, Any]:
    def set_status(msg):
        if status_callback:
            status_callback(msg)

    set_status("Initializing scan...")
    scan = empty_scan_response()
    errors: list[str] = []

    set_status("Validating URL...")
    normalized_url, validation_error = normalize_and_validate_url(raw_url)
    if validation_error:
        errors.append(validation_error)
        scan["validation"] = {
            "ok": False,
            "normalized_url": "",
            "error": validation_error,
        }
        scan["features"] = build_extraction_payload({}, {}, {}, {}, "skipped", "Validation failed; extraction skipped.")
        scan["errors"] = errors
        return scan

    set_status("Checking redirect chain...")
    redirect_check = validate_redirect_chain(normalized_url)
    if not redirect_check["ok"]:
        errors.append(redirect_check["error"])
        scan["validation"] = {
            "ok": False,
            "normalized_url": normalized_url,
            "error": redirect_check["error"],
        }
        scan["features"] = build_extraction_payload({}, {}, {}, {}, "skipped", "Redirect gate blocked scan.")
        scan["errors"] = errors
        return scan

    if redirect_check.get("warning"):
        errors.append(redirect_check["warning"])

    set_status("Extracting lexical features...")
    url_lexical = extract_url_lexical_features(normalized_url)
    
    set_status("Querying domain and WHOIS records...")
    domain_host = extract_domain_host_features(normalized_url)

    set_status("Running browser simulation (this may take a few seconds)...")
    selenium_result = run_selenium_reachability_and_dom(normalized_url, timeout_seconds=BROWSER_TIMEOUT_SECONDS, job_id=job_id)
    reachability = selenium_result["reachability"]
    reachability["redirect_hops"] = len(redirect_check.get("hops", []))

    page_dom = selenium_result.get("dom_features", {})
    page_text = selenium_result.get("page_text", "")

    extraction_status = "full" if selenium_result.get("dom_status") == "full" else "partial"
    extraction_note = selenium_result.get("dom_note", "")
    if domain_host.get("status") == "partial":
        extraction_note = f"{extraction_note} {domain_host.get('note', '')}".strip()

    set_status("Building machine learning features...")
    model_vector = build_ml_feature_vector(
        normalized_url=normalized_url,
        url_lexical=url_lexical,
        page_dom=page_dom,
        domain_host=domain_host,
        reachability=reachability,
        redirect_check=redirect_check,
    )

    set_status("Evaluating phishing risk model...")
    prediction = predict_with_model(model_vector, url_lexical, reachability, domain_host)
    if prediction.get("error"):
        errors.append(prediction["error"])

    set_status("Analyzing page content for threats...")
    page_title = reachability.get("title", "") or ""
    content_analysis = classify_content_threats(
        page_text=page_text,
        page_title=page_title,
        url=normalized_url,
        url_lexical=url_lexical,
    )

    scan["validation"] = {
        "ok": True,
        "normalized_url": normalized_url,
        "error": "",
    }
    scan["reachability"] = reachability
    scan["features"] = build_extraction_payload(
        url_lexical=url_lexical,
        page_dom=page_dom,
        domain_host=domain_host,
        model_vector=model_vector,
        status=extraction_status,
        note=extraction_note,
    )
    scan["prediction"] = prediction
    scan["content_analysis"] = content_analysis
    scan["confidence"] = prediction.get("confidence")
    scan["top_signals"] = prediction.get("top_signals", [])
    scan["errors"] = errors

    set_status("Finalizing report...")
    return scan
