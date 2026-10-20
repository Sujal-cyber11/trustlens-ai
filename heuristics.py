"""Deterministic local heuristics engine for TrustLens AI.

Fixes included:
- Standard login/password wording ('Enter your password', 'Student Login') is NOT a threat by itself;
  credential-demand scoring applies ONLY when combined with explicit urgency/threat wording,
  direct reply demands ('reply with', 'share your'), or a suspicious/lookalike domain.
- Validates public registered domains strictly (rejects localhost, 127.0.0.1, private IPs, and free text).
- Supports user_allowlist overrides and caps blacklist floor at 80 with evidence-only explanations.
- Uses only fixed-width look-behinds in regular expressions.
"""
from __future__ import annotations

import difflib
import ipaddress
import logging
import re
import unicodedata
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("trustlens.heuristics")

TRUSTLENS_INTERNAL_MARKER = "[TL_INTERNAL]"

INTERNAL_SIGNATURE_SUBSTRINGS: tuple[str, ...] = (
    TRUSTLENS_INTERNAL_MARKER.lower(),
    "trustlens ai",
    "trustlens:",
    "=== trustlens",
    "trustlens cybercrime",
    "calm-down reality check",
    "what it seems to be",
    "malicious webpage / phishing risk",
    "verified clean webpage",
)

PROTECTED_BRANDS: dict[str, tuple[str, ...]] = {
    "amazon": ("amazon.com", "amazon.in", "amzn.in", "amzn.to", "media-amazon.com"),
    "flipkart": ("flipkart.com",),
    "myntra": ("myntra.com",),
    "meesho": ("meesho.com",),
    "paytm": ("paytm.com", "paytm.in"),
    "phonepe": ("phonepe.com",),
    "gpay": ("pay.google.com", "google.com"),
    "google": ("google.com", "google.co.in", "g.co", "gmail.com", "youtube.com"),
    "youtube": ("youtube.com", "youtu.be"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "outlook.com"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "whatsapp": ("whatsapp.com", "wa.me"),
    "telegram": ("telegram.org", "t.me"),
    "instagram": ("instagram.com",),
    "facebook": ("facebook.com", "fb.com"),
    "github": ("github.com",),
    "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "hdfcbank": ("hdfcbank.com", "hdfc.com"),
    "icicibank": ("icicibank.com",),
    "axisbank": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "pnbindia": ("pnbindia.in",),
    "indiapost": ("indiapost.gov.in",),
    "irctc": ("irctc.co.in",),
    "uidai": ("uidai.gov.in",),
    "incometax": ("incometax.gov.in",),
    "npci": ("npci.org.in", "bhimupi.org.in"),
    "bses": ("bsesdelhi.com",),
    "openai": ("openai.com", "chatgpt.com"),
    "chatgpt": ("chatgpt.com", "openai.com"),
    "gemini": ("gemini.google.com", "aistudio.google.com", "google.com"),
    "claude": ("claude.ai", "anthropic.com"),
}

BRAND_ALIASES: dict[str, str] = {
    "hdfc": "hdfcbank",
    "icici": "icicibank",
    "axis": "axisbank",
    "pnb": "pnbindia",
    "amzn": "amazon",
    "flpkrt": "flipkart",
    "fb": "facebook",
    "insta": "instagram",
    "yt": "youtube",
    "gpt": "chatgpt",
    "openal": "openai",
}

WHITELIST_DOMAINS: tuple[str, ...] = tuple(
    {d for doms in PROTECTED_BRANDS.values() for d in doms}
    | {"localhost", "127.0.0.1", "example.com", "cybercrime.gov.in", "wikipedia.org"}
)

BENIGN_ACADEMIC_GOV_SUFFIXES: tuple[str, ...] = (
    ".ac.in", ".edu.in", ".gov.in", ".nic.in", ".org.in", ".edu", ".gov", ".ac.uk",
)

SUSPICIOUS_TLDS: tuple[str, ...] = (
    ".xyz", ".top", ".buzz", ".click", ".zip", ".loan", ".work",
    ".tk", ".gq", ".ml", ".cf", ".rest", ".fit", ".icu", ".vip", ".win", ".bid",
)

URL_SHORTENERS: tuple[str, ...] = (
    "bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd", "shorturl.at", "ow.ly",
)

MULTI_PART_PUBLIC_SUFFIXES: tuple[str, ...] = (
    "co.in", "gov.in", "org.in", "ac.in", "net.in", "res.in", "edu.in", "nic.in",
    "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br", "com.sg",
)

VALID_HOSTNAME_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

EXPLICIT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"(?<![/@a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|in|org|net|edu|gov|mil|co|io|ai|me|app|dev|xyz|top|buzz|click|zip|loan|work|tk|info|biz|online|site|tech|store|shop|bank|pay|icu|vip|win|pro|sbi|example)\b(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
CARD_OR_AADHAAR_RE = re.compile(r"(?<!\d)(?:\d[ -]?){11,18}\d(?!\d)")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
OTP_BEFORE_RE = re.compile(
    r"\b\d{4,8}\b(?=\s*(?:is your|is the|otp|one time password|verification code))",
    re.IGNORECASE,
)
OTP_AFTER_RE = re.compile(
    r"\b(otp\s+is|code\s+is|password\s+is|pin\s+is|otp[:\s-]+)\s*(\d{4,8})\b",
    re.IGNORECASE,
)

EXPLICIT_URGENCY_PATTERNS: tuple[str, ...] = (
    "account blocked",
    "account is blocked",
    "temporarily restricted",
    "account suspended",
    "will be suspended",
    "verify now",
    "verify immediately",
    "within 24 hours",
    "within 12 hours",
    "disconnected tonight",
    "power will be disconnected",
    "immediately call",
    "urgent action required",
    "security alert:",
    "unpaid clearance",
    "customs warehouse",
    "reactivate it",
    "avoid suspension",
)

def is_trustlens_internal_text(text: str) -> bool:
    if not text:
        return False
    s = text.strip()
    low = s.lower()
    if TRUSTLENS_INTERNAL_MARKER.lower() in low or low.startswith(("⚠️ trustlens:", "trustlens:")):
        return True
    if re.match(r"^\s*(curl|Invoke-WebRequest|iwr|wget|python|pytest|pip)\b", low, re.IGNORECASE):
        return True
    return False


def is_local_or_private_host(host: str) -> bool:
    """Returns True if host is localhost, loopback, private IP, or link-local."""
    if not host:
        return True
    h = host.strip().lower().rstrip(".")
    if ":" in h and not h.startswith("["):
        h = h.split(":", 1)[0]
    h = h.strip("[]")
    if h in ("localhost", "127.0.0.1", "0.0.0.0", "::1") or h.endswith((".local", ".localhost", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def normalize_valid_public_domain(raw: str | None) -> str | None:
    """Validates and normalizes a registered domain, rejecting titles, sentences, localhost, and private IPs."""
    if not raw or not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if not candidate or " " in candidate or "\n" in candidate or "\t" in candidate:
        return None
    if "://" in candidate or "/" in candidate:
        try:
            parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
            candidate = parsed.hostname or ""
        except ValueError:
            return None
    candidate = candidate.lower().strip(".")
    if not candidate or is_local_or_private_host(candidate):
        return None
    if not VALID_HOSTNAME_RE.match(candidate):
        return None
    reg = get_registered_domain(candidate)
    if not reg or not VALID_HOSTNAME_RE.match(reg) or is_local_or_private_host(reg):
        return None
    return reg


def scrub_pii(text: str) -> str:
    """Redacts emails, card/Aadhaar numbers, phone numbers, PANs, and OTP codes before cloud calls."""
    if not text:
        return ""
    cleaned = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    cleaned = PAN_RE.sub("[REDACTED_PAN]", cleaned)
    cleaned = OTP_BEFORE_RE.sub("[REDACTED_OTP]", cleaned)
    cleaned = OTP_AFTER_RE.sub(r"\1 [REDACTED_OTP]", cleaned)
    cleaned = CARD_OR_AADHAAR_RE.sub("[REDACTED_CARD_OR_ID]", cleaned)
    cleaned = PHONE_RE.sub("[REDACTED_PHONE]", cleaned)
    return cleaned


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


CONFUSABLE_CHAR_MAP: dict[str, str] = {
    "0": "o", "1": "l", "!": "l", "|": "l", "3": "e", "4": "a", "@": "a",
    "5": "s", "$": "s", "7": "t", "8": "b", "9": "g", "6": "g", "2": "z",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "α": "a", "ο": "o", "ρ": "p", "ν": "v",
}


def _visual_skeleton(label: str) -> str:
    s = unicodedata.normalize("NFKC", label.lower())
    s = (
        s.replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .replace("nn", "m")
        .replace("ri", "n")
        .replace("ci", "a")
    )
    s = "".join(CONFUSABLE_CHAR_MAP.get(ch, ch) for ch in s)
    s = re.sub(r"(.)\1+", r"\1", s)
    return s


def has_mixed_scripts(host: str) -> bool:
    scripts: set[str] = set()
    for ch in host:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
                script = name.split()[0]
                scripts.add(script)
            except ValueError:
                continue
    return len(scripts) > 1


def split_domain_parts(host: str) -> tuple[str, str, str]:
    clean = host.lower().strip(".")
    if not clean:
        return "", "", ""
    parts = [p for p in clean.split(".") if p]
    if len(parts) == 1:
        return "", parts[0], ""

    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in MULTI_PART_PUBLIC_SUFFIXES:
        suffix = last_two
        domain_label = parts[-3]
        subdomain = ".".join(parts[:-3])
    else:
        suffix = parts[-1]
        domain_label = parts[-2]
        subdomain = ".".join(parts[:-2])

    if subdomain == "www":
        subdomain = ""
    return subdomain, domain_label, suffix


def get_registered_domain(host: str) -> str:
    clean = host.lower().strip(".")
    if not clean:
        return ""
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        pass
    _, label, suffix = split_domain_parts(clean)
    return f"{label}.{suffix}" if suffix else label


def domain_matches(host: str, allowed_domains: tuple[str, ...] | list[str]) -> bool:
    h = host.lower().strip(".")
    return any(h == d.lower() or h.endswith("." + d.lower()) for d in allowed_domains if d)


def extract_first_url_or_domain(text: str) -> tuple[bool, bool, str, str, str]:
    candidate = text.strip()
    if not candidate:
        return False, False, "", "", ""

    m_exp = EXPLICIT_URL_RE.search(candidate)
    if m_exp:
        raw_url = m_exp.group(0).rstrip(".,;:!?)]}\"'")
        is_single = len(candidate.split()) == 1 and candidate.startswith(("http://", "https://"))
        try:
            p = urlparse(raw_url)
            host = (p.hostname or "").lower().rstrip(".")
            if host:
                return True, is_single, raw_url, host, p.scheme.lower()
        except ValueError:
            log.debug("Malformed explicit URL skipped: %s", raw_url)

    text_without_emails = EMAIL_RE.sub(" ", candidate)
    m_bare = BARE_DOMAIN_RE.search(text_without_emails)
    if m_bare:
        raw_dom = m_bare.group(0).rstrip(".,;:!?)]}\"'")
        is_single = len(candidate.split()) == 1
        full_url = f"https://{raw_dom}"
        try:
            p = urlparse(full_url)
            host = (p.hostname or "").lower().rstrip(".")
            if host:
                return True, is_single, full_url, host, "https"
        except ValueError:
            log.debug("Malformed bare domain skipped: %s", raw_dom)

    return False, False, "", "", ""


def detect_brand_impersonation(host: str, extra_allowlist: list[str] | None = None) -> dict[str, Any] | None:
    host_clean = host.lower().strip(".")
    if not host_clean or is_local_or_private_host(host_clean):
        return None
    if domain_matches(host_clean, WHITELIST_DOMAINS):
        return None
    if extra_allowlist and domain_matches(host_clean, extra_allowlist):
        return None

    subdomain, core_label, _ = split_domain_parts(host_clean)
    if not core_label or len(core_label) < 2:
        return None

    is_punycode = "xn--" in host_clean
    is_mixed = has_mixed_scripts(host_clean)

    clean_label = core_label.replace("-", "")
    skel_label = _visual_skeleton(clean_label)
    il_unified = skel_label.replace("l", "i")

    ai_brands = {"openai", "chatgpt", "gemini", "claude"}

    for alias, target_brand in BRAND_ALIASES.items():
        if clean_label == alias or alias in core_label.split("-") or skel_label == _visual_skeleton(alias):
            official = PROTECTED_BRANDS[target_brand][0]
            is_ai = target_brand in ai_brands
            return {
                "brand": target_brand.upper(),
                "official": official,
                "is_ai": is_ai,
                "technique": "Impersonating AI Platform (Look-Alike Alias)" if is_ai else "Brand Impersonation (Look-Alike Alias)",
                "explanation": f"Domain '{host_clean}' impersonates {target_brand.upper()} (official domain: {official}).",
                "score_boost": 94,
            }

    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_skel = _visual_skeleton(brand)
        brand_il = brand_skel.replace("l", "i")
        is_ai = brand in ai_brands
        prefix = "Impersonating AI Platform" if is_ai else "Brand Impersonation"

        sub_tokens = re.split(r"[.-]", subdomain) if subdomain else []
        label_tokens = core_label.split("-")
        if clean_label == brand or brand in label_tokens or brand in sub_tokens:
            return {
                "brand": brand.upper(),
                "official": official_domains[0],
                "is_ai": is_ai,
                "technique": f"{prefix} (Combo-Squatting / Unauthorized Domain)",
                "explanation": f"Domain '{host_clean}' uses protected name '{brand.upper()}' on an unverified host (official: {official_domains[0]}).",
                "score_boost": 91,
            }

        if skel_label == brand_skel or il_unified == brand_il:
            return {
                "brand": brand.upper(),
                "official": official_domains[0],
                "technique": f"{prefix} (Visual Homoglyph Substitution)",
                "explanation": (
                    f"Domain '{host_clean}' visually mimics '{brand.upper()}' ({official_domains[0]}) "
                    "using look-alike characters (such as 'rn' for 'm', '0' for 'o', or '1'/'l' for 'i')."
                ),
                "score_boost": 96,
            }

        for token in label_tokens + sub_tokens:
            if len(token) >= 4:
                tok_skel = _visual_skeleton(token)
                dist_tok = _levenshtein(token, brand)
                dist_tok_skel = _levenshtein(tok_skel, brand_skel)
                if tok_skel == brand_skel or (len(brand) >= 5 and min(dist_tok, dist_tok_skel) == 1):
                    return {
                        "brand": brand.upper(),
                        "official": official_domains[0],
                        "is_ai": is_ai,
                        "technique": f"{prefix} (Typosquatted Combo Domain)",
                        "explanation": f"Domain '{host_clean}' embeds a typosquatted variant ('{token}') of '{brand.upper()}' ({official_domains[0]}).",
                        "score_boost": 94,
                    }

        if len(brand) >= 4 and abs(len(clean_label) - len(brand)) <= 2:
            dist = _levenshtein(clean_label, brand)
            dist_skel = _levenshtein(skel_label, brand_skel)
            dist_il = _levenshtein(il_unified, brand_il)
            min_dist = min(dist, dist_skel, dist_il)
            ratio = difflib.SequenceMatcher(None, skel_label, brand_skel).ratio()
            if min_dist == 1 or (len(brand) >= 6 and min_dist <= 2 and ratio >= 0.75):
                return {
                    "brand": brand.upper(),
                    "official": official_domains[0],
                    "is_ai": is_ai,
                    "technique": f"{prefix} (Typosquatting Edit Distance {min_dist})",
                    "explanation": f"Domain '{host_clean}' is a {min_dist}-character typosquat of '{brand.upper()}' ({official_domains[0]}).",
                    "score_boost": 93,
                }

    if is_punycode or is_mixed:
        return {
            "brand": "Internationalized / Mixed-Script Host",
            "official": "Verified ASCII Portal",
            "is_ai": False,
            "technique": "IDN Punycode / Mixed-Script Homograph",
            "explanation": f"Hostname '{host_clean}' mixes Unicode scripts or uses punycode ('xn--') to spoof characters.",
            "score_boost": 88,
        }

    return None


def has_explicit_urgency_or_threat(text_low: str) -> bool:
    """Checks if text contains explicit account suspension, deadline, or threat language."""
    return any(pat in text_low for pat in EXPLICIT_URGENCY_PATTERNS)


def evaluate_heuristics(text: str, memory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs complete local deterministic pre-analysis on text/URLs and returns structured signals."""
    memory = memory or {}
    weights = memory.get("weights", {})
    user_allowlist = [str(d).lower().strip() for d in memory.get("user_allowlist", []) if d]
    blacklist = [
        str(d).lower().strip()
        for d in memory.get("blacklisted_domains", [])
        if d and not domain_matches(str(d), user_allowlist) and not is_local_or_private_host(str(d))
    ]

    raw_stripped = (text or "").strip()
    if not raw_stripped:
        return {
            "is_url": False,
            "has_url": False,
            "url": "",
            "domain": "",
            "whitelisted": False,
            "blacklisted": False,
            "impersonation_detected": False,
            "inconclusive": False,
            "pass1_naive_score": 0,
            "base_score": 0,
            "detected_category": "Empty Input",
            "dark_pattern": "None",
            "calm_message": "No content to scan.",
            "calm_message_hi": "स्कैन करने के लिए कोई सामग्री नहीं है।",
            "what_input_is_about": "The submitted input was empty.",
            "what_input_is_about_hi": "प्रस्तुत इनपुट खाली था।",
            "what_it_seems_to_be": "Empty string.",
            "what_it_seems_to_be_hi": "खाली टेक्स्ट।",
            "how_it_affects_user": "No impact on the user.",
            "how_it_affects_user_hi": "उपयोगकर्ता पर कोई प्रभाव नहीं।",
            "confidence_score_explanation": "Scored 0/100 because the input is empty.",
            "auto_calibration_note": "Skipped empty payload.",
            "heuristic_indicators": [],
            "recommended_actions": ["No action needed."],
            "recommended_actions_hi": ["किसी कार्रवाई की आवश्यकता नहीं है।"],
        }

    candidate = raw_stripped[:20_000]
    t_low = candidate.lower()

    urgency_w = int(weights.get("urgency_penalty", 25))
    tld_w = int(weights.get("unverified_tld_penalty", 40))
    http_w = int(weights.get("missing_https_penalty", 20))
    spoof_w = int(weights.get("brand_spoof_penalty", 45))
    collect_w = int(weights.get("collect_trap_penalty", 50))
    bait_w = int(weights.get("vague_bait_penalty", 55))

    pass1_score = 0
    if any(k in t_low for k in ["otp", "urgent", "blocked", "suspended", "expire", "immediately", "pay", "₹", "rs.", "refund"]):
        pass1_score += urgency_w + 20

    score = 0
    indicators: list[dict[str, str]] = []
    category = "General Digital Communication"
    dark_pattern = "None"
    calm_en = "✅ No manipulation or phishing trap detected."
    calm_hi = "✅ कोई फ़िशिंग या धोखाधड़ी का जाल नहीं मिला।"
    about_en = f"Text snippet ({len(candidate)} chars) inspected for fraud indicators."
    about_hi = f"धोखाधड़ी संकेतों के लिए संदेश ({len(candidate)} अक्षर) की जांच की गई।"
    seems_en = "Appears to be a standard informational or transactional message."
    seems_hi = "यह एक सामान्य सूचनात्मक संदेश प्रतीत होता है।"
    affects_en = "No suspicious links or credential traps detected."
    affects_hi = "कोई संदिग्ध लिंक या पासवर्ड चुराने वाला जाल नहीं मिला।"

    has_url, is_url, url, host, scheme = extract_first_url_or_domain(candidate)
    whitelisted = False
    blacklisted = False
    impersonation_info = None
    domain_risk_signal = False

    if has_url and host:
        about_en = f"Input references domain '{host}'."
        about_hi = f"इनपुट में डोमेन '{host}' का उल्लेख है।"

        if is_local_or_private_host(host):
            whitelisted = True
        else:
            whitelisted = domain_matches(host, WHITELIST_DOMAINS) or domain_matches(host, user_allowlist)
            blacklisted = (not whitelisted) and domain_matches(host, blacklist)

        if host.endswith(SUSPICIOUS_TLDS):
            pass1_score += 45

        is_ip_literal = False
        try:
            ip_obj = ipaddress.ip_address(host)
            is_ip_literal = ip_obj.is_global
        except ValueError:
            is_ip_literal = False

        subdomain, _, _ = split_domain_parts(host)
        excessive_subdomains = len([p for p in subdomain.split(".") if p]) >= 3
        is_shortener = domain_matches(host, URL_SHORTENERS)
        is_mixed = has_mixed_scripts(host) or "xn--" in host

        if blacklisted:
            score = max(score, 80)
            domain_risk_signal = True
            category = "Blacklisted Domain Match"
            dark_pattern = "Threat Feed Match"
            seems_en = f"References '{host}', which is listed in your local domain blacklist."
            seems_hi = f"'{host}' का उल्लेख है, जो स्थानीय ब्लैकलिस्ट में शामिल है।"
            affects_en = "Interacting with a blacklisted domain risks credential or financial theft."
            affects_hi = "ब्लैकलिस्ट किए गए डोमेन का उपयोग करने से डेटा या पैसे चोरी होने का जोखिम है।"
            calm_en = f"⚠️ Caution: '{host}' is on your local domain blacklist (floor score 80/100)."
            calm_hi = f"⚠️ सावधान: '{host}' आपकी स्थानीय ब्लैकलिस्ट में है (स्कोर 80/100)।"
            indicators.append({
                "type": "Blacklisted Domain",
                "target": host,
                "explanation": f"Domain '{host}' matched local blacklist in agent_memory.json.",
                "severity": "High",
            })

        if not whitelisted:
            if scheme == "http":
                score += http_w
                domain_risk_signal = True
                indicators.append({
                    "type": "Insecure HTTP Protocol",
                    "target": url,
                    "explanation": "Link uses unencrypted HTTP instead of HTTPS.",
                    "severity": "Medium",
                })
            if host.endswith(SUSPICIOUS_TLDS):
                score += tld_w
                domain_risk_signal = True
                seems_en = f"External link using a high-risk top-level domain ('{host}')."
                seems_hi = f"उच्च जोखिम वाले डोमेन ('{host}') का उपयोग करने वाला लिंक।"
                affects_en = "High-risk TLDs (.xyz, .top, .click) are frequently used for phishing sites."
                affects_hi = "ऐसे डोमेन (.xyz, .top, .click) अक्सर फ़िशिंग वेबसाइटों के लिए उपयोग किए जाते हैं।"
                indicators.append({
                    "type": "Suspicious TLD",
                    "target": host,
                    "explanation": f"Domain '{host}' uses a high-risk top-level domain.",
                    "severity": "High",
                })
            if is_ip_literal:
                score = max(score, 85)
                domain_risk_signal = True
                category = "Raw IP-Address Host"
                indicators.append({
                    "type": "IP-Literal URL",
                    "target": host,
                    "explanation": "Uses a raw IP address instead of a domain name.",
                    "severity": "High",
                })
            if is_shortener:
                score += 35
                domain_risk_signal = True
                indicators.append({
                    "type": "URL Shortener",
                    "target": host,
                    "explanation": "Obscures the destination domain behind a shortener link.",
                    "severity": "Medium",
                })
            if excessive_subdomains:
                score += 30
                domain_risk_signal = True
                indicators.append({
                    "type": "Excessive Subdomains",
                    "target": host,
                    "explanation": "Hostname chains 3 or more subdomains.",
                    "severity": "Medium",
                })
            if is_mixed:
                score = max(score, 88)
                domain_risk_signal = True
                category = "Mixed-Script / IDN Homograph"
                indicators.append({
                    "type": "Mixed-Script / Punycode Host",
                    "target": host,
                    "explanation": "Hostname mixes Unicode scripts or uses punycode ('xn--').",
                    "severity": "High",
                })

            impersonation_info = detect_brand_impersonation(host, extra_allowlist=user_allowlist)
            if impersonation_info:
                boost = max(int(impersonation_info["score_boost"]), spoof_w + 40)
                score = max(score, boost)
                domain_risk_signal = True
                category = f"{impersonation_info['technique']} ({impersonation_info['brand']})"
                dark_pattern = "Visual Homoglyph / Brand Spoofing"
                about_en = f"Domain '{host}' closely resembles '{impersonation_info['brand']}'."
                about_hi = f"डोमेन '{host}' लोकप्रिय सेवा '{impersonation_info['brand']}' जैसा दिखता है।"
                seems_en = (
                    f"Impersonates {impersonation_info['brand']} ({impersonation_info['official']}) "
                    f"via {impersonation_info['technique']}."
                )
                seems_hi = (
                    f"{impersonation_info['technique']} के माध्यम से {impersonation_info['brand']} "
                    f"({impersonation_info['official']}) की नकल करता है।"
                )
                affects_en = f"Submitting credentials or payments on '{host}' exposes them to attackers."
                affects_hi = f"'{host}' पर पासवर्ड या भुगतान दर्ज करने से डेटा चोरी हो सकता है।"
                calm_en = (
                    f"🛑 Impersonation Detected: '{host}' is not the official {impersonation_info['brand']} domain "
                    f"('{impersonation_info['official']}')."
                )
                calm_hi = (
                    f"🛑 नकली डोमेन चेतावनी: '{host}' आधिकारिक {impersonation_info['brand']} डोमेन "
                    f"('{impersonation_info['official']}') नहीं है।"
                )
                indicators.append({
                    "type": impersonation_info["technique"],
                    "target": host,
                    "explanation": impersonation_info["explanation"],
                    "severity": "High",
                })

    if not has_url and has_mixed_scripts(candidate):
        for word in candidate.split():
            if has_mixed_scripts(word):
                score = max(score, 65)
                category = "Mixed-Script Obfuscated Text"
                indicators.append({
                    "type": "Mixed-Script Word Obfuscation",
                    "target": word[:40],
                    "explanation": "Word combines multiple Unicode scripts (e.g., Latin + Cyrillic).",
                    "severity": "Medium",
                })
                break

    is_verified_safe = False
    if not has_url or whitelisted:
        if (
            ("do not share" in t_low or "never ask for otp" in t_low or "never calls to ask" in t_low or "dont share" in t_low)
            and "otp" in t_low
            and "*401*" not in t_low
            and not any(k in t_low for k in ["reply with", "send your", "share your otp with us"])
        ):
            is_verified_safe = True
            score = 5
            category = "Legitimate Bank OTP Security Alert"
            dark_pattern = "None"
            about_en = "One-Time Password (OTP) alert that warns you NOT to share the code."
            about_hi = "वन-टाइम पासवर्ड (OTP) संदेश जो कोड साझा न करने की चेतावनी देता है।"
            seems_en = "Genuine transactional security OTP from your bank or service."
            seems_hi = "आपके बैंक या सेवा से वास्तविक सुरक्षा ओटीपी (OTP)।"
            affects_en = "Safe as long as you initiated the transaction and keep the code private."
            affects_hi = "जब तक आप कोड किसी के साथ साझा नहीं करते, यह सुरक्षित है।"
            calm_en = "✅ Verified Safe: Genuine bank OTP alert. Keep this code private."
            calm_hi = "✅ सुरक्षित: वास्तविक बैंक OTP संदेश। कोड निजी रखें।"
            indicators = []

        elif (
            ("paid ₹" in t_low or "paid rs" in t_low or "debited" in t_low)
            and ("upi ref" in t_low or "via upi" in t_low or "thank you" in t_low)
            and not any(k in t_low for k in ["request", "collect", "click", "call", "enter your upi pin"])
        ):
            is_verified_safe = True
            score = 0
            category = "Legitimate UPI Payment Receipt"
            dark_pattern = "None"
            about_en = "Confirmation receipt for a completed UPI payment."
            about_hi = "पूर्ण किए गए UPI भुगतान की पुष्टि रसीद।"
            seems_en = "Standard post-transaction receipt."
            seems_hi = "मानक लेनदेन रसीद।"
            affects_en = "Informational receipt only; poses zero security risk."
            affects_hi = "केवल जानकारी के लिए रसीद; कोई जोखिम नहीं।"
            calm_en = "✅ Verified Safe: Standard UPI payment confirmation receipt."
            calm_hi = "✅ सुरक्षित: मानक UPI भुगतान पुष्टि रसीद।"
            indicators = []

        elif whitelisted and is_url:
            is_verified_safe = True
            score = 0
            category = "Verified Official Website"
            dark_pattern = "None"
            about_en = f"Direct link to allow-listed domain '{host}'."
            about_hi = f"सत्यापित डोमेन '{host}' का सीधा लिंक।"
            seems_en = f"Trusted domain ('{host}')."
            seems_hi = f"विश्वसनीय डोमेन ('{host}')।"
            affects_en = "Safe to visit; matches known allow-list."
            affects_hi = "विज़िट करने के लिए सुरक्षित।"
            calm_en = f"✅ Verified Safe: '{host}' is an allow-listed domain."
            calm_hi = f"✅ सुरक्षित: '{host}' एक विश्वसनीय डोमेन है।"
            indicators = []

    if not is_verified_safe:
        # 1. Credential / OTP / PIN / CVV Harvesting:
        # Requires explicit direct-reply extraction ('reply with', 'share your') OR explicit urgency/threat wording
        # OR a flagged domain risk signal. Simply saying 'Enter your password' or 'Student Login' is NOT a risk indicator by itself.
        asks_secrets = any(k in t_low for k in ["password", "otp", "upi pin", "mpin", "cvv", "seed phrase", "api key", "secret key"])
        direct_reply_demand = any(
            k in t_low
            for k in ["reply with", "reply to this", "send your", "share your", "provide your", "mail your", "whatsapp your"]
        )
        urgent_threat = has_explicit_urgency_or_threat(t_low)

        if asks_secrets and (direct_reply_demand or urgent_threat or domain_risk_signal):
            score = max(score, 96)
            category = "Credential & OTP Harvesting Scam"
            dark_pattern = "Direct Secret Extraction"
            about_en = "Message demanding login credentials, passwords, PINs, or OTPs under urgency or via message reply."
            about_hi = "दबाव दिखाकर या संदेश के जवाब में यूजरनेम, पासवर्ड, पिन या ओटीपी (OTP) मांगने वाला संदेश।"
            seems_en = "Presents itself as an urgent account reactivation or verification alert."
            seems_hi = "तत्काल खाता सत्यापन संदेश जैसा दिखता है।"
            affects_en = "Sharing passwords or OTPs gives attackers full control over your account."
            affects_hi = "पासवर्ड या ओटीपी साझा करने से ठग आपके खाते पर नियंत्रण पा सकते हैं।"
            calm_en = "🚨 Do not reply with or enter your password, PIN, or OTP. Legitimate institutions never ask for secrets via message reply."
            calm_hi = "🚨 अपना पासवर्ड, पिन या ओटीपी साझा न करें। असली संस्थाएं कभी संदेश में पासवर्ड नहीं मांगतीं।"
            indicators.append({
                "type": "Credential / OTP Harvesting Demand",
                "target": "Password / OTP / PIN request with urgency or reply demand",
                "explanation": "Requests confidential authentication secrets combined with urgency or direct-reply wording.",
                "severity": "High",
            })

        # 2. UPI Collect Request Refund Trap
        if ("request" in t_low or "collect" in t_low or "pay ₹" in t_low or "pay rs" in t_low) and any(
            k in t_low for k in ["refund", "cashback", "receive", "upi pin", "enter pin", "olx"]
        ):
            score = max(score, collect_w + 46)
            category = "UPI Collect-Request Reversal Scam"
            dark_pattern = "Semantic Misdirection ('Refund' Note on Debit Button)"
            about_en = "UPI collect request labeled as a 'Refund' or 'Cashback' asking you to tap 'Pay' and enter your UPI PIN."
            about_hi = "UPI भुगतान अनुरोध जिसे 'रिफंड' बताया गया है और 'Pay' दबाकर पिन डालने को कहता है।"
            seems_en = "Disguised as incoming refund money."
            seems_hi = "खाते में पैसे आने का दिखावा करता है।"
            affects_en = "Entering your UPI PIN on a collect request always deducts money from your bank account."
            affects_hi = "UPI पिन डालने से हमेशा खाते से पैसे कटते हैं।"
            calm_en = "🛑 You never need to enter a UPI PIN or tap 'Pay' to receive money. Decline this request."
            calm_hi = "🛑 पैसे प्राप्त करने के लिए कभी भी UPI पिन डालने की आवश्यकता नहीं होती है।"
            indicators.append({
                "type": "UPI Collect Debit Trap",
                "target": "Action 'Pay / Enter PIN' vs Note 'Refund/Cashback'",
                "explanation": "Disguises an outgoing money collect request as an incoming refund.",
                "severity": "High",
            })

        # 3. Utility / Electricity Disconnection Scam
        if ("electricity" in t_low or "power" in t_low) and ("disconnect" in t_low or "tonight" in t_low or "9:30" in t_low):
            score = max(score, urgency_w + 68)
            category = "Utility Disconnection Phishing Lure"
            dark_pattern = "Artificial Night-Time Deadline"
            about_en = "Message threatening electricity disconnection tonight unless you call a number or click a link."
            about_hi = "आज रात बिजली काटने की धमकी देने वाला संदेश।"
            seems_en = "Pretends to be an urgent notice from the electricity utility."
            seems_hi = "बिजली विभाग की चेतावनी जैसा दिखता है।"
            affects_en = "Pushes victims into calling scammers or paying on a fake billing portal."
            affects_hi = "उपयोगकर्ता को नकली नंबर पर कॉल करने या नकली लिंक पर भुगतान करने के लिए फंसाता है।"
            calm_en = "🧘 Your electricity is not getting disconnected tonight via personal mobile numbers or unverified links."
            calm_hi = "🧘 आज रात निजी नंबरों या अनजान लिंक से आपकी बिजली नहीं कट रही है।"
            indicators.append({
                "type": "Utility Cutoff Threat",
                "target": "Electricity disconnection tonight threat",
                "explanation": "Uses a sudden night-time utility cutoff threat to pressure the user.",
                "severity": "High",
            })

        # 4. Prepaid Task / Fake Job Scam
        if any(k in t_low for k in ["daily", "wfh", "part-time", "work from home"]) and any(
            k in t_low for k in ["rating", "youtube", "trial bonus", "₹3,000", "₹5,000", "instant bonus", "telegram"]
        ):
            score = max(score, 90)
            category = "Prepaid Task / Fake Job Scam"
            dark_pattern = "Micro-Reward Bait-and-Switch"
            about_en = "Offer promising high daily payouts for simple online ratings or likes."
            about_hi = "घर बैठे रेटिंग या लाइक करके रोज़ हज़ारों कमाने का प्रलोभन।"
            seems_en = "Pretends to be an easy work-from-home job."
            seems_hi = "आसान पार्ट-टाइम नौकरी जैसा दिखता है।"
            affects_en = "Lures victims into depositing larger sums for 'prepaid VIP tasks' that are stolen."
            affects_hi = "'VIP टास्क' के नाम पर बड़ी रकम जमा करवाकर ठग लेता है।"
            calm_en = "💡 This matches a prepaid task scam pattern. Do not pay registration or task deposits."
            calm_hi = "💡 यह प्रीपेड टास्क स्कैम है। कोई भी राशि जमा न करें।"
            indicators.append({
                "type": "Task Scam Payout Lure",
                "target": "High daily payout for simple ratings/likes",
                "explanation": "Matches WhatsApp/Telegram prepaid task fraud pattern.",
                "severity": "High",
            })

        # 5. Emotional Emergency Scam
        if any(k in t_low for k in ["met with accident", "hospital", "phone fell", "broken screen", "friend's number", "police station"]) and any(
            k in t_low for k in ["send money", "urgently", "upi", "rs", "₹", "transfer"]
        ):
            score = max(score, 88)
            category = "Emotional Emergency Impersonation Scam"
            dark_pattern = "Emotional Panic Manipulation"
            about_en = "Message claiming a family/friend hospital or accident emergency and asking for immediate money."
            about_hi = "दुर्घटना या अस्पताल की आपात स्थिति बताकर तुरंत पैसे मांगने वाला संदेश।"
            seems_en = "Pretends to be a relative messaging from a new number."
            seems_hi = "नए नंबर से किसी रिश्तेदार का संदेश प्रतीत होता है।"
            affects_en = "Pressures you into transferring money before verifying with the person directly."
            affects_hi = "बिना पुष्टि किए तुरंत पैसे ट्रांसफर करवाने की कोशिश करता है।"
            calm_en = "🧘 Call your relative's known phone number directly to verify before sending money."
            calm_hi = "🧘 पैसे भेजने से पहले अपने परिजन के असली नंबर पर कॉल करके पुष्टि करें।"
            indicators.append({
                "type": "Emergency Pretext Money Demand",
                "target": "Accident / Hospital + Immediate UPI Transfer",
                "explanation": "Uses an emergency pretext to rush a money transfer.",
                "severity": "High",
            })

        # 6. USSD Call Forwarding (*401*)
        if "*401*" in t_low:
            score = 99
            category = "USSD Call-Forwarding OTP Interception Scam"
            dark_pattern = "Carrier USSD Abuse"
            about_en = "Instructions asking you to dial '*401*' followed by a phone number."
            about_hi = "'*401*' के बाद फ़ोन नंबर डायल करने का निर्देश।"
            seems_en = "Pretends to be a delivery cancellation or support code."
            seems_hi = "पार्सल रद्दीकरण कोड जैसा दिखावा करता है।"
            affects_en = "Dialing *401* forwards your incoming calls and voice OTPs to the scammer."
            affects_hi = "*401* डायल करने से आपकी कॉल और ओटीपी ठग के फोन पर फॉरवर्ड हो जाते हैं।"
            calm_en = "🚨 Do not dial *401*. If already dialed, dial ##002# to cancel call forwarding."
            calm_hi = "🚨 *401* डायल न करें। कॉल फॉरवर्डिंग हटाने के लिए ##002# डायल करें।"
            indicators.append({
                "type": "Malicious USSD Code (*401*)",
                "target": "*401*",
                "explanation": "Unconditional call-forwarding code disguised as a verification code.",
                "severity": "High",
            })

        # 7. Vague Attention-Bait Lures ("5M credited to your account, click here")
        has_bait_hook = any(
            k in t_low
            for k in [
                "credited", "won", "winner", "lottery", "prize", "reward", "gift", "cashback",
                "5m", "million", "lakh", "crore", "bonus", "unclaimed", "selected", "congrats",
                "urgent", "action required", "package waiting", "parcel hold", "is this you",
            ]
        ) or bool(re.search(r"\b\d+\s*(?:m|k|lakh|cr|crore|million|rs|₹|\$)\b", t_low))

        has_vague_cta = any(
            k in t_low
            for k in [
                "click here", "tap here", "check here", "visit link", "open link", "claim now",
                "claim here", "verify now", "verify here", "check now", "login here", "call now",
                "act now", "confirm now",
            ]
        )

        if (has_bait_hook and (has_vague_cta or (has_url and not whitelisted))) and score < 85:
            vague_score = max(bait_w + 30, 86) if (has_bait_hook and has_vague_cta) else max(bait_w, 58)
            score = max(score, vague_score)
            category = "Vague Attention-Bait / Curiosity Lure"
            dark_pattern = "Information-Withholding Hook"
            about_en = f"Vague message ('{scrub_pii(candidate)[:80]}') making a financial or urgent claim without verifiable details."
            about_hi = f"बिना किसी विवरण के दावा करने वाला अस्पष्ट संदेश ('{scrub_pii(candidate)[:80]}')।"
            seems_en = "Pretends to be a bank credit, reward payout, or urgent alert."
            seems_hi = "बैंक क्रेडिट या इनाम की सूचना होने का दिखावा करता है।"
            affects_en = "Lures you into clicking an unverified link to harvest credentials or install malware."
            affects_hi = "असत्यापित लिंक पर क्लिक करने के लिए प्रेरित करता है।"
            calm_en = "🧐 Doubt this message: Genuine services include verifiable account/reference details rather than vague 'click here' hooks."
            calm_hi = "🧐 इस संदेश पर संदेह करें: असली सेवाएं बिना विवरण के ऐसे 'click here' संदेश नहीं भेजतीं।"
            indicators.append({
                "type": "Vague Attention-Bait Hook",
                "target": scrub_pii(candidate)[:60],
                "explanation": "Attention-grabbing claim combined with a call-to-action but zero verifiable details.",
                "severity": "High" if score >= 66 else "Medium",
            })

    final_score = min(100, int(score))
    level_str = "High" if final_score >= 66 else "Medium" if final_score >= 31 else "Low"
    inconclusive = (final_score == 0 and not is_verified_safe and len(candidate) > 15)

    if final_score >= 31:
        detected_types = ", ".join(i["type"] for i in indicators[:3]) or category
        actions_en = [
            f"Do not interact with the flagged element(s): {detected_types}.",
            "Verify independently through the official application or website.",
        ]
        actions_hi = [
            f"चिह्नित तत्वों ({detected_types}) के साथ इंटरैक्ट न करें।",
            "आधिकारिक ऐप या वेबसाइट के माध्यम से स्वतंत्र रूप से सत्यापित करें।",
        ]
    else:
        actions_en = ["No risk indicators triggered. Standard security practices apply."]
        actions_hi = ["कोई जोखिम संकेत नहीं मिला। सामान्य सुरक्षा अभ्यास बनाए रखें।"]

    return {
        "is_url": is_url,
        "has_url": has_url,
        "url": url,
        "domain": host,
        "whitelisted": whitelisted,
        "blacklisted": blacklisted,
        "impersonation_detected": bool(impersonation_info),
        "is_verified_safe": is_verified_safe,
        "inconclusive": inconclusive,
        "pass1_naive_score": min(100, pass1_score),
        "base_score": final_score,
        "detected_category": category,
        "dark_pattern": dark_pattern,
        "calm_message": calm_en,
        "calm_message_hi": calm_hi,
        "what_input_is_about": about_en,
        "what_input_is_about_hi": about_hi,
        "what_it_seems_to_be": seems_en,
        "what_it_seems_to_be_hi": seems_hi,
        "how_it_affects_user": affects_en,
        "how_it_affects_user_hi": affects_hi,
        "confidence_score_explanation": (
            f"Deterministic analysis scored {final_score}/100 ({level_str}) "
            f"based on {len(indicators)} detected indicator(s)."
        ),
        "auto_calibration_note": "Deterministic pre-analysis complete.",
        "heuristic_indicators": indicators,
        "recommended_actions": actions_en,
        "recommended_actions_hi": actions_hi,
    }
