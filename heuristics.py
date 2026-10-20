"""Deterministic local heuristics engine for TrustLens AI.

Performs zero-network pre-analysis before any LLM call:
- PII scrubbing (phones, payment cards, emails, Aadhaar/PAN patterns, standalone OTPs).
- URL & bare-domain extraction, IDN/punycode decoding, mixed-script Unicode detection,
  IP-literal detection, URL shortener detection, and excessive subdomain checking.
- Visual homoglyph normalization (rn->m, vv->w, cl->d, 0->o, 1->l/i, etc.) and
  Levenshtein edit-distance matching against popular Indian and global brands.
- Text pattern detection for linkless credential harvesting, UPI collect-request traps,
  utility/KYC/parcel/job/lottery scams, emotional family-emergency lures, USSD *401*
  call forwarding, and vague attention-bait.
- Allow-list protection for genuine bank OTPs and standard UPI payment receipts.
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
    | {"localhost", "127.0.0.1", "example.com", "cybercrime.gov.in"}
)

SUSPICIOUS_TLDS: tuple[str, ...] = (
    ".xyz", ".top", ".buzz", ".click", ".zip", ".loan", ".work",
    ".tk", ".gq", ".ml", ".cf", ".rest", ".fit", ".icu", ".vip", ".win", ".bid",
)

URL_SHORTENERS: tuple[str, ...] = (
    "bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd", "shorturl.at", "ow.ly",
)

MULTI_PART_PUBLIC_SUFFIXES: tuple[str, ...] = (
    "co.in", "gov.in", "org.in", "ac.in", "net.in", "res.in",
    "co.uk", "org.uk", "com.au", "co.jp", "com.br", "com.sg",
)

EXPLICIT_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
BARE_DOMAIN_RE = re.compile(
    r"(?<![/@a-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|in|org|net|edu|gov|mil|co|io|ai|me|app|dev|xyz|top|buzz|click|zip|loan|work|tk|info|biz|online|site|tech|store|shop|bank|pay|icu|vip|win|pro|sbi)\b(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
CARD_OR_AADHAAR_RE = re.compile(r"(?<!\d)(?:\d[ -]?){11,18}\d(?!\d)")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)")
PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
OTP_CODE_RE = re.compile(r"\b(?=\d{4,8}\b)\d+(?=\s*(?:is your|is the|otp|one time password|verification code))", re.IGNORECASE)
OTP_AFTER_RE = re.compile(r"\b((?:otp|code|password|pin)\s+is\s+)\d{4,8}\b", re.IGNORECASE)


def scrub_pii(text: str) -> str:
    """Redacts emails, card/Aadhaar numbers, phone numbers, PANs, and OTP codes before cloud calls."""
    if not text:
        return ""
    cleaned = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    cleaned = PAN_RE.sub("[REDACTED_PAN]", cleaned)
    cleaned = OTP_CODE_RE.sub("[REDACTED_OTP]", cleaned)
    cleaned = OTP_AFTER_RE.sub(r"\1[REDACTED_OTP]", cleaned)
    cleaned = CARD_OR_AADHAAR_RE.sub("[REDACTED_CARD_OR_ID]", cleaned)
    cleaned = PHONE_RE.sub("[REDACTED_PHONE]", cleaned)
    return cleaned


def _levenshtein(s1: str, s2: str) -> int:
    """Computes exact Levenshtein edit distance between two strings."""
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
    # Cyrillic / Greek common confusables
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "α": "a", "ο": "o", "ρ": "p", "ν": "v",
}


def _visual_skeleton(label: str) -> str:
    """Normalizes multi-letter and single-letter visual homoglyphs into a canonical skeleton."""
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


def _has_mixed_scripts(host: str) -> bool:
    """Detects if a hostname mixes Latin characters with Cyrillic, Greek, or Devanagari scripts."""
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
    """TLD-aware domain splitter returning (subdomain, registrable_domain_label, public_suffix)."""
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


def domain_matches(host: str, allowed_domains: tuple[str, ...] | list[str]) -> bool:
    """Checks if host exactly matches or is a subdomain of any domain in allowed_domains."""
    h = host.lower().strip(".")
    return any(h == d.lower() or h.endswith("." + d.lower()) for d in allowed_domains if d)


def extract_first_url_or_domain(text: str) -> tuple[bool, bool, str, str, str]:
    """Extracts (has_url, is_standalone_url, normalized_url, hostname, scheme) from text."""
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

    # Do not treat email addresses as bare domains
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


def detect_brand_impersonation(host: str) -> dict[str, Any] | None:
    """Checks if a hostname impersonates a protected Indian/global brand or AI service."""
    host_clean = host.lower().strip(".")
    if not host_clean or domain_matches(host_clean, WHITELIST_DOMAINS):
        return None

    subdomain, core_label, _ = split_domain_parts(host_clean)
    if not core_label or len(core_label) < 2:
        return None

    # Check IDN / Punycode or mixed-script homograph attack
    is_punycode = "xn--" in host_clean
    is_mixed = _has_mixed_scripts(host_clean)

    clean_label = core_label.replace("-", "")
    skel_label = _visual_skeleton(clean_label)
    il_unified = skel_label.replace("l", "i")

    ai_brands = {"openai", "chatgpt", "gemini", "claude"}

    # 1. Check direct alias mapping
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

    # 2. Check protected brands
    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_skel = _visual_skeleton(brand)
        brand_il = brand_skel.replace("l", "i")
        is_ai = brand in ai_brands
        prefix = "Impersonating AI Platform" if is_ai else "Brand Impersonation"

        # Brand stuffed into subdomain or hyphenated label (e.g. sbi.verify-user.com or chatgpt-pro.com)
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

        # Visual homoglyph skeleton match (arnazon -> amazon, g00gle -> google, paytrn -> paytm, sbl -> sbi)
        if skel_label == brand_skel or il_unified == brand_il:
            return {
                "brand": brand.upper(),
                "official": official_domains[0],
                "is_ai": is_ai,
                "technique": f"{prefix} (Visual Homoglyph Substitution)",
                "explanation": (
                    f"Domain '{host_clean}' visually mimics '{brand.upper()}' ({official_domains[0]}) "
                    "using look-alike characters (such as 'rn' for 'm', '0' for 'o', or '1'/'l' for 'i')."
                ),
                "score_boost": 96,
            }

        # Embedded homoglyph brand (e.g. chatgpi-pro.com, arnazon-prime.in)
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

        # Levenshtein edit distance on full label (e.g. hdfcbnk.com, chatgpi.com, flpkart.com)
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


def evaluate_heuristics(text: str, memory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs complete local deterministic pre-analysis on text/URLs and returns structured signals."""
    memory = memory or {}
    weights = memory.get("weights", {})
    blacklist = [str(d).lower().strip() for d in memory.get("blacklisted_domains", []) if d]

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

    # Pass-1: Naive keyword screener (demonstrates what a simple static keyword scanner does)
    pass1_score = 0
    if any(k in t_low for k in ["otp", "urgent", "blocked", "suspended", "expire", "immediately", "pay", "₹", "rs.", "refund", "account"]):
        pass1_score += urgency_w + 20

    score = 0
    indicators: list[dict[str, str]] = []
    category = "General Digital Communication"
    dark_pattern = "None"
    calm_en = "✅ No immediate manipulation or phishing trap detected. Standard caution applies."
    calm_hi = "✅ कोई तत्काल फ़िशिंग या धोखाधड़ी का जाल नहीं मिला। सामान्य सावधानी बरतें।"
    about_en = f"Message or text snippet ({len(candidate)} chars) inspected for fraud patterns."
    about_hi = f"धोखाधड़ी पैटर्न के लिए संदेश ({len(candidate)} अक्षर) की जांच की गई।"
    seems_en = "Appears to be a standard informational or conversational message."
    seems_hi = "यह एक सामान्य सूचनात्मक या बातचीत का संदेश प्रतीत होता है।"
    affects_en = "Does not request sensitive credentials, money transfers, or risky link clicks."
    affects_hi = "यह संवेदनशील पासवर्ड, पैसे या जोखिम भरे लिंक पर क्लिक करने की मांग नहीं करता है।"

    has_url, is_url, url, host, scheme = extract_first_url_or_domain(candidate)
    whitelisted = False
    blacklisted = False
    impersonation_info = None

    if has_url and host:
        about_en = f"Input contains a web link pointing to domain '{host}'."
        about_hi = f"इनपुट में डोमेन '{host}' की ओर इशारा करने वाला एक वेब लिंक है।"

        if host.endswith(SUSPICIOUS_TLDS):
            pass1_score += 45

        whitelisted = domain_matches(host, WHITELIST_DOMAINS)
        blacklisted = domain_matches(host, blacklist)

        # Check IP-literal URL
        is_ip_literal = False
        try:
            ipaddress.ip_address(host)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        subdomain, _, _ = split_domain_parts(host)
        excessive_subdomains = len([p for p in subdomain.split(".") if p]) >= 3
        is_shortener = domain_matches(host, URL_SHORTENERS)
        is_mixed = _has_mixed_scripts(host) or "xn--" in host

        if blacklisted:
            score = 100
            category = "Known Blacklisted Phishing Domain"
            dark_pattern = "Threat Feed Blacklist Match"
            seems_en = f"Disguised as an online portal at '{host}', which is a confirmed blacklisted scam domain."
            seems_hi = f"'{host}' पर एक पोर्टल के रूप में प्रच्छन्न, जो एक ब्लैकलिस्टेड स्कैम डोमेन है।"
            affects_en = "Opening this link exposes your passwords, banking data, or device to immediate theft."
            affects_hi = "इस लिंक को खोलने से आपके पासवर्ड और बैंकिंग डेटा चोरी हो सकते हैं।"
            calm_en = f"🛑 STOP! The domain '{host}' is on your local threat blacklist. Do not open it."
            calm_hi = f"🛑 रुकें! डोमेन '{host}' ब्लैकलिस्ट में है। इसे न खोलें।"
            indicators.append({
                "type": "Blacklisted Threat Domain",
                "target": host,
                "explanation": f"Domain '{host}' matched local threat intelligence blacklist in agent_memory.json.",
                "severity": "High",
            })

        if not whitelisted:
            if scheme == "http":
                score += http_w
                indicators.append({
                    "type": "Insecure HTTP Protocol",
                    "target": url,
                    "explanation": "Link uses unencrypted HTTP instead of HTTPS.",
                    "severity": "Medium",
                })
            if host.endswith(SUSPICIOUS_TLDS):
                score += tld_w
                seems_en = f"External link using a high-risk disposable domain ending ('{host}')."
                seems_hi = f"उच्च जोखिम वाले डिस्पोजेबल डोमेन ('{host}') का उपयोग करने वाला लिंक।"
                affects_en = "Disposable domains (.xyz, .top, .click) are heavily used for temporary credential-stealing websites."
                affects_hi = "डिस्पोजेबल डोमेन (.xyz, .top, .click) का उपयोग फ़िशिंग वेबसाइटों के लिए किया जाता है।"
                indicators.append({
                    "type": "High-Risk Disposable TLD",
                    "target": host,
                    "explanation": "Uses a top-level domain frequently abused by phishing campaigns.",
                    "severity": "High",
                })
            if is_ip_literal:
                score = max(score, 85)
                category = "Raw IP-Address Phishing Host"
                indicators.append({
                    "type": "IP-Literal URL",
                    "target": host,
                    "explanation": "Uses a raw IP address instead of a verified domain name to hide server identity.",
                    "severity": "High",
                })
            if is_shortener:
                score += 35
                indicators.append({
                    "type": "Obfuscated URL Shortener",
                    "target": host,
                    "explanation": "Hides the true destination domain behind a link shortener.",
                    "severity": "Medium",
                })
            if excessive_subdomains:
                score += 30
                indicators.append({
                    "type": "Excessive Subdomain Chaining",
                    "target": host,
                    "explanation": "Uses deep nested subdomains to disguise the actual root domain.",
                    "severity": "Medium",
                })
            if is_mixed:
                score = max(score, 88)
                category = "Mixed-Script / IDN Homograph Attack"
                indicators.append({
                    "type": "Mixed-Script / Punycode Host",
                    "target": host,
                    "explanation": "Mixes alphabets (e.g., Cyrillic and Latin) or uses punycode to fake visual letters.",
                    "severity": "High",
                })

            impersonation_info = detect_brand_impersonation(host)
            if impersonation_info:
                boost = max(int(impersonation_info["score_boost"]), spoof_w + 40)
                score = max(score, boost)
                category = f"{impersonation_info['technique']} ({impersonation_info['brand']})"
                dark_pattern = "Visual Homoglyph / Brand Spoofing"
                about_en = f"Web address '{host}' visually mimics the popular service '{impersonation_info['brand']}'."
                about_hi = f"वेब पता '{host}' लोकप्रिय सेवा '{impersonation_info['brand']}' की नकल करता है।"
                seems_en = (
                    f"Pretends to be the official {impersonation_info['brand']} website ({impersonation_info['official']}) "
                    f"via {impersonation_info['technique']}."
                )
                seems_hi = (
                    f"{impersonation_info['technique']} के माध्यम से आधिकारिक {impersonation_info['brand']} "
                    f"वेबसाइट ({impersonation_info['official']}) होने का दिखावा करता है।"
                )
                affects_en = (
                    f"Entering login passwords, OTPs, or payment details on '{host}' hands them straight to scammers."
                )
                affects_hi = f"'{host}' पर पासवर्ड, ओटीपी या भुगतान विवरण दर्ज करने से वे सीधे ठगों के पास चले जाएंगे।"
                calm_en = (
                    f"🛑 IMPERSONATION ALERT: '{host}' is a fake look-alike of {impersonation_info['brand']}! "
                    f"The real domain is '{impersonation_info['official']}'."
                )
                calm_hi = (
                    f"🛑 नकली वेबसाइट चेतावनी: '{host}' {impersonation_info['brand']} की नकल है! "
                    f"असली वेबसाइट '{impersonation_info['official']}' है।"
                )
                indicators.append({
                    "type": impersonation_info["technique"],
                    "target": host,
                    "explanation": impersonation_info["explanation"],
                    "severity": "High",
                })

    # Check mixed scripts in body text look-alike words if no URL
    if not has_url and _has_mixed_scripts(candidate):
        # Allow pure English + standard Hindi Devanagari sentences without Latin-Cyrillic word mixing
        for word in candidate.split():
            if _has_mixed_scripts(word):
                score = max(score, 65)
                category = "Mixed-Script Obfuscated Text"
                indicators.append({
                    "type": "Mixed-Script Word Obfuscation",
                    "target": word[:40],
                    "explanation": "Word combines multiple Unicode scripts (e.g., Latin + Cyrillic) to evade filters.",
                    "severity": "Medium",
                })
                break

    # Allow-list logic for genuine bank OTPs and genuine UPI payment receipts
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
            about_en = "A standard One-Time Password (OTP) alert that explicitly warns you NOT to share the code."
            about_hi = "एक मानक वन-टाइम पासवर्ड (OTP) संदेश जो स्पष्ट रूप से कोड साझा न करने की चेतावनी देता है।"
            seems_en = "Genuine transactional security OTP from your bank or service."
            seems_hi = "आपके बैंक या सेवा से वास्तविक सुरक्षा ओटीपी (OTP)।"
            affects_en = "Safe as long as you initiated the login/payment yourself and never read the code to anyone."
            affects_hi = "यह पूरी तरह सुरक्षित है जब तक आप इसे किसी कॉलर या अनजान व्यक्ति के साथ साझा नहीं करते।"
            calm_en = "✅ Verified Safe: Genuine bank OTP alert. Keep this code private."
            calm_hi = "✅ सुरक्षित: यह वास्तविक बैंक OTP संदेश है। इस कोड को किसी के साथ साझा न करें।"
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
            about_en = "A standard confirmation receipt for a completed UPI payment."
            about_hi = "पूर्ण किए गए UPI भुगतान की मानक पुष्टि रसीद।"
            seems_en = "Genuine post-transaction notification with no action or link required."
            seems_hi = "वास्तविक लेनदेन सूचना जिसमें किसी लिंक या पिन की आवश्यकता नहीं है।"
            affects_en = "Informational receipt only; poses zero security risk."
            affects_hi = "केवल जानकारी के लिए रसीद; कोई सुरक्षा जोखिम नहीं है।"
            calm_en = "✅ Verified Safe: Standard UPI payment confirmation receipt."
            calm_hi = "✅ सुरक्षित: मानक UPI भुगतान पुष्टि रसीद।"
            indicators = []

        elif whitelisted and is_url:
            is_verified_safe = True
            score = 0
            category = "Verified Official Website"
            dark_pattern = "None"
            about_en = f"Direct link to verified official website '{host}'."
            about_hi = f"सत्यापित आधिकारिक वेबसाइट '{host}' का सीधा लिंक।"
            seems_en = f"Official, trusted domain ('{host}')."
            seems_hi = f"आधिकारिक और विश्वसनीय डोमेन ('{host}')।"
            affects_en = "Safe to visit; matches known official domain whitelist."
            affects_hi = "विज़िट करने के लिए सुरक्षित; आधिकारिक डोमेन सूची से मेल खाता है।"
            calm_en = f"✅ Verified Safe: '{host}' is an official trusted website."
            calm_hi = f"✅ सुरक्षित: '{host}' एक आधिकारिक और विश्वसनीय वेबसाइट है।"
            indicators = []

    if not is_verified_safe:
        # 1. Linkless Credential / OTP / PIN / CVV Harvesting
        asks_secrets = any(k in t_low for k in ["password", "otp", "upi pin", "mpin", "cvv", "seed phrase", "api key", "secret key"])
        asks_action = any(k in t_low for k in ["reply", "send", "share", "provide", "enter", "confirm", "verify", "reactivate", "restricted", "blocked", "suspended"])
        if asks_secrets and (asks_action or "username" in t_low):
            score = max(score, 96)
            category = "Direct Credential & OTP Harvesting Scam"
            dark_pattern = "Fear Appeal & Direct Secret Extraction"
            about_en = "An urgent alert claiming account restriction and asking you to reply with or share your username, password, PIN, or OTP."
            about_hi = "खाता बंद होने का डर दिखाकर आपसे यूजरनेम, पासवर्ड, पिन या ओटीपी (OTP) मांगने वाला संदेश।"
            seems_en = "Disguised as an official bank or AI security verification prompt."
            seems_hi = "आधिकारिक बैंक या सुरक्षा सत्यापन संदेश जैसा दिखने का प्रयास।"
            affects_en = "Sharing your password or OTP lets scammers take over your bank account and steal your money immediately."
            affects_hi = "पासवर्ड या ओटीपी साझा करने से ठग तुरंत आपके बैंक खाते से पैसे निकाल सकते हैं।"
            calm_en = "🚨 STOP! Real banks and support teams NEVER ask for your password, PIN, or OTP in a message reply."
            calm_hi = "🚨 रुकें! कोई भी असली बैंक कभी भी संदेश में आपका पासवर्ड, पिन या ओटीपी नहीं मांगता है।"
            indicators.append({
                "type": "Direct Secret / OTP Demand",
                "target": "Request for Username / Password / OTP / PIN",
                "explanation": "Demands confidential login secrets directly under a false urgency pretext.",
                "severity": "High",
            })

        # 2. UPI Collect Request Refund Trap
        if ("request" in t_low or "collect" in t_low or "pay ₹" in t_low or "pay rs" in t_low) and any(
            k in t_low for k in ["refund", "cashback", "receive", "upi pin", "enter pin", "olx"]
        ):
            score = max(score, collect_w + 46)
            category = "UPI Collect-Request Reversal Scam"
            dark_pattern = "Semantic Misdirection ('Refund' Note on Debit Button)"
            about_en = "A UPI payment request labeled as a 'Refund' or 'Cashback' that asks you to tap 'Pay' and enter your UPI PIN."
            about_hi = "एक UPI भुगतान अनुरोध जिसे 'रिफंड' या 'कैशबैक' बताया गया है और आपसे 'Pay' दबाकर UPI पिन डालने को कहता है।"
            seems_en = "Pretends to be money coming INTO your account."
            seems_hi = "ऐसा दिखावा करता है जैसे आपके खाते में पैसे आ रहे हैं।"
            affects_en = "Entering your UPI PIN on a collect request ALWAYS deducts money from your bank account."
            affects_hi = "UPI पिन डालने से हमेशा आपके बैंक खाते से पैसे कटते हैं, मिलते नहीं हैं।"
            calm_en = "🛑 STOP: You NEVER need to enter your UPI PIN or click 'Pay' to receive money! Decline this request."
            calm_hi = "🛑 रुकें: पैसे प्राप्त करने के लिए कभी भी UPI पिन डालने या 'Pay' दबाने की आवश्यकता नहीं होती है!"
            indicators.append({
                "type": "UPI Collect Debit Trap",
                "target": "Action 'Pay / Enter PIN' vs Note 'Refund/Cashback'",
                "explanation": "Scammer disguised an outgoing money collect request as an incoming refund.",
                "severity": "High",
            })

        # 3. Utility / Electricity / KYC / Parcel / Job Scams
        if ("electricity" in t_low or "power" in t_low) and ("disconnect" in t_low or "tonight" in t_low or "9:30" in t_low):
            score = max(score, urgency_w + 68)
            category = "Utility Disconnection Phishing & Vishing Lure"
            dark_pattern = "Artificial Night-Time Deadline Panic"
            about_en = "A message threatening that your electricity will be cut off tonight unless you call a number or click a link."
            about_hi = "आज रात बिजली काटने की धमकी देने वाला संदेश जो किसी नंबर पर कॉल करने या लिंक खोलने को कहता है।"
            seems_en = "Pretends to be an urgent notice from the electricity board."
            seems_hi = "बिजली विभाग की ओर से तत्काल चेतावनी जैसा दिखता है।"
            affects_en = "Tricks panicked users into calling scammers who ask to install screen-sharing apps or pay fake bills."
            affects_hi = "घबराहट में उपयोगकर्ता ठगों को कॉल कर बैठते हैं और स्क्रीन-शेयरिंग ऐप या नकली लिंक के शिकार हो जाते हैं।"
            calm_en = "🧘 Relax: Your electricity is NOT getting cut tonight. Utility boards never disconnect power via personal mobile numbers or '.xyz' links."
            calm_hi = "🧘 शांत रहें: आज रात आपकी बिजली नहीं कट रही है। बिजली बोर्ड कभी भी निजी नंबरों से ऐसी धमकी नहीं देता।"
            indicators.append({
                "type": "Artificial Cutoff Deadline",
                "target": "Electricity disconnection tonight threat",
                "explanation": "Uses false night-time disconnection panic to bypass critical thinking.",
                "severity": "High",
            })

        if any(k in t_low for k in ["daily", "wfh", "part-time", "work from home"]) and any(
            k in t_low for k in ["rating", "youtube", "trial bonus", "₹3,000", "₹5,000", "instant bonus", "telegram"]
        ):
            score = max(score, 90)
            category = "Prepaid Task / Fake Job Scam"
            dark_pattern = "Micro-Reward Bait-and-Switch"
            about_en = "An offer promising thousands of rupees daily for simple online ratings or likes."
            about_hi = "घर बैठे रेटिंग या लाइक करके रोज़ हज़ारों रुपये कमाने का प्रलोभन।"
            seems_en = "Pretends to be an easy work-from-home part-time job."
            seems_hi = "आसान वर्क-फ्रॉम-होम पार्ट-टाइम नौकरी जैसा दिखता है।"
            affects_en = "Pays a tiny initial bonus to gain trust, then demands large 'prepaid VIP task' deposits and steals your money."
            affects_hi = "पहले छोटा बोनस देकर भरोसा जीतते हैं और फिर 'VIP टास्क' के नाम पर बड़ी रकम जमा करवाकर ठग लेते हैं।"
            calm_en = "💡 Heads up: This is a classic prepaid task scam. Do not join their group or deposit money."
            calm_hi = "💡 सावधान: यह एक प्रीपेड टास्क स्कैम है। किसी भी ग्रुप में न जुड़ें और पैसे जमा न करें।"
            indicators.append({
                "type": "Unrealistic Task Payout Lure",
                "target": "Earn thousands daily for ratings/likes",
                "explanation": "Matches known WhatsApp/Telegram prepaid task scam pattern.",
                "severity": "High",
            })

        # 4. Emotional Family Emergency Lure
        if any(k in t_low for k in ["met with accident", "hospital", "phone fell", "broken screen", "friend's number", "police station"]) and any(
            k in t_low for k in ["send money", "urgently", "upi", "rs", "₹", "transfer"]
        ):
            score = max(score, 88)
            category = "Emotional Emergency Impersonation Scam"
            dark_pattern = "Emotional Panic Manipulation"
            about_en = "An urgent message claiming a family member or friend is in a hospital/accident emergency and needs immediate money."
            about_hi = "दुर्घटना या अस्पताल की आपात स्थिति का दावा करके तुरंत पैसे मांगने वाला संदेश।"
            seems_en = "Pretends to be a distressed relative messaging from a new number."
            seems_hi = "नए नंबर से संदेश भेजने वाले किसी परेशान रिश्तेदार जैसा प्रतीत होता है।"
            affects_en = "Exploits fear for loved ones so you transfer money before calling them to verify."
            affects_hi = "अपनो की चिंता का फायदा उठाकर बिना जांचे पैसे ट्रांसफर करवाने की कोशिश।"
            calm_en = "🧘 Pause and breathe: Call your family member's real phone number directly before sending a single rupee."
            calm_hi = "🧘 रुकें और शांत रहें: एक भी रुपया भेजने से पहले अपने परिजन के असली नंबर पर सीधे कॉल करके पुष्टि करें।"
            indicators.append({
                "type": "Emergency Pretext Money Demand",
                "target": "Accident / Hospital + Immediate UPI Transfer",
                "explanation": "Uses emotional shock to prevent the victim from verifying caller identity.",
                "severity": "High",
            })

        # 5. USSD Call Forwarding (*401*)
        if "*401*" in t_low:
            score = 99
            category = "USSD Call-Forwarding OTP Interception Scam"
            dark_pattern = "Courier / Support Pretext USSD Abuse"
            about_en = "Instructions asking you to dial '*401*' followed by a phone number."
            about_hi = "'*401*' के बाद किसी फ़ोन नंबर को डायल करने का निर्देश।"
            seems_en = "Pretends to be a parcel cancellation or customer service code."
            seems_hi = "पार्सल रद्दीकरण या कस्टमर केयर कोड जैसा दिखावा करता है।"
            affects_en = "Dialing *401* forwards all your incoming phone calls and bank voice OTPs to the scammer's phone."
            affects_hi = "*401* डायल करने से आपकी सभी इनकमिंग कॉल और बैंक ओटीपी ठग के फोन पर फॉरवर्ड हो जाते हैं।"
            calm_en = "🚨 DANGER: Never dial *401*! If you already dialed it, dial ##002# immediately to cancel call forwarding."
            calm_hi = "🚨 खतरा: कभी भी *401* डायल न करें! यदि कर दिया है, तो कॉल फॉरवर्डिंग बंद करने के लिए तुरंत ##002# डायल करें।"
            indicators.append({
                "type": "Malicious Carrier USSD Code (*401*)",
                "target": "*401*",
                "explanation": "Unconditional call-forwarding code disguised as a verification code.",
                "severity": "High",
            })

        # 6. Vague Attention-Bait / Information-Withholding Lures ("5M credited to your account, click here")
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
        ) or (has_url and not whitelisted)

        if (has_bait_hook or has_vague_cta) and score < 85:
            vague_score = max(bait_w + 30, 86) if (has_bait_hook and has_vague_cta) else max(bait_w, 58)
            score = max(score, vague_score)
            category = "Vague Attention-Bait / Curiosity Lure"
            dark_pattern = "Information-Withholding Curiosity / Greed Hook"
            about_en = f"A short, vague message ('{scrub_pii(candidate)[:80]}') making a big claim or demanding a click without verifiable context."
            about_hi = f"बिना किसी पक्के विवरण के बड़ा दावा करने या क्लिक करने के लिए कहने वाला अस्पष्ट संदेश ('{scrub_pii(candidate)[:80]}')।"
            seems_en = "Pretends to be a bank credit, reward payout, or urgent account alert."
            seems_hi = "बैंक क्रेडिट, इनाम या तत्काल खाता अलर्ट होने का दिखावा करता है।"
            affects_en = "Baits you into clicking an unverified link that leads to credential phishing or malware."
            affects_hi = "जिज्ञासा या लालच पैदा करके आपको खतरनाक फ़िशिंग लिंक पर क्लिक करने के लिए फंसाता है।"
            calm_en = "🧐 DOUBT THIS MESSAGE: Genuine banks never send vague '5M credited, click here' texts without official account details."
            calm_hi = "🧐 इस संदेश पर संदेह करें: असली बैंक कभी भी बिना खाता विवरण के ऐसे अस्पष्ट 'click here' संदेश नहीं भेजते।"
            indicators.append({
                "type": "Vague Attention-Bait Hook",
                "target": scrub_pii(candidate)[:60],
                "explanation": "Makes an attention-grabbing financial or urgent claim with zero verifiable business details.",
                "severity": "High" if score >= 66 else "Medium",
            })

    final_score = min(100, int(score))
    level_str = "High" if final_score >= 66 else "Medium" if final_score >= 31 else "Low"
    inconclusive = (final_score == 0 and not is_verified_safe and len(candidate) > 15)

    actions_en = (
        [
            "Do NOT click any links, reply with passwords/OTPs, or approve UPI collect requests.",
            "Verify independently by opening the official app or typing the real website address yourself.",
            "Report suspected cyber fraud to Helpline 1930 or https://cybercrime.gov.in.",
        ]
        if final_score >= 31
        else ["No immediate threat detected. Never share OTPs or UPI PINs with anyone."]
    )
    actions_hi = (
        [
            "किसी भी लिंक पर क्लिक न करें, पासवर्ड/OTP का जवाब न दें और UPI कलेक्ट रिक्वेस्ट स्वीकार न करें।",
            "आधिकारिक ऐप खोलकर या स्वयं असली वेबसाइट टाइप करके स्वतंत्र रूप से जांच करें।",
            "संदिग्ध साइबर धोखाधड़ी की रिपोर्ट हेल्पलाइन 1930 या https://cybercrime.gov.in पर करें।",
        ]
        if final_score >= 31
        else ["कोई तत्काल खतरा नहीं मिला। अपना OTP या UPI पिन कभी किसी के साथ साझा न करें।"]
    )

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
            f"Deterministic pre-analysis scored {final_score}/100 ({level_str}) vs naive keyword pass {min(100, pass1_score)}/100 "
            f"across {len(indicators)} triggered indicator(s)."
        ),
        "auto_calibration_note": "Deterministic Pass-1 vs Pass-2 evaluation ready.",
        "heuristic_indicators": indicators,
        "recommended_actions": actions_en,
        "recommended_actions_hi": actions_hi,
    }
