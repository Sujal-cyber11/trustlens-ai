"""Deterministic webpage analyzer with plain-language templates and real score_breakdown slices."""
from __future__ import annotations

import ipaddress
import logging
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from heuristics import (
    BENIGN_ACADEMIC_GOV_SUFFIXES,
    PLAIN_SIGNAL_TEMPLATES,
    PROTECTED_BRANDS,
    SUSPICIOUS_TLDS,
    WHITELIST_DOMAINS,
    build_normalized_score_breakdown,
    default_verdict_line,
    detect_brand_impersonation,
    domain_matches,
    has_explicit_urgency_or_threat,
    has_mixed_scripts,
    is_local_or_private_host,
    scrub_pii,
    split_domain_parts,
)

log = logging.getLogger("trustlens.page_analysis")


class PageSignal(BaseModel):
    id: str = Field(..., min_length=1, max_length=80)
    severity: str = Field("Medium", max_length=20)
    evidence: str = Field("", max_length=120)
    count: int = Field(1, ge=1, le=10000)

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_sev(cls, v: Any) -> str:
        s = str(v or "Medium").strip().lower()
        if s.startswith("high"):
            return "High"
        if s.startswith("low"):
            return "Low"
        return "Medium"

    @field_validator("evidence", mode="before")
    @classmethod
    def _clean_ev(cls, v: Any) -> str:
        return scrub_pii(str(v or "").strip())[:120]


class PageAuditRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    hostname: str = Field(..., min_length=1, max_length=255)
    title: str = Field("", max_length=300)
    signals: list[PageSignal] = Field(default_factory=list, max_length=60)
    text_sample: str = Field("", max_length=500)
    language: str = Field("en", pattern="^(en|hi)$")


PAGE_SIGNAL_TEMPLATES: dict[str, dict[str, Any]] = {
    "cross_site_login_form": {
        "name_en": "Fake Login Box Sending Password Elsewhere",
        "slice_key": "cross_site_login",
        "group": "malicious",
        "about_en": "What this is: A login box that sends your password to strangers.",
        "about_hi": "यह क्या है: एक लॉगिन बॉक्स जो आपका पासवर्ड अनजान लोगों को भेजता है।",
        "seems_en": "What it pretends to be: A normal sign-in page.",
        "seems_hi": "यह क्या दिखता है: एक सामान्य लॉगिन पेज।",
        "affects_en": "What could happen to you: They can steal your password when you sign in.",
        "affects_hi": "आप पर क्या असर होगा: लॉगिन करते ही आपका पासवर्ड चोरी हो सकता है।",
        "explain_en": "This login box sends your password to a different website.",
        "explain_hi": "यह लॉगिन बॉक्स आपका पासवर्ड किसी दूसरी वेबसाइट पर भेजता है।",
        "action_en": "Do not type your password on this page.",
        "action_hi": "इस पेज पर अपना पासवर्ड बिल्कुल न लिखें।",
    },
    "unsafe_http_login_form": {
        "name_en": "Unsafe Login Box Without Lock",
        "slice_key": "unsafe_connection",
        "group": "malicious",
        "about_en": "What this is: A login box on an unsafe connection.",
        "about_hi": "यह क्या है: बिना सुरक्षा लॉक वाला एक लॉगिन बॉक्स।",
        "seems_en": "What it pretends to be: A safe place to sign in.",
        "seems_hi": "यह क्या दिखता है: लॉगिन करने की एक सुरक्षित जगह।",
        "affects_en": "What could happen to you: Others can see the password you type here.",
        "affects_hi": "आप पर क्या असर होगा: यहाँ लिखा गया पासवर्ड दूसरे लोग देख सकते हैं।",
        "explain_en": "This login form sends your password without safety protection.",
        "explain_hi": "यह फॉर्म बिना किसी सुरक्षा के आपका पासवर्ड भेजता है।",
        "action_en": "Close this page without signing in.",
        "action_hi": "बिना लॉगिन किए इस पेज को बंद कर दें।",
    },
    "password_box_on_fake_site": {
        "name_en": "Password Box on Untrusted Site",
        "slice_key": "asks_for_otp",
        "group": "malicious",
        "about_en": "What this is: A fake website asking for your password or OTP.",
        "about_hi": "यह क्या है: पासवर्ड या OTP मांगने वाली एक नकली वेबसाइट।",
        "seems_en": "What it pretends to be: A real login page you know.",
        "seems_hi": "यह क्या दिखता है: आपकी जानी-पहचानी असली लॉगिन वेबसाइट।",
        "affects_en": "What could happen to you: Typing your password gives them your account.",
        "affects_hi": "आप पर क्या असर होगा: पासवर्ड लिखने से आपका खाता उनके हाथ लग जाएगा।",
        "explain_en": "It looks like a login page, but it steals passwords.",
        "explain_hi": "यह लॉगिन पेज जैसा दिखता है, पर पासवर्ड चुराने के लिए बना है।",
        "action_en": "Do not enter your password or OTP here.",
        "action_hi": "यहाँ अपना पासवर्ड या OTP बिल्कुल न डालें।",
    },
    "hidden_box_or_layer": {
        "name_en": "Hidden Trap Over Buttons",
        "slice_key": "hidden_button_trap",
        "group": "malicious",
        "about_en": "What this is: A page with an invisible layer over buttons.",
        "about_hi": "यह क्या है: बटनों के ऊपर छुपी हुई परत वाला एक पेज।",
        "seems_en": "What it pretends to be: A normal button or video player.",
        "seems_hi": "यह क्या दिखता है: एक सामान्य बटन या वीडियो प्लेयर।",
        "affects_en": "What could happen to you: Clicking a button clicks a hidden trap instead.",
        "affects_hi": "आप पर क्या असर होगा: बटन दबाने पर अनजाने में कुछ गलत क्लिक हो सकता है।",
        "explain_en": "An invisible box is hiding on top of the buttons.",
        "explain_hi": "बटनों के ऊपर एक न दिखने वाला जाल छुपा हुआ है।",
        "action_en": "Close this tab and do not click anything.",
        "action_hi": "इस टैब को बंद कर दें और कहीं क्लिक न करें।",
    },
    "fake_link_text": {
        "name_en": "Link Going to Wrong Place",
        "slice_key": "fake_link_text",
        "group": "malicious",
        "about_en": "What this is: A link that lies about where it goes.",
        "about_hi": "यह क्या है: एक लिंक जो दिखता कुछ है और ले कहीं और जाता है।",
        "seems_en": "What it pretends to be: A link to a trusted company.",
        "seems_hi": "यह क्या दिखता है: किसी भरोसेमंद कंपनी का असली लिंक।",
        "affects_en": "What could happen to you: Clicking it takes you to a fake website.",
        "affects_hi": "आप पर क्या असर होगा: इस पर क्लिक करने से आप नकली वेबसाइट पर पहुंच जाएंगे।",
        "explain_en": "The link text says one website name but opens another.",
        "explain_hi": "लिंक पर नाम किसी और वेबसाइट का लिखा है पर खुलता कुछ और है।",
        "action_en": "Do not click links on this page.",
        "action_hi": "इस पेज के किसी भी लिंक पर क्लिक न करें।",
    },
    "hidden_page_code_or_download": {
        "name_en": "Sneaky File Download or Code",
        "slice_key": "sneaky_download",
        "group": "malicious",
        "about_en": "What this is: A page trying to download files by itself.",
        "about_hi": "यह क्या है: अपने आप फाइल डाउनलोड करने की कोशिश करता एक पेज।",
        "seems_en": "What it pretends to be: A normal download or update page.",
        "seems_hi": "यह क्या दिखता है: एक सामान्य डाउनलोड या अपडेट पेज।",
        "affects_en": "What could happen to you: It can put harmful files on your computer.",
        "affects_hi": "आप पर क्या असर होगा: यह आपके कंप्यूटर में खतरनाक फाइल डाल सकता है।",
        "explain_en": "This page tried to start a download without you clicking.",
        "explain_hi": "इस पेज ने आपके क्लिक किए बिना फाइल डाउनलोड करने की कोशिश की।",
        "action_en": "Delete any file this page downloaded.",
        "action_hi": "अगर कोई फाइल डाउनलोड हुई है तो उसे तुरंत डिलीट करें।",
    },
    "copy_or_close_trap": {
        "name_en": "Page Blocking Copy or Close",
        "slice_key": "copy_or_close_block",
        "group": "dark_pattern",
        "about_en": "What this is: A page that messes with your mouse or copying.",
        "about_hi": "यह क्या है: आपके माउस या कॉपी करने के काम को रोकने वाला पेज।",
        "seems_en": "What it pretends to be: A normal article or offer page.",
        "seems_hi": "यह क्या दिखता है: एक सामान्य जानकारी या ऑफर वाला पेज।",
        "affects_en": "What could happen to you: It can change what you copy or stop you leaving.",
        "affects_hi": "आप पर क्या असर होगा: यह आपके कॉपी किए गए टेक्स्ट को बदल सकता है।",
        "explain_en": "This page changes what you copy or blocks right-click.",
        "explain_hi": "यह पेज कॉपी किए टेक्स्ट को बदलता है या राइट-क्लिक रोकता है।",
        "action_en": "Close this browser tab now.",
        "action_hi": "इस ब्राउज़र टैब को अभी बंद कर दें।",
    },
    "unasked_popup_request": {
        "name_en": "Unasked Permission Popup",
        "slice_key": "unasked_popup",
        "group": "malicious",
        "about_en": "What this is: A page asking for camera, location, or alerts right away.",
        "about_hi": "यह क्या है: खुलते ही कैमरा, लोकेशन या अलर्ट मांगने वाला पेज।",
        "seems_en": "What it pretends to be: A normal website check.",
        "seems_hi": "यह क्या दिखता है: वेबसाइट की एक सामान्य जांच।",
        "affects_en": "What could happen to you: Allowing it lets them spam or track you.",
        "affects_hi": "आप पर क्या असर होगा: अनुमति देने से वे आपको नकली अलर्ट भेज सकते हैं।",
        "explain_en": "It asked for browser permissions without you clicking anything.",
        "explain_hi": "इसने आपके क्लिक किए बिना ही फोन या कंप्यूटर की अनुमति मांगी।",
        "action_en": "Click Block on the permission popup.",
        "action_hi": "अनुमति मांगने वाले बॉक्स पर Block दबाएं।",
    },
    "ClickFix": {
        "name_en": "Fake Computer Fix Command Trick",
        "slice_key": "clickfix_keys",
        "group": "malicious",
        "about_en": "What this is: A fake check asking you to press keys on your keyboard.",
        "about_hi": "यह क्या है: कीबोर्ड पर बटन दबाने के लिए कहने वाला एक खतरनाक धोखा।",
        "seems_en": "What it pretends to be: A human check or computer fix step.",
        "seems_hi": "यह क्या दिखता है: इंसान होने की जांच या कंप्यूटर ठीक करने का तरीका।",
        "affects_en": "What could happen to you: Pressing those keys installs bad software on your PC.",
        "affects_hi": "आप पर क्या असर होगा: ये बटन दबाने से आपके कंप्यूटर में वायरस आ सकता है।",
        "explain_en": "Real websites never ask you to press Win+R and paste text.",
        "explain_hi": "असली वेबसाइट कभी भी Win+R दबाकर कुछ पेस्ट करने को नहीं कहती।",
        "action_en": "Do not press Win+R or paste anything.",
        "action_hi": "कीबोर्ड पर Win+R बिल्कुल न दबाएं और कुछ पेस्ट न करें।",
    },
    "fake_virus_scare": {
        "name_en": "Fake Virus Alert Popup",
        "slice_key": "fake_virus_alert",
        "group": "malicious",
        "about_en": "What this is: A fake warning saying your computer has a virus.",
        "about_hi": "यह क्या है: कंप्यूटर में वायरस होने का डर दिखाने वाली नकली चेतावनी।",
        "seems_en": "What it pretends to be: A real Windows security alert with a phone number.",
        "seems_hi": "यह क्या दिखता है: कंप्यूटर की असली सुरक्षा चेतावनी और हेल्पलाइन नंबर।",
        "affects_en": "What could happen to you: Calling that number lets scammers into your computer.",
        "affects_hi": "आप पर क्या असर होगा: उस नंबर पर कॉल करने से ठग आपका कंप्यूटर कंट्रोल कर लेंगे।",
        "explain_en": "Webpages cannot scan your computer for viruses. This alert is fake.",
        "explain_hi": "कोई भी वेबसाइट आपके कंप्यूटर में वायरस नहीं ढूंढ सकती। यह झूठ है।",
        "action_en": "Do not call the phone number on the screen.",
        "action_hi": "स्क्रीन पर लिखे फोन नंबर पर बिल्कुल कॉल न करें।",
    },
    "fake_timer": {
        "name_en": "Fake Countdown Clock",
        "slice_key": "fake_countdown",
        "group": "dark_pattern",
        "about_en": "What this is: A shopping or offer page with a fake timer.",
        "about_hi": "यह क्या है: नकली घड़ी दिखाकर जल्दी कराने वाला एक पेज।",
        "seems_en": "What it pretends to be: A deal that is about to end right now.",
        "seems_hi": "यह क्या दिखता है: अभी तुरंत खत्म होने वाला एक खास ऑफर।",
        "affects_en": "What could happen to you: It rushes you into buying without thinking.",
        "affects_hi": "आप पर क्या असर होगा: यह आपको बिना सोचे-समझे पैसे खर्च करने की जल्दी कराता है।",
        "explain_en": "The countdown clock starts over when you reload the page.",
        "explain_hi": "पेज दोबारा लोड करने पर यह घड़ी फिर से शुरू हो जाती है।",
        "action_en": "Ignore the clock and take your time.",
        "action_hi": "घड़ी पर ध्यान न दें और आराम से सोचकर फैसला लें।",
    },
    "pre_ticked_box": {
        "name_en": "Pre-Ticked Extra Cost Box",
        "slice_key": "pre_ticked_addon",
        "group": "dark_pattern",
        "about_en": "What this is: A page with extra boxes already ticked for you.",
        "about_hi": "यह क्या है: पहले से टिक किए गए एक्स्ट्रा चार्ज के बॉक्स वाला पेज।",
        "seems_en": "What it pretends to be: A normal checkout or signup form.",
        "seems_hi": "यह क्या दिखता है: एक सामान्य पेमेंट या साइन-अप फॉर्म।",
        "affects_en": "What could happen to you: You might pay extra monthly fees by mistake.",
        "affects_hi": "आप पर क्या असर होगा: गलती से आपके एक्स्ट्रा पैसे कट सकते हैं।",
        "explain_en": "They ticked an extra paid option for you without asking.",
        "explain_hi": "उन्होंने आपसे पूछे बिना पैसे वाले बॉक्स पर पहले से टिक लगा दिया है।",
        "action_en": "Untick any extra boxes before you pay.",
        "action_hi": "पेमेंट करने से पहले सभी फालतू बॉक्स से टिक हटा दें।",
    },
    "guilt_button": {
        "name_en": "Guilt-Trip No Button",
        "slice_key": "guilt_no_button",
        "group": "dark_pattern",
        "about_en": "What this is: A page that uses rude words on the No button.",
        "about_hi": "यह क्या है: मना करने वाले बटन पर अजीब बातें लिखने वाला पेज।",
        "seems_en": "What it pretends to be: A helpful discount or safety offer.",
        "seems_hi": "यह क्या दिखता है: आपकी बचत या सुरक्षा का एक ऑफर।",
        "affects_en": "What could happen to you: It tries to make you feel bad for saying no.",
        "affects_hi": "आप पर क्या असर होगा: यह आपको 'ना' कहने पर बुरा महसूस कराने की चाल है।",
        "explain_en": "The decline button uses guilt to push you into clicking yes.",
        "explain_hi": "मना करने वाला बटन आपको शर्मिंदा करके 'हाँ' दबाने के लिए उकसाता है।",
        "action_en": "Feel free to click the no button anyway.",
        "action_hi": "बिना झिझक मना करने वाले बटन को दबाएं।",
    },
    "unfair_buttons": {
        "name_en": "Giant Accept Button Trick",
        "slice_key": "unfair_choice_buttons",
        "group": "dark_pattern",
        "about_en": "What this is: A popup where Accept is huge and Reject is tiny.",
        "about_hi": "यह क्या है: एक बॉक्स जहाँ Accept बटन बहुत बड़ा और Reject छुपा हुआ है।",
        "seems_en": "What it pretends to be: A normal cookie or terms choice.",
        "seems_hi": "यह क्या दिखता है: एक सामान्य सहमति मांगने वाला बॉक्स।",
        "affects_en": "What could happen to you: It tricks you into sharing your browsing data.",
        "affects_hi": "आप पर क्या असर होगा: यह आपको अनजाने में अपनी जानकारी देने के लिए फंसाता है।",
        "explain_en": "They hid the reject button so you only see accept.",
        "explain_hi": "उन्होंने मना करने वाले बटन को छुपा दिया है ताकि आप सिर्फ हाँ दबाएं।",
        "action_en": "Look closely for the small reject or manage button.",
        "action_hi": "छोटे अक्षरों में लिखे Reject बटन को ढूंढकर दबाएं।",
    },
}

RAW_SIGNAL_TO_TEMPLATE_KEY: dict[str, str] = {
    "cross_domain_password_form": "cross_site_login_form",
    "insecure_http_form": "unsafe_http_login_form",
    "password_or_otp_input": "password_box_on_fake_site",
    "hidden_or_cross_iframe": "hidden_box_or_layer",
    "clickjack_overlay": "hidden_box_or_layer",
    "deceptive_anchor_mismatch": "fake_link_text",
    "suspicious_inline_script": "hidden_page_code_or_download",
    "document_write_script": "hidden_page_code_or_download",
    "auto_download_trigger": "hidden_page_code_or_download",
    "clipboard_hijack_hook": "copy_or_close_trap",
    "contextmenu_or_unload_trap": "copy_or_close_trap",
    "unprompted_permission_request": "unasked_popup_request",
    "clickfix_command_trap": "ClickFix",
    "fake_system_dialog": "fake_virus_scare",
    "fake_support_urgency": "fake_virus_scare",
    "resetting_countdown_timer": "fake_timer",
    "fake_urgency_scarcity": "fake_timer",
    "prechecked_addon_box": "pre_ticked_box",
    "forced_continuity_wording": "pre_ticked_box",
    "hidden_drip_pricing": "pre_ticked_box",
    "confirm_shaming": "guilt_button",
    "asymmetric_choice_ui": "unfair_buttons",
    "disguised_ad_button": "unfair_buttons",
    "misdirection_close_button": "fake_link_text",
    "nagging_modal": "unfair_buttons",
    "sneak_into_basket": "pre_ticked_box",
}


def strip_url_query_and_fragment(raw_url: str) -> str:
    try:
        p = urlparse(raw_url.strip())
        scheme = p.scheme if p.scheme in ("http", "https") else "https"
        netloc = (p.hostname or "").lower().rstrip(".")
        if p.port and p.port not in (80, 443):
            netloc = f"{netloc}:{p.port}"
        path = p.path or "/"
        return f"{scheme}://{netloc}{path}"[:500]
    except ValueError:
        return raw_url.split("?")[0].split("#")[0][:500]


def evaluate_page_signals(req: PageAuditRequest, memory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Scores webpage signals and builds a real score_breakdown list matching combined score."""
    memory = memory or {}
    weights = memory.get("weights", {})
    user_allowlist = [str(d).lower().strip() for d in memory.get("user_allowlist", []) if d]
    blacklist = [
        str(d).lower().strip()
        for d in memory.get("blacklisted_domains", [])
        if d and not domain_matches(str(d), user_allowlist) and not is_local_or_private_host(str(d))
    ]

    host = req.hostname.lower().strip(".")
    clean_url = strip_url_query_and_fragment(req.url)
    clean_title = scrub_pii(req.title.strip())[:200]
    clean_sample = scrub_pii(req.text_sample.strip())[:500]
    combined_text_low = f"{clean_title} {clean_sample}".lower()

    is_allowlisted = (
        is_local_or_private_host(host)
        or domain_matches(host, WHITELIST_DOMAINS)
        or domain_matches(host, user_allowlist)
    )
    is_academic_or_gov = host.endswith(BENIGN_ACADEMIC_GOV_SUFFIXES)
    blacklisted = (not is_allowlisted) and domain_matches(host, blacklist)

    malicious_score = 0
    dark_pattern_score = 0
    hard_signals_count = 0
    medium_signals_count = 0
    hard_floor = 0

    indicators: list[dict[str, str]] = []
    raw_slices: list[dict[str, Any]] = []
    dark_pattern_names: list[str] = []
    matched_template_keys: list[str] = []

    is_ip_literal = False
    try:
        ip_obj = ipaddress.ip_address(host)
        is_ip_literal = ip_obj.is_global
    except ValueError:
        is_ip_literal = False

    is_suspicious_tld = (not is_allowlisted) and host.endswith(SUSPICIOUS_TLDS)
    impersonation_info = detect_brand_impersonation(host, extra_allowlist=user_allowlist) if not is_allowlisted else None
    has_urgency_threat = has_explicit_urgency_or_threat(combined_text_low)

    claimed_brand_in_title = None
    if not is_allowlisted and clean_title:
        t_low = clean_title.lower()
        for brand, official_doms in PROTECTED_BRANDS.items():
            if len(brand) >= 4 and brand in t_low:
                claimed_brand_in_title = (brand, official_doms[0])
                break

    if blacklisted:
        malicious_score = max(malicious_score, 80)
        hard_signals_count += 1
        hard_floor = max(hard_floor, 80)
        raw_slices.append({"key": "known_scam_link", "points": 80, "severity": "High"})
        indicators.append({
            "type": "Known Scam Link",
            "target": host,
            "explanation": PLAIN_SIGNAL_TEMPLATES["known_bad_link"]["explain_en"],
            "severity": "High",
        })

    if impersonation_info:
        boost = int(impersonation_info.get("score_boost", 92))
        malicious_score = max(malicious_score, boost)
        hard_signals_count += 1
        hard_floor = max(hard_floor, boost)
        raw_slices.append({"key": "fake_website_name", "points": boost, "severity": "High"})
        indicators.append({
            "type": impersonation_info["technique"],
            "target": host,
            "explanation": impersonation_info["explanation"],
            "severity": "High",
        })

    if not is_allowlisted:
        if is_suspicious_tld:
            tld_pen = int(weights.get("unverified_tld_penalty", 40))
            malicious_score += tld_pen
            medium_signals_count += 1
            raw_slices.append({"key": "strange_link_ending", "points": tld_pen, "severity": "Medium"})
            indicators.append({
                "type": "Strange Link Ending",
                "target": host,
                "explanation": PLAIN_SIGNAL_TEMPLATES["strange_link_ending"]["explain_en"],
                "severity": "Medium",
            })
        if is_ip_literal:
            malicious_score = max(malicious_score, 75)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 75)
            raw_slices.append({"key": "number_only_link", "points": 75, "severity": "High"})
            indicators.append({
                "type": "Number-Only Address",
                "target": host,
                "explanation": "This page uses numbers instead of a real company name.",
                "severity": "High",
            })
        subdomain, _, _ = split_domain_parts(host)
        if len([p for p in subdomain.split(".") if p]) >= 3:
            malicious_score += 25
            medium_signals_count += 1
            raw_slices.append({"key": "confusing_long_link", "points": 25, "severity": "Medium"})
            indicators.append({
                "type": "Long Confusing Address",
                "target": host,
                "explanation": "This address stacks extra words to hide the real website name.",
                "severity": "Medium",
            })
        if has_mixed_scripts(host) or "xn--" in host:
            malicious_score = max(malicious_score, 85)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 85)
            raw_slices.append({"key": "mixed_foreign_letters", "points": 85, "severity": "High"})
            indicators.append({
                "type": "Look-Alike Foreign Letters",
                "target": host,
                "explanation": "This address mixes foreign letters to trick your eyes.",
                "severity": "High",
            })

    signal_ids = {s.id.strip().lower() for s in req.signals}
    has_cross_domain_or_http_form = bool(signal_ids & {"cross_domain_password_form", "insecure_http_form"})
    has_domain_or_form_threat = bool(
        has_cross_domain_or_http_form
        or impersonation_info
        or is_suspicious_tld
        or is_ip_literal
        or blacklisted
        or claimed_brand_in_title
        or has_urgency_threat
    )

    for sig in req.signals:
        sid = sig.id.strip().lower()
        tpl_key = RAW_SIGNAL_TO_TEMPLATE_KEY.get(sid, "cross_site_login_form")
        tpl = PAGE_SIGNAL_TEMPLATES[tpl_key]
        human_label = tpl["name_en"]
        slice_key = tpl["slice_key"]
        group = tpl["group"]
        ev = sig.evidence or f"Found {sig.count} time(s)"

        if sid == "cross_domain_password_form":
            pen = int(weights.get("cross_domain_form_penalty", 75))
            malicious_score = max(malicious_score + 35, pen + 15)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 90)
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": max(pen, 75), "severity": "High"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High",
            })
        elif sid == "insecure_http_form":
            pen = int(weights.get("insecure_form_penalty", 45))
            malicious_score = max(malicious_score + pen, 72)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 72)
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": max(pen, 45), "severity": "High"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High",
            })
        elif sid == "password_or_otp_input":
            if has_domain_or_form_threat and not is_allowlisted:
                malicious_score = max(malicious_score + 20, 75 if (impersonation_info or blacklisted or claimed_brand_in_title) else 50)
                if impersonation_info or blacklisted or claimed_brand_in_title:
                    hard_signals_count += 1
                    hard_floor = max(hard_floor, 92)
                else:
                    medium_signals_count += 1
                matched_template_keys.append(tpl_key)
                raw_slices.append({"key": slice_key, "points": 25, "severity": "High" if hard_floor >= 66 else "Medium"})
                indicators.append({
                    "type": human_label,
                    "target": ev,
                    "explanation": tpl["explain_en"],
                    "severity": "High" if hard_floor >= 66 else "Medium",
                })
        elif sid == "hidden_or_cross_iframe":
            malicious_score += 25
            medium_signals_count += 1
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": 25, "severity": "Medium"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "Medium",
            })
        elif sid == "clickjack_overlay":
            pen = int(weights.get("clickjack_overlay_penalty", 55))
            malicious_score = max(malicious_score + pen, 55)
            medium_signals_count += 1
            if "hidden_or_cross_iframe" in signal_ids or not is_allowlisted:
                hard_floor = max(hard_floor, 55)
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": pen, "severity": "High" if malicious_score >= 66 else "Medium"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High" if malicious_score >= 66 else "Medium",
            })
        elif sid == "deceptive_anchor_mismatch":
            pen = int(weights.get("deceptive_link_penalty", 45))
            malicious_score = max(malicious_score + pen, 68)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 68)
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": max(pen, 45), "severity": "High"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High",
            })
        elif sid in ("suspicious_inline_script", "document_write_script"):
            pen = int(weights.get("suspicious_script_penalty", 35))
            malicious_score += pen
            medium_signals_count += 1
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": pen, "severity": "Medium"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "Medium",
            })
        elif sid == "auto_download_trigger":
            malicious_score = max(malicious_score + 55, 80)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 80)
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": 80, "severity": "High"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High",
            })
        elif sid in ("clipboard_hijack_hook", "contextmenu_or_unload_trap"):
            malicious_score += 30
            dark_pattern_score += 25
            medium_signals_count += 1
            dark_pattern_names.append(human_label)
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": 30, "severity": "Medium"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "Medium",
            })
        elif sid == "unprompted_permission_request":
            pen = int(weights.get("unprompted_permission_penalty", 40))
            malicious_score += pen
            medium_signals_count += 1
            matched_template_keys.append(tpl_key)
            raw_slices.append({"key": slice_key, "points": pen, "severity": "Medium"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "Medium",
            })
        elif sid == "clickfix_command_trap":
            pen = int(weights.get("clickfix_penalty", 95))
            malicious_score = max(malicious_score, pen)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 95)
            matched_template_keys.insert(0, tpl_key)
            raw_slices.append({"key": slice_key, "points": pen, "severity": "High"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High",
            })
        elif sid in ("fake_system_dialog", "fake_support_urgency"):
            pen = int(weights.get("fake_system_ui_penalty", 85))
            malicious_score = max(malicious_score, pen)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 85)
            matched_template_keys.insert(0, tpl_key)
            raw_slices.append({"key": slice_key, "points": pen, "severity": "High"})
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High",
            })
        elif group == "dark_pattern":
            dark_pattern_names.append(human_label)
            medium_signals_count += 1
            matched_template_keys.append(tpl_key)
            if sid == "resetting_countdown_timer":
                pts = int(weights.get("dark_pattern_timer_penalty", 35)) + 10
            elif sid == "fake_urgency_scarcity":
                pts = int(weights.get("dark_pattern_timer_penalty", 35))
            elif sid in ("prechecked_addon_box", "forced_continuity_wording", "hidden_drip_pricing"):
                pts = int(weights.get("dark_pattern_prechecked_penalty", 25)) + 10
            elif sid == "confirm_shaming":
                pts = int(weights.get("dark_pattern_shaming_penalty", 25)) + 10
            elif sid in ("asymmetric_choice_ui", "disguised_ad_button", "misdirection_close_button", "nagging_modal"):
                pts = int(weights.get("dark_pattern_asymmetric_penalty", 25)) + 10
            elif sid == "sneak_into_basket":
                pts = int(weights.get("dark_pattern_sneak_penalty", 35)) + 10
            else:
                pts = 25
            dark_pattern_score += pts
            raw_slices.append({"key": slice_key, "points": pts, "severity": "High" if dark_pattern_score >= 66 else "Medium"})

            indicators.append({
                "type": f"Trick: {human_label}",
                "target": ev,
                "explanation": tpl["explain_en"],
                "severity": "High" if dark_pattern_score >= 66 else "Medium",
            })

    if claimed_brand_in_title and not is_allowlisted:
        b_name, b_official = claimed_brand_in_title
        if "password_or_otp_input" in signal_ids or has_cross_domain_or_http_form:
            malicious_score = max(malicious_score, 92)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 92)
            matched_template_keys.insert(0, "password_box_on_fake_site")
            raw_slices.append({"key": "fake_website_name", "points": 65, "severity": "High"})
            indicators.append({
                "type": "Fake Brand Login Page",
                "target": f"Title says {b_name} on {host}",
                "explanation": f"The page says {b_name} but the website address is {host}, not {b_official}.",
                "severity": "High",
            })

    has_weak_login_text = any(
        w in combined_text_low for w in ("enter your password", "forgot password", "verify your account")
    )
    is_routine_student_or_org_portal = (
        is_academic_or_gov
        or any(w in combined_text_low for w in ("student login", "roll number", "faculty login", "staff login", "employee portal"))
    )

    if len(req.signals) == 0 and hard_signals_count == 0 and medium_signals_count == 0:
        if is_allowlisted or is_routine_student_or_org_portal:
            malicious_score = 0
            dark_pattern_score = 0
            needs_ai = False
            raw_slices = []
        elif has_urgency_threat:
            malicious_score = 45
            medium_signals_count = 1
            needs_ai = True
            raw_slices.append({"key": "vague_click_bait", "points": 45, "severity": "Medium"})
            indicators.append({
                "type": "Rushed Account Warning",
                "target": clean_sample[:80],
                "explanation": "This page uses scary words to rush you on an unknown website.",
                "severity": "Medium",
            })
        elif has_weak_login_text:
            malicious_score = 35
            needs_ai = True
            raw_slices.append({"key": "asks_for_otp", "points": 35, "severity": "Medium"})
            indicators.append({
                "type": "Login Prompt on Unknown Website",
                "target": host,
                "explanation": "This unknown website asks for a password. Check the address carefully.",
                "severity": "Medium",
            })
        else:
            malicious_score = 0
            dark_pattern_score = 0
            needs_ai = False
            raw_slices = []
    else:
        needs_ai = False

    malicious_score = min(100, malicious_score)
    dark_pattern_score = min(100, dark_pattern_score)

    combined = max(malicious_score, dark_pattern_score)
    if malicious_score >= 25 and dark_pattern_score >= 25:
        combined = min(100, combined + int(min(malicious_score, dark_pattern_score) * 0.25))
    combined = max(combined, hard_floor)

    if is_allowlisted and hard_signals_count == 0:
        combined = 0 if len(req.signals) == 0 else min(combined, 20)
        malicious_score = min(malicious_score, combined)
        dark_pattern_score = min(dark_pattern_score, combined)

    if combined >= 66 and hard_signals_count == 0 and medium_signals_count < 2:
        combined = 60
        malicious_score = min(malicious_score, 60)
        dark_pattern_score = min(dark_pattern_score, 60)

    if len(req.signals) == 0 and hard_signals_count == 0 and medium_signals_count <= 1:
        combined = min(combined, 45)
        malicious_score = min(malicious_score, 45)

    level = "High" if combined >= 66 else "Medium" if combined >= 31 else "Low"
    is_suspicious = combined >= 31

    if not needs_ai and not is_allowlisted:
        needs_ai = (25 <= combined <= 75) or (hard_signals_count > 0)

    verdict_en = default_verdict_line(level, "en")
    verdict_hi = default_verdict_line(level, "hi")
    dp_summary = ", ".join(dict.fromkeys(dark_pattern_names)) if dark_pattern_names else "None"
    breakdown = build_normalized_score_breakdown(raw_slices, combined)

    if not is_suspicious:
        safe_tpl = PLAIN_SIGNAL_TEMPLATES["safe_general"]
        cat = "Safe Webpage"
        calm_en = safe_tpl["calm_en"]
        calm_hi = safe_tpl["calm_hi"]
        about_en = safe_tpl["about_en"]
        about_hi = safe_tpl["about_hi"]
        seems_en = safe_tpl["seems_en"]
        seems_hi = safe_tpl["seems_hi"]
        affects_en = safe_tpl["affects_en"]
        affects_hi = safe_tpl["affects_hi"]
        actions_en = list(safe_tpl["actions_en"])
        actions_hi = list(safe_tpl["actions_hi"])
    elif impersonation_info:
        imp_tpl = PLAIN_SIGNAL_TEMPLATES["lookalike_website"]
        b_name = impersonation_info["brand"]
        cat = f"Fake {b_name.title()} Website"
        calm_en = imp_tpl["calm_en"]
        calm_hi = imp_tpl["calm_hi"]
        about_en = f"What this is: The website says {host}, not {impersonation_info['official']}."
        about_hi = f"यह क्या है: वेबसाइट का नाम {host} लिखा है, {impersonation_info['official']} नहीं।"
        seems_en = f"What it pretends to be: The real {b_name.title()} login page."
        seems_hi = f"यह क्या दिखता है: असली {b_name.title()} का लॉगिन पेज।"
        affects_en = imp_tpl["affects_en"]
        affects_hi = imp_tpl["affects_hi"]
        actions_en = list(imp_tpl["actions_en"])
        actions_hi = list(imp_tpl["actions_hi"])
    elif blacklisted:
        bl_tpl = PLAIN_SIGNAL_TEMPLATES["known_bad_link"]
        cat = "Known Scam Website"
        calm_en = bl_tpl["calm_en"]
        calm_hi = bl_tpl["calm_hi"]
        about_en = bl_tpl["about_en"]
        about_hi = bl_tpl["about_hi"]
        seems_en = bl_tpl["seems_en"]
        seems_hi = bl_tpl["seems_hi"]
        affects_en = bl_tpl["affects_en"]
        affects_hi = bl_tpl["affects_hi"]
        actions_en = list(bl_tpl["actions_en"])
        actions_hi = list(bl_tpl["actions_hi"])
    elif matched_template_keys:
        primary_key = matched_template_keys[0]
        ptpl = PAGE_SIGNAL_TEMPLATES[primary_key]
        cat = ptpl["name_en"]
        calm_en = "Stay calm. Read this before you click anything."
        calm_hi = "शांत रहें। कुछ भी क्लिक करने से पहले इसे पढ़ें।"
        about_en = ptpl["about_en"]
        about_hi = ptpl["about_hi"]
        seems_en = ptpl["seems_en"]
        seems_hi = ptpl["seems_hi"]
        affects_en = ptpl["affects_en"]
        affects_hi = ptpl["affects_hi"]

        actions_en = []
        actions_hi = []
        for k in dict.fromkeys(matched_template_keys):
            t_item = PAGE_SIGNAL_TEMPLATES[k]
            if len(actions_en) < 3:
                actions_en.append(t_item["action_en"])
                actions_hi.append(t_item["action_hi"])
    else:
        cat = "Unverified Login Page"
        calm_en = "Stay calm. Check the website address before signing in."
        calm_hi = "शांत रहें। लॉगिन करने से पहले वेबसाइट का नाम जांच लें।"
        about_en = "What this is: An unknown website asking for your password."
        about_hi = "यह क्या है: पासवर्ड मांगने वाली एक अनजान वेबसाइट।"
        seems_en = "What it pretends to be: A normal sign-in page."
        seems_hi = "यह क्या दिखता है: एक सामान्य लॉगिन पेज।"
        affects_en = "What could happen to you: They could steal your password if this site is fake."
        affects_hi = "आप पर क्या असर होगा: अगर यह साइट नकली है तो पासवर्ड चोरी हो सकता है।"
        actions_en = [
            "Check the website address carefully.",
            "Do not type your password if the name looks wrong.",
        ]
        actions_hi = [
            "वेबसाइट का नाम ध्यान से देखें।",
            "अगर नाम अजीब लगे तो अपना पासवर्ड न डालें।",
        ]

    return {
        "url": clean_url,
        "domain": host,
        "title": clean_title,
        "whitelisted": is_allowlisted,
        "blacklisted": blacklisted,
        "impersonation_detected": bool(impersonation_info),
        "malicious_score": malicious_score,
        "dark_pattern_score": dark_pattern_score,
        "base_score": combined,
        "score_breakdown": breakdown,
        "hard_floor": hard_floor,
        "hard_signal_fired": hard_signals_count > 0,
        "needs_ai": needs_ai,
        "pass1_naive_score": malicious_score,
        "verdict_line": verdict_en,
        "verdict_line_hi": verdict_hi,
        "overall_risk_score": level,
        "is_suspicious": is_suspicious,
        "detected_category": cat,
        "dark_pattern": dp_summary,
        "dark_pattern_count": len(dark_pattern_names),
        "calm_message": calm_en,
        "calm_message_hi": calm_hi,
        "what_input_is_about": about_en,
        "what_input_is_about_hi": about_hi,
        "what_it_seems_to_be": seems_en,
        "what_it_seems_to_be_hi": seems_hi,
        "how_it_affects_user": affects_en,
        "how_it_affects_user_hi": affects_hi,
        "confidence_score_explanation": (
            f"Combined score {combined}/100 (Safety risk {malicious_score}/100, "
            f"Tricks {dark_pattern_score}/100)."
        ),
        "heuristic_indicators": indicators,
        "recommended_actions": actions_en[:3],
        "recommended_actions_hi": actions_hi[:3],
    }
