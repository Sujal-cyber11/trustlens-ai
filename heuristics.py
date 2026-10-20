"""Deterministic local heuristics engine, plain-language validator, and score_breakdown builder for TrustLens AI.

All user-facing text and chart slice labels follow strict plain-language rules:
- Reading level: age 10. Short words. Sentences of 12 words or fewer.
- Zero banned technical jargon on the main card or chart labels.
- Everyday spoken Hindi / Hinglish for all _hi fields.
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

BANNED_WORDS: tuple[str, ...] = (
    "phishing",
    "homoglyph",
    "typosquat",
    "typosquatting",
    "credential",
    "credentials",
    "harvesting",
    "impersonation",
    "impersonating",
    "malicious",
    "heuristic",
    "heuristics",
    "obfuscation",
    "obfuscated",
    "dom",
    "domain",
    "domains",
    "url",
    "urls",
    "spoofing",
    "spoofed",
    "vishing",
    "social engineering",
    "indicator",
    "indicators",
    "payload",
    "payloads",
    "script",
    "scripts",
    "overlay",
    "overlays",
    "clickjacking",
    "dark pattern",
    "dark patterns",
    "hacked",
    "danger!!!",
)

# Plain-language labels for score_breakdown pie chart slices (EN & HI, passes simple_text_check)
PLAIN_SLICE_LABELS: dict[str, tuple[str, str]] = {
    "nothing_suspicious": ("Nothing suspicious found", "कुछ भी गलत नहीं मिला"),
    "other_small_things": ("Other small things", "अन्य छोटी बातें"),
    "fake_website_name": ("Fake website name", "नकली वेबसाइट का नाम"),
    "known_scam_link": ("Known scam link", "जानी-मानी नकली लिंक"),
    "strange_link_ending": ("Strange link ending", "अजीब अंत वाला लिंक"),
    "unsafe_connection": ("Link without safety lock", "बिना सुरक्षा लॉक का लिंक"),
    "number_only_link": ("Link made of numbers", "सिर्फ नंबरों वाला लिंक"),
    "hidden_short_link": ("Short link hiding address", "पता छुपाने वाला छोटा लिंक"),
    "confusing_long_link": ("Long confusing link name", "लंबा और उलझाने वाला नाम"),
    "mixed_foreign_letters": ("Tricky look-alike letters", "धोखा देने वाले मिलते-जुलते अक्षर"),
    "asks_for_otp": ("Asks for your OTP or password", "आपका OTP या पासवर्ड मांगना"),
    "fake_refund_trap": ("Fake refund asking for PIN", "पिन मांगने वाला नकली रिफंड"),
    "power_cutoff_scare": ("Fake power cutoff scare", "बिजली काटने का झूठा डर"),
    "fake_job_bonus": ("Fake daily job payout", "रोज़ कमाई का झूठा लालच"),
    "family_trouble_scare": ("Fake family emergency", "परिवार पर मुसीबत का झूठा डर"),
    "call_forward_code": ("Trick code *401* for calls", "कॉल चुराने वाला *401* कोड"),
    "vague_click_bait": ("Rushing you with missing details", "अधूरी बात बताकर क्लिक कराना"),
    "cross_site_login": ("Login box sending password away", "पासवर्ड बाहर भेजने वाला बॉक्स"),
    "hidden_button_trap": ("Hidden button on top of page", "पेज के ऊपर छुपा हुआ बटन"),
    "fake_link_text": ("Link going to wrong place", "गलत जगह ले जाने वाला लिंक"),
    "sneaky_download": ("Automatic file download", "अपने आप फाइल डाउनलोड होना"),
    "copy_or_close_block": ("Blocking copy or page close", "कॉपी करने या बंद करने से रोकना"),
    "unasked_popup": ("Asking permission without click", "बिना पूछे अनुमति मांगना"),
    "clickfix_keys": ("Asking to press keys on PC", "कीबोर्ड पर बटन दबाने की चाल"),
    "fake_virus_alert": ("Fake computer virus warning", "कंप्यूटर में वायरस की झूठी चेतावनी"),
    "fake_countdown": ("Fake countdown clock", "नकली उल्टी गिनती की घड़ी"),
    "pre_ticked_addon": ("Extra cost box already ticked", "पहले से टिक किया एक्स्ट्रा चार्ज"),
    "guilt_no_button": ("Rude words on the No button", "मना करने वाले बटन पर दबाव"),
    "unfair_choice_buttons": ("Huge accept button trick", "बहुत बड़ा हाँ बटन दिखाने की चाल"),
}

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

PLAIN_SIGNAL_TEMPLATES: dict[str, dict[str, Any]] = {
    "lookalike_website": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. Nothing bad has happened yet.",
        "calm_hi": "शांत रहें। अभी कुछ भी गलत नहीं हुआ है।",
        "about_en": "What this is: A fake website address spelled wrong on purpose.",
        "about_hi": "यह क्या है: जानबूझकर गलत स्पेलिंग वाला एक नकली वेबसाइट पता।",
        "seems_en": "What it pretends to be: A real company website you trust.",
        "seems_hi": "यह क्या दिखता है: आपकी जानी-पहचानी असली कंपनी की वेबसाइट।",
        "affects_en": "What could happen to you: They can steal your password and money.",
        "affects_hi": "आप पर क्या असर होगा: वे आपका पासवर्ड और पैसे चुरा सकते हैं।",
        "explain_en": "The website name is spelled wrong to trick you.",
        "explain_hi": "आपको धोखा देने के लिए वेबसाइट का नाम गलत लिखा गया है।",
        "actions_en": [
            "Do not open this link.",
            "Type the real website address yourself.",
            "Close this message now.",
        ],
        "actions_hi": [
            "इस लिंक को न खोलें।",
            "असली वेबसाइट का नाम खुद टाइप करें।",
            "इस मैसेज को अभी बंद कर दें।",
        ],
    },
    "known_bad_link": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. You are safe if you do not click.",
        "calm_hi": "शांत रहें। अगर आप क्लिक नहीं करते हैं तो आप सुरक्षित हैं।",
        "about_en": "What this is: A link from our known scam list.",
        "about_hi": "यह क्या है: हमारी नकली वेबसाइटों की लिस्ट में शामिल एक लिंक।",
        "seems_en": "What it pretends to be: A normal service or bank page.",
        "seems_hi": "यह क्या दिखता है: एक सामान्य बैंक या सेवा का पेज।",
        "affects_en": "What could happen to you: Opening it can steal your login details.",
        "affects_hi": "आप पर क्या असर होगा: इसे खोलने से आपका पासवर्ड चोरी हो सकता है।",
        "explain_en": "This website address is already on our known scam list.",
        "explain_hi": "यह वेबसाइट पता पहले से हमारी धोखाधड़ी की लिस्ट में है।",
        "actions_en": [
            "Do not open this link.",
            "Delete this message right away.",
            "Open your real bank app instead.",
        ],
        "actions_hi": [
            "इस लिंक को न खोलें।",
            "इस मैसेज को तुरंत डिलीट करें।",
            "इसकी जगह अपना असली बैंक ऐप खोलें।",
        ],
    },
    "strange_link_ending": {
        "verdict_en": "⚠️ Be careful",
        "verdict_hi": "⚠️ सावधान रहें",
        "calm_en": "Take a breath. Do not rush to click this link.",
        "calm_hi": "शांत रहें। इस लिंक पर क्लिक करने की जल्दबाजी न करें।",
        "about_en": "What this is: A web link with a strange ending.",
        "about_hi": "यह क्या है: अजीब अंत वाला एक वेब लिंक।",
        "seems_en": "What it pretends to be: An official notice or update link.",
        "seems_hi": "यह क्या दिखता है: एक सरकारी या कंपनी का असली लिंक।",
        "affects_en": "What could happen to you: Cheap fake links often steal your details.",
        "affects_hi": "आप पर क्या असर होगा: ऐसे सस्ते नकली लिंक आपकी जानकारी चुराते हैं।",
        "explain_en": "Real banks and big shops do not use strange link endings.",
        "explain_hi": "असली बैंक और बड़ी कंपनियां ऐसे अजीब लिंक का इस्तेमाल नहीं करतीं।",
        "actions_en": [
            "Do not click this link.",
            "Check your official app directly.",
        ],
        "actions_hi": [
            "इस लिंक पर क्लिक न करें।",
            "सीधे अपने असली ऐप में जाकर जांच करें।",
        ],
    },
    "asks_for_otp": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. Your account is safe if you do not reply.",
        "calm_hi": "शांत रहें। जवाब न देने पर आपका बैंक खाता सुरक्षित है।",
        "about_en": "What this is: A message asking for your password or OTP.",
        "about_hi": "यह क्या है: आपका पासवर्ड या OTP मांगने वाला एक नकली मैसेज।",
        "seems_en": "What it pretends to be: An urgent bank security alert.",
        "seems_hi": "यह क्या दिखता है: बैंक की तरफ से आया एक जरूरी अलर्ट।",
        "affects_en": "What could happen to you: Sharing your OTP lets them take your money.",
        "affects_hi": "आप पर क्या असर होगा: OTP बताने से वे आपके पैसे निकाल सकते हैं।",
        "explain_en": "It is rushing you to share your OTP or password.",
        "explain_hi": "यह डराकर आपसे आपका OTP या पासवर्ड मांग रहा है।",
        "actions_en": [
            "Do not reply to this message.",
            "Never share your OTP or password.",
            "Call your bank on the number on your card.",
        ],
        "actions_hi": [
            "इस मैसेज का जवाब न दें।",
            "अपना OTP या पासवर्ड किसी को न बताएं।",
            "अपने बैंक कार्ड पर लिखे नंबर पर कॉल करें।",
        ],
    },
    "fake_refund_request": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. Do not enter your UPI PIN.",
        "calm_hi": "शांत रहें। अपना UPI पिन बिल्कुल न डालें।",
        "about_en": "What this is: A payment request dressed up as a refund.",
        "about_hi": "यह क्या है: रिफंड के नाम पर पैसे मांगने वाला एक धोखा।",
        "seems_en": "What it pretends to be: Money coming into your bank account.",
        "seems_hi": "यह क्या दिखता है: जैसे आपके बैंक खाते में पैसे आ रहे हैं।",
        "affects_en": "What could happen to you: Entering your PIN takes money from your account.",
        "affects_hi": "आप पर क्या असर होगा: पिन डालते ही आपके खाते से पैसे कट जाएंगे।",
        "explain_en": "You never need to enter a PIN to receive money.",
        "explain_hi": "पैसे पाने के लिए कभी भी UPI पिन नहीं डालना पड़ता।",
        "actions_en": [
            "Tap Decline on this request now.",
            "Do not enter your UPI PIN.",
            "Block the person who sent this.",
        ],
        "actions_hi": [
            "इस रिक्वेस्ट को तुरंत Decline करें।",
            "अपना UPI पिन बिल्कुल न डालें।",
            "भेजने वाले नंबर को ब्लॉक करें।",
        ],
    },
    "electricity_cutoff_scam": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. Your electricity will not be cut tonight.",
        "calm_hi": "शांत रहें। आज रात आपकी बिजली नहीं कटेगी।",
        "about_en": "What this is: A fake warning about your electricity bill.",
        "about_hi": "यह क्या है: बिजली बिल के नाम पर डराने वाला नकली मैसेज।",
        "seems_en": "What it pretends to be: A final cutoff notice from the power office.",
        "seems_hi": "यह क्या दिखता है: बिजली विभाग से आया आखिरी नोटिस।",
        "affects_en": "What could happen to you: Calling them or clicking lets them steal money.",
        "affects_hi": "आप पर क्या असर होगा: कॉल करने या लिंक खोलने से पैसे चोरी हो सकते हैं।",
        "explain_en": "Power companies never cut electricity at night from personal phone numbers.",
        "explain_hi": "बिजली कंपनी कभी भी निजी नंबर से मैसेज भेजकर रात में बिजली नहीं काटती।",
        "actions_en": [
            "Do not call the phone number in the message.",
            "Do not click the link.",
            "Check your bill in your real electricity app.",
        ],
        "actions_hi": [
            "मैसेज में दिए गए नंबर पर कॉल न करें।",
            "लिंक पर क्लिक न करें।",
            "अपने असली बिजली ऐप में बिल चेक करें।",
        ],
    },
    "fake_job_offer": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. Do not send them any money.",
        "calm_hi": "शांत रहें। उन्हें एक भी रुपया न भेजें।",
        "about_en": "What this is: A fake work-from-home job message.",
        "about_hi": "यह क्या है: घर बैठे कमाई का लालच देने वाला नकली मैसेज।",
        "seems_en": "What it pretends to be: An easy job paying thousands every day.",
        "seems_hi": "यह क्या दिखता है: रोज़ हज़ारों दिलाने वाली एक आसान नौकरी।",
        "affects_en": "What could happen to you: They pay a small bonus then steal your savings.",
        "affects_hi": "आप पर क्या असर होगा: वे पहले छोटा बोनस देकर बाद में बड़ी रकम ठग लेंगे।",
        "explain_en": "Real jobs never ask you to pay money to unlock tasks.",
        "explain_hi": "असली नौकरी में काम पाने के लिए कभी पैसे जमा नहीं करने पड़ते।",
        "actions_en": [
            "Do not click the link.",
            "Never pay money to get a job.",
            "Block this sender.",
        ],
        "actions_hi": [
            "इस लिंक पर क्लिक न करें।",
            "काम पाने के लिए कभी पैसे न दें।",
            "इस नंबर को ब्लॉक करें।",
        ],
    },
    "family_emergency_scam": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. Call your family member first to check.",
        "calm_hi": "शांत रहें। पहले अपने घरवाले को फोन करके सच जानें।",
        "about_en": "What this is: A message claiming a relative is in trouble.",
        "about_hi": "यह क्या है: किसी रिश्तेदार के मुसीबत में होने का दावा करता मैसेज।",
        "seems_en": "What it pretends to be: Your family member texting from a new number.",
        "seems_hi": "यह क्या दिखता है: नए नंबर से आपके किसी अपने का मैसेज।",
        "affects_en": "What could happen to you: You might send money to a stranger in panic.",
        "affects_hi": "आप पर क्या असर होगा: घबराहट में आप किसी ठग को पैसे भेज सकते हैं।",
        "explain_en": "They want you to panic and send money without checking.",
        "explain_hi": "वे चाहते हैं कि आप घबराकर बिना पूछे तुरंत पैसे भेज दें।",
        "actions_en": [
            "Do not send any money yet.",
            "Call your relative on their old phone number.",
            "Ask a question only the real person knows.",
        ],
        "actions_hi": [
            "अभी बिल्कुल पैसे न भेजें।",
            "अपने रिश्तेदार के पुराने असली नंबर पर कॉल करें।",
            "उनसे कोई ऐसी बात पूछें जो सिर्फ वही जानते हों।",
        ],
    },
    "call_forwarding_trap": {
        "verdict_en": "🛑 This is a scam",
        "verdict_hi": "🛑 यह एक धोखा है",
        "calm_en": "Stay calm. Do not dial that code on your phone.",
        "calm_hi": "शांत रहें। अपने फोन पर वह नंबर बिल्कुल डायल न करें।",
        "about_en": "What this is: A trick code starting with *401*.",
        "about_hi": "यह क्या है: *401* से शुरू होने वाला एक धोखेबाज कोड।",
        "seems_en": "What it pretends to be: A code to cancel or track a parcel.",
        "seems_hi": "यह क्या दिखता है: पार्सल कैंसिल या ट्रैक करने का कोड।",
        "affects_en": "What could happen to you: It sends all your phone calls and OTPs to them.",
        "affects_hi": "आप पर क्या असर होगा: इससे आपके सारे कॉल और OTP ठग के फोन पर जाएंगे।",
        "explain_en": "Dialing *401* sends your bank calls to the scammer's phone.",
        "explain_hi": "*401* डायल करने से आपके बैंक कॉल ठग के नंबर पर चले जाते हैं।",
        "actions_en": [
            "Do not dial *401* on your phone.",
            "Dial ##002# now to stop any call forwarding.",
            "Hang up the call immediately.",
        ],
        "actions_hi": [
            "अपने फोन पर *401* कभी डायल न करें।",
            "कॉल फॉरवर्डिंग बंद करने के लिए ##002# डायल करें।",
            "कॉल तुरंत काट दें।",
        ],
    },
    "vague_attention_bait": {
        "verdict_en": "⚠️ Be careful",
        "verdict_hi": "⚠️ सावधान रहें",
        "calm_en": "Stay calm. Do not click the link out of curiosity.",
        "calm_hi": "शांत रहें। उत्सुकता में आकर लिंक पर क्लिक न करें।",
        "about_en": "What this is: A short message trying to grab your attention.",
        "about_hi": "यह क्या है: आपका ध्यान खींचने वाला एक अधूरा मैसेज।",
        "seems_en": "What it pretends to be: Big money or an urgent update for you.",
        "seems_hi": "यह क्या दिखता है: आपके खाते में बड़ी रकम आने या जरूरी खबर का मैसेज।",
        "affects_en": "What could happen to you: Clicking can take you to a fake page.",
        "affects_hi": "आप पर क्या असर होगा: क्लिक करने से आप किसी नकली वेबसाइट पर फंस सकते हैं।",
        "explain_en": "It makes a big claim with no real details to make you click.",
        "explain_hi": "यह बिना किसी पक्के सबूत के बड़ा दावा करके आपको क्लिक करने के लिए उकसाता है।",
        "actions_en": [
            "Do not click the link.",
            "Open your bank app yourself to check your balance.",
            "Ignore and delete this message.",
        ],
        "actions_hi": [
            "लिंक पर क्लिक न करें।",
            "बैलेंस देखने के लिए खुद अपना बैंक ऐप खोलें।",
            "इस मैसेज को अनदेखा करें और हटा दें।",
        ],
    },
    "safe_bank_otp": {
        "verdict_en": "✅ This looks safe",
        "verdict_hi": "✅ यह सुरक्षित लगता है",
        "calm_en": "Everything looks fine. Keep this OTP to yourself.",
        "calm_hi": "सब ठीक है। यह OTP किसी और को न बताएं।",
        "about_en": "What this is: A real one-time code from your bank.",
        "about_hi": "यह क्या है: आपके बैंक से आया एक असली OTP कोड।",
        "seems_en": "What it pretends to be: A normal login code with a safety reminder.",
        "seems_hi": "यह क्या दिखता है: सुरक्षा चेतावनी के साथ आया सामान्य लॉगिन कोड।",
        "affects_en": "What could happen to you: Nothing bad if you keep this code private.",
        "affects_hi": "आप पर क्या असर होगा: जब तक आप यह कोड किसी को नहीं बताते, आप सुरक्षित हैं।",
        "explain_en": "It has no fake links and reminds you not to share the code.",
        "explain_hi": "इसमें कोई नकली लिंक नहीं है और यह कोड न बताने की सलाह देता है।",
        "actions_en": [
            "Enter the code only if you are logging in right now.",
            "Never read this OTP to anyone on a call.",
        ],
        "actions_hi": [
            "अगर आप खुद लॉगिन कर रहे हैं तभी यह कोड डालें।",
            "फोन कॉल पर किसी को भी यह OTP न बताएं।",
        ],
    },
    "safe_upi_receipt": {
        "verdict_en": "✅ This looks safe",
        "verdict_hi": "✅ यह सुरक्षित लगता है",
        "calm_en": "Everything looks fine. This is just a payment receipt.",
        "calm_hi": "सब ठीक है। यह सिर्फ आपके पेमेंट की रसीद है।",
        "about_en": "What this is: A receipt for a payment that is already done.",
        "about_hi": "यह क्या है: पूरे हो चुके पेमेंट की एक सामान्य रसीद।",
        "seems_en": "What it pretends to be: A normal payment message from your bank.",
        "seems_hi": "यह क्या दिखता है: बैंक से आया पेमेंट पूरा होने का मैसेज।",
        "affects_en": "What could happen to you: Nothing bad. It does not ask for a PIN.",
        "affects_hi": "आप पर क्या असर होगा: कोई खतरा नहीं है। यह आपसे पिन नहीं मांगता।",
        "explain_en": "It only shows a past payment and asks for nothing.",
        "explain_hi": "यह सिर्फ पुराने पेमेंट की जानकारी दे रहा है और कुछ मांग नहीं रहा।",
        "actions_en": [
            "No action needed.",
            "Check your bank app if you do not recognize the payment.",
        ],
        "actions_hi": [
            "कुछ करने की जरूरत नहीं है।",
            "अगर पेमेंट आपने नहीं किया तो अपने बैंक ऐप में चेक करें।",
        ],
    },
    "safe_general": {
        "verdict_en": "✅ This looks safe",
        "verdict_hi": "✅ यह सुरक्षित लगता है",
        "calm_en": "Stay calm. Nothing bad was found here.",
        "calm_hi": "शांत रहें। यहाँ कोई गलत बात नहीं मिली।",
        "about_en": "What this is: A normal message or trusted website address.",
        "about_hi": "यह क्या है: एक सामान्य मैसेज या भरोसेमंद वेबसाइट पता।",
        "seems_en": "What it pretends to be: Normal everyday information.",
        "seems_hi": "यह क्या दिखता है: रोज़मर्रा की सामान्य जानकारी।",
        "affects_en": "What could happen to you: It does not ask for your password or money.",
        "affects_hi": "आप पर क्या असर होगा: यह आपसे पासवर्ड या पैसे नहीं मांगता है।",
        "explain_en": "No scam tricks were found in this text.",
        "explain_hi": "इस मैसेज में कोई धोखाधड़ी वाली बात नहीं मिली।",
        "actions_en": [
            "You can continue normally.",
            "Never share your OTP or password with anyone.",
        ],
        "actions_hi": [
            "आप सामान्य रूप से आगे बढ़ सकते हैं।",
            "अपना OTP या पासवर्ड कभी किसी को न बताएं।",
        ],
    },
}


def build_normalized_score_breakdown(
    raw_slices: list[dict[str, Any]],
    final_score: int,
) -> list[dict[str, Any]]:
    """
    Builds a mathematically honest score_breakdown list where:
    - Zero signals or final_score == 0 returns one slice: 'Nothing suspicious found' (0 points).
    - Non-zero final_score normalizes slice points if they exceed final_score, or appends
      'Other small things' if final_score exceeds the sum of slices, so sum(points) == final_score.
    """
    target = max(0, min(100, int(final_score)))
    merged_by_key: dict[str, dict[str, Any]] = {}
    for item in raw_slices:
        pts = int(item.get("points", 0) or 0)
        if pts <= 0:
            continue
        k = str(item.get("key") or "other_small_things")
        lbl_en, lbl_hi = PLAIN_SLICE_LABELS.get(
            k,
            (
                str(item.get("label_en") or "Other small things"),
                str(item.get("label_hi") or "अन्य छोटी बातें"),
            ),
        )
        sev = str(item.get("severity") or ("High" if pts >= 45 else "Medium"))
        if k in merged_by_key:
            merged_by_key[k]["points"] += pts
        else:
            merged_by_key[k] = {
                "key": k,
                "label_en": lbl_en,
                "label_hi": lbl_hi,
                "points": pts,
                "severity": sev,
            }

    slices = list(merged_by_key.values())
    if target == 0 or not slices:
        if target > 0 and not slices:
            lbl_en, lbl_hi = PLAIN_SLICE_LABELS["other_small_things"]
            return [
                {
                    "key": "other_small_things",
                    "label_en": lbl_en,
                    "label_hi": lbl_hi,
                    "points": target,
                    "severity": "High" if target >= 66 else "Medium",
                }
            ]
        lbl_en, lbl_hi = PLAIN_SLICE_LABELS["nothing_suspicious"]
        return [
            {
                "key": "nothing_suspicious",
                "label_en": lbl_en,
                "label_hi": lbl_hi,
                "points": 0,
                "severity": "Low",
            }
        ]

    total_raw = sum(s["points"] for s in slices)
    if total_raw > target:
        # Scale proportionally so sum equals target
        scaled: list[dict[str, Any]] = []
        running = 0
        for idx, s in enumerate(slices):
            if idx == len(slices) - 1:
                new_pts = max(1, target - running)
            else:
                new_pts = max(1, int(round((s["points"] / total_raw) * target)))
                if running + new_pts > target - (len(slices) - 1 - idx):
                    new_pts = max(1, target - (len(slices) - 1 - idx) - running)
            running += new_pts
            s_copy = dict(s)
            s_copy["points"] = new_pts
            scaled.append(s_copy)
        # Adjust last slice if rounding drifted by 1
        diff = target - sum(x["points"] for x in scaled)
        if diff != 0 and scaled:
            scaled[-1]["points"] = max(1, scaled[-1]["points"] + diff)
        return scaled

    if total_raw < target:
        rem = target - total_raw
        lbl_en, lbl_hi = PLAIN_SLICE_LABELS["other_small_things"]
        slices.append(
            {
                "key": "other_small_things",
                "label_en": lbl_en,
                "label_hi": lbl_hi,
                "points": rem,
                "severity": "Medium" if rem >= 20 else "Low",
            }
        )
    return slices


def default_verdict_line(overall_risk_score: str, lang: str = "en") -> str:
    lvl = str(overall_risk_score or "Low").strip().lower()
    if lang == "hi":
        if lvl.startswith("high"):
            return "🛑 यह एक धोखा है"
        if lvl.startswith("med"):
            return "⚠️ सावधान रहें"
        return "✅ यह सुरक्षित लगता है"
    if lvl.startswith("high"):
        return "🛑 This is a scam"
    if lvl.startswith("med"):
        return "⚠️ Be careful"
    return "✅ This looks safe"


def simple_text_check(text: str, lang: str = "en") -> tuple[bool, list[str]]:
    if not text or not text.strip():
        return True, []

    violations: list[str] = []
    low = text.lower()

    for bw in BANNED_WORDS:
        pattern = rf"\b{re.escape(bw)}\b" if bw.isalnum() else re.escape(bw)
        if re.search(pattern, low):
            violations.append(f"banned_word:{bw}")

    allowed_caps = {"OTP", "PIN", "UPI", "SBI", "HDFC", "ICICI", "BSES", "PAN", "SIM", "ATM", "WFH", "VIP", "OLX", "SMS"}
    for tok in re.findall(r"\b[A-Z]{4,}\b", text):
        if tok not in allowed_caps:
            violations.append(f"all_caps:{tok}")

    sentences = [s.strip() for s in re.split(r"(?:\.(?!\d)|[!?।\n])+", text) if s.strip()]
    for sent in sentences:
        words = [w for w in sent.split() if re.search(r"[\w\u0900-\u097F]", w)]
        if len(words) > 15:
            violations.append(f"sentence_too_long:{len(words)}_words")

    return len(violations) == 0, violations


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
            log.debug("Malformed explicit link skipped: %s", raw_url)

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
            log.debug("Malformed bare link skipped: %s", raw_dom)

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
                "brand": target_brand,
                "official": official,
                "is_ai": is_ai,
                "technique": "Fake AI Website Name" if is_ai else "Fake Brand Website Name",
                "explanation": f"The website says {host_clean}, not {official}. It is fake.",
                "score_boost": 94,
            }

    for brand, official_domains in PROTECTED_BRANDS.items():
        brand_skel = _visual_skeleton(brand)
        brand_il = brand_skel.replace("l", "i")
        is_ai = brand in ai_brands
        prefix = "Fake AI Website Name" if is_ai else "Fake Brand Website Name"

        sub_tokens = re.split(r"[.-]", subdomain) if subdomain else []
        label_tokens = core_label.split("-")
        if clean_label == brand or brand in label_tokens or brand in sub_tokens:
            return {
                "brand": brand,
                "official": official_domains[0],
                "is_ai": is_ai,
                "technique": prefix,
                "explanation": f"It uses the name {brand} on a fake address ({host_clean}).",
                "score_boost": 91,
            }

        if skel_label == brand_skel or il_unified == brand_il:
            return {
                "brand": brand,
                "official": official_domains[0],
                "is_ai": is_ai,
                "technique": prefix,
                "explanation": f"The website name is spelled wrong on purpose. It says {core_label}, not {brand}.",
                "score_boost": 96,
            }

        for token in label_tokens + sub_tokens:
            if len(token) >= 4:
                tok_skel = _visual_skeleton(token)
                dist_tok = _levenshtein(token, brand)
                dist_tok_skel = _levenshtein(tok_skel, brand_skel)
                if tok_skel == brand_skel or (len(brand) >= 5 and min(dist_tok, dist_tok_skel) == 1):
                    return {
                        "brand": brand,
                        "official": official_domains[0],
                        "is_ai": is_ai,
                        "technique": prefix,
                        "explanation": f"The website name says {token} instead of {brand}. It is fake.",
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
                    "brand": brand,
                    "official": official_domains[0],
                    "is_ai": is_ai,
                    "technique": prefix,
                    "explanation": f"The website name is spelled wrong. It says {core_label}, not {brand}.",
                    "score_boost": 93,
                }

    if is_punycode or is_mixed:
        return {
            "brand": "trusted site",
            "official": "real website",
            "is_ai": False,
            "technique": "Look-Alike Foreign Letters",
            "explanation": f"The website address {host_clean} uses look-alike letters to trick you.",
            "score_boost": 88,
        }

    return None


def has_explicit_urgency_or_threat(text_low: str) -> bool:
    return any(pat in text_low for pat in EXPLICIT_URGENCY_PATTERNS)


def evaluate_heuristics(text: str, memory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Runs local pre-analysis on text/links and returns plain-language fields + score_breakdown."""
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
        tpl = PLAIN_SIGNAL_TEMPLATES["safe_general"]
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
            "score_breakdown": build_normalized_score_breakdown([], 0),
            "verdict_line": tpl["verdict_en"],
            "verdict_line_hi": tpl["verdict_hi"],
            "detected_category": "Empty Text",
            "dark_pattern": "None",
            "calm_message": tpl["calm_en"],
            "calm_message_hi": tpl["calm_hi"],
            "what_input_is_about": "What this is: An empty message.",
            "what_input_is_about_hi": "यह क्या है: एक खाली मैसेज।",
            "what_it_seems_to_be": "What it pretends to be: Nothing was written here.",
            "what_it_seems_to_be_hi": "यह क्या दिखता है: यहाँ कुछ नहीं लिखा है।",
            "how_it_affects_user": "What could happen to you: Nothing at all.",
            "how_it_affects_user_hi": "आप पर क्या असर होगा: कुछ भी नहीं।",
            "confidence_score_explanation": "Scored 0/100 because input was empty.",
            "auto_calibration_note": "Skipped empty text.",
            "heuristic_indicators": [],
            "recommended_actions": ["No action needed."],
            "recommended_actions_hi": ["कुछ करने की जरूरत नहीं है।"],
            "primary_template_key": "safe_general",
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
    raw_slices: list[dict[str, Any]] = []
    chosen_tpl_key = "safe_general"
    category = "Normal Message"
    dark_pattern = "None"
    custom_about_en: str | None = None
    custom_about_hi: str | None = None
    custom_seems_en: str | None = None
    custom_seems_hi: str | None = None

    has_url, is_url, url, host, scheme = extract_first_url_or_domain(candidate)
    whitelisted = False
    blacklisted = False
    impersonation_info = None
    domain_risk_signal = False

    if has_url and host:
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
            chosen_tpl_key = "known_bad_link"
            category = "Known Scam Link"
            dark_pattern = "Known Scam Website"
            raw_slices.append({"key": "known_scam_link", "points": 80, "severity": "High"})
            indicators.append({
                "type": "Known Scam Link",
                "target": host,
                "explanation": PLAIN_SIGNAL_TEMPLATES["known_bad_link"]["explain_en"],
                "severity": "High",
            })

        if not whitelisted:
            if scheme == "http":
                score += http_w
                domain_risk_signal = True
                if chosen_tpl_key == "safe_general":
                    chosen_tpl_key = "strange_link_ending"
                raw_slices.append({"key": "unsafe_connection", "points": http_w, "severity": "Medium"})
                indicators.append({
                    "type": "Unsafe Web Link",
                    "target": url,
                    "explanation": "This link does not use a safe lock connection.",
                    "severity": "Medium",
                })
            if host.endswith(SUSPICIOUS_TLDS):
                score += tld_w
                domain_risk_signal = True
                if chosen_tpl_key == "safe_general":
                    chosen_tpl_key = "strange_link_ending"
                category = "Strange Web Link"
                raw_slices.append({"key": "strange_link_ending", "points": tld_w, "severity": "High"})
                indicators.append({
                    "type": "Strange Link Ending",
                    "target": host,
                    "explanation": PLAIN_SIGNAL_TEMPLATES["strange_link_ending"]["explain_en"],
                    "severity": "High",
                })
            if is_ip_literal:
                score = max(score, 85)
                domain_risk_signal = True
                chosen_tpl_key = "known_bad_link"
                category = "Number-Only Web Link"
                raw_slices.append({"key": "number_only_link", "points": 85, "severity": "High"})
                indicators.append({
                    "type": "Number-Only Link",
                    "target": host,
                    "explanation": "This link uses raw numbers instead of a real company name.",
                    "severity": "High",
                })
            if is_shortener:
                score += 35
                domain_risk_signal = True
                if chosen_tpl_key == "safe_general":
                    chosen_tpl_key = "strange_link_ending"
                raw_slices.append({"key": "hidden_short_link", "points": 35, "severity": "Medium"})
                indicators.append({
                    "type": "Hidden Short Link",
                    "target": host,
                    "explanation": "This short link hides where it really takes you.",
                    "severity": "Medium",
                })
            if excessive_subdomains:
                score += 30
                domain_risk_signal = True
                raw_slices.append({"key": "confusing_long_link", "points": 30, "severity": "Medium"})
                indicators.append({
                    "type": "Long Confusing Web Address",
                    "target": host,
                    "explanation": "This link stacks many words to hide the real website name.",
                    "severity": "Medium",
                })
            if is_mixed:
                score = max(score, 88)
                domain_risk_signal = True
                chosen_tpl_key = "lookalike_website"
                category = "Look-Alike Website Name"
                raw_slices.append({"key": "mixed_foreign_letters", "points": 88, "severity": "High"})
                indicators.append({
                    "type": "Look-Alike Letters",
                    "target": host,
                    "explanation": "The website name mixes foreign letters to trick your eyes.",
                    "severity": "High",
                })

            impersonation_info = detect_brand_impersonation(host, extra_allowlist=user_allowlist)
            if impersonation_info:
                boost = max(int(impersonation_info["score_boost"]), spoof_w + 40)
                score = max(score, boost)
                domain_risk_signal = True
                chosen_tpl_key = "lookalike_website"
                b_name = impersonation_info["brand"]
                category = f"Fake {b_name.title()} Link"
                dark_pattern = "Fake Website Name"
                custom_about_en = f"What this is: The website says {host}, not {impersonation_info['official']}."
                custom_about_hi = f"यह क्या है: वेबसाइट का नाम {host} लिखा है, {impersonation_info['official']} नहीं।"
                custom_seems_en = f"What it pretends to be: The real {b_name.title()} website."
                custom_seems_hi = f"यह क्या दिखता है: असली {b_name.title()} की वेबसाइट।"
                raw_slices.append({"key": "fake_website_name", "points": boost, "severity": "High"})
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
                chosen_tpl_key = "lookalike_website"
                category = "Tricky Mixed Letters"
                raw_slices.append({"key": "mixed_foreign_letters", "points": 65, "severity": "Medium"})
                indicators.append({
                    "type": "Mixed Alphabet Letters",
                    "target": word[:40],
                    "explanation": "This word mixes different alphabets to trick safety checks.",
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
            score = 0
            chosen_tpl_key = "safe_bank_otp"
            category = "Real Bank OTP"
            dark_pattern = "None"
            indicators = []
            raw_slices = []

        elif (
            ("paid ₹" in t_low or "paid rs" in t_low or "debited" in t_low)
            and ("upi ref" in t_low or "via upi" in t_low or "thank you" in t_low)
            and not any(k in t_low for k in ["request", "collect", "click", "call", "enter your upi pin"])
        ):
            is_verified_safe = True
            score = 0
            chosen_tpl_key = "safe_upi_receipt"
            category = "Real UPI Receipt"
            dark_pattern = "None"
            indicators = []
            raw_slices = []

        elif whitelisted and is_url:
            is_verified_safe = True
            score = 0
            chosen_tpl_key = "safe_general"
            category = "Trusted Website"
            dark_pattern = "None"
            indicators = []
            raw_slices = []

    if not is_verified_safe:
        asks_secrets = any(k in t_low for k in ["password", "otp", "upi pin", "mpin", "cvv", "seed phrase", "api key", "secret key"])
        direct_reply_demand = any(
            k in t_low
            for k in ["reply with", "reply to this", "send your", "share your", "provide your", "mail your", "whatsapp your"]
        )
        urgent_threat = has_explicit_urgency_or_threat(t_low)

        if asks_secrets and (direct_reply_demand or urgent_threat or domain_risk_signal):
            score = max(score, 96)
            chosen_tpl_key = "asks_for_otp"
            category = "Stealing Your OTP or Password"
            dark_pattern = "Rushing You for Secrets"
            raw_slices.append({"key": "asks_for_otp", "points": 70 if urgent_threat else 96, "severity": "High"})
            if urgent_threat:
                raw_slices.append({"key": "vague_click_bait", "points": urgency_w + 1, "severity": "Medium"})
            indicators.append({
                "type": "Asks for OTP or Password",
                "target": "OTP / Password Request",
                "explanation": PLAIN_SIGNAL_TEMPLATES["asks_for_otp"]["explain_en"],
                "severity": "High",
            })

        if ("request" in t_low or "collect" in t_low or "pay ₹" in t_low or "pay rs" in t_low) and any(
            k in t_low for k in ["refund", "cashback", "receive", "upi pin", "enter pin", "olx"]
        ):
            score = max(score, collect_w + 46)
            chosen_tpl_key = "fake_refund_request"
            category = "Fake UPI Refund Trick"
            dark_pattern = "Pay Button Dressed as Refund"
            raw_slices.append({"key": "fake_refund_trap", "points": collect_w + 46, "severity": "High"})
            indicators.append({
                "type": "Fake UPI Refund Request",
                "target": "Pay Button vs Refund Note",
                "explanation": PLAIN_SIGNAL_TEMPLATES["fake_refund_request"]["explain_en"],
                "severity": "High",
            })

        if ("electricity" in t_low or "power" in t_low) and ("disconnect" in t_low or "tonight" in t_low or "9:30" in t_low):
            score = max(score, urgency_w + 68)
            chosen_tpl_key = "electricity_cutoff_scam"
            category = "Fake Electricity Cutoff Scam"
            dark_pattern = "Night Cutoff Scare"
            raw_slices.append({"key": "power_cutoff_scare", "points": 68, "severity": "High"})
            raw_slices.append({"key": "vague_click_bait", "points": urgency_w, "severity": "Medium"})
            indicators.append({
                "type": "Fake Power Cutoff Threat",
                "target": "Tonight Electricity Cutoff",
                "explanation": PLAIN_SIGNAL_TEMPLATES["electricity_cutoff_scam"]["explain_en"],
                "severity": "High",
            })

        if any(k in t_low for k in ["daily", "wfh", "part-time", "work from home"]) and any(
            k in t_low for k in ["rating", "youtube", "trial bonus", "₹3,000", "₹5,000", "instant bonus", "telegram"]
        ):
            score = max(score, 90)
            chosen_tpl_key = "fake_job_offer"
            category = "Fake Work-From-Home Job"
            dark_pattern = "Small Bonus Trap"
            raw_slices.append({"key": "fake_job_bonus", "points": 90, "severity": "High"})
            indicators.append({
                "type": "Fake Daily Job Payout",
                "target": "Daily Payout Promise",
                "explanation": PLAIN_SIGNAL_TEMPLATES["fake_job_offer"]["explain_en"],
                "severity": "High",
            })

        if any(k in t_low for k in ["met with accident", "hospital", "phone fell", "broken screen", "friend's number", "police station"]) and any(
            k in t_low for k in ["send money", "urgently", "upi", "rs", "₹", "transfer"]
        ):
            score = max(score, 88)
            chosen_tpl_key = "family_emergency_scam"
            category = "Fake Family Emergency"
            dark_pattern = "Panic Money Request"
            raw_slices.append({"key": "family_trouble_scare", "points": 88, "severity": "High"})
            indicators.append({
                "type": "Fake Family Emergency",
                "target": "Urgent Hospital Money Request",
                "explanation": PLAIN_SIGNAL_TEMPLATES["family_emergency_scam"]["explain_en"],
                "severity": "High",
            })

        if "*401*" in t_low:
            score = 99
            chosen_tpl_key = "call_forwarding_trap"
            category = "*401* Call Forwarding Trick"
            dark_pattern = "Phone Code Trick"
            raw_slices.append({"key": "call_forward_code", "points": 99, "severity": "High"})
            indicators.append({
                "type": "*401* Call Forwarding Code",
                "target": "*401*",
                "explanation": PLAIN_SIGNAL_TEMPLATES["call_forwarding_trap"]["explain_en"],
                "severity": "High",
            })

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
            chosen_tpl_key = "vague_attention_bait"
            category = "Vague Click Trap"
            dark_pattern = "Missing Details Trick"
            raw_slices.append({"key": "vague_click_bait", "points": vague_score, "severity": "High" if vague_score >= 66 else "Medium"})
            indicators.append({
                "type": "Vague Attention Bait",
                "target": scrub_pii(candidate)[:50],
                "explanation": PLAIN_SIGNAL_TEMPLATES["vague_attention_bait"]["explain_en"],
                "severity": "High" if score >= 66 else "Medium",
            })

    final_score = min(100, int(score))
    level_str = "High" if final_score >= 66 else "Medium" if final_score >= 31 else "Low"
    inconclusive = (final_score == 0 and not is_verified_safe and len(candidate) > 15)

    tpl = PLAIN_SIGNAL_TEMPLATES.get(chosen_tpl_key, PLAIN_SIGNAL_TEMPLATES["safe_general"])
    verdict_en = default_verdict_line(level_str, "en")
    verdict_hi = default_verdict_line(level_str, "hi")
    breakdown = build_normalized_score_breakdown(raw_slices, final_score)

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
        "score_breakdown": breakdown,
        "verdict_line": verdict_en,
        "verdict_line_hi": verdict_hi,
        "detected_category": category,
        "dark_pattern": dark_pattern,
        "calm_message": tpl["calm_en"],
        "calm_message_hi": tpl["calm_hi"],
        "what_input_is_about": custom_about_en or tpl["about_en"],
        "what_input_is_about_hi": custom_about_hi or tpl["about_hi"],
        "what_it_seems_to_be": custom_seems_en or tpl["seems_en"],
        "what_it_seems_to_be_hi": custom_seems_hi or tpl["seems_hi"],
        "how_it_affects_user": tpl["affects_en"],
        "how_it_affects_user_hi": tpl["affects_hi"],
        "confidence_score_explanation": (
            f"Score {final_score}/100 ({level_str}) from {len(indicators)} check(s)."
        ),
        "auto_calibration_note": "Local check complete.",
        "heuristic_indicators": indicators,
        "recommended_actions": list(tpl["actions_en"]),
        "recommended_actions_hi": list(tpl["actions_hi"]),
        "primary_template_key": chosen_tpl_key,
    }
