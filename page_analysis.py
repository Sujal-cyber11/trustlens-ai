"""Deterministic webpage malicious-behaviour and dark-pattern analyzer for TrustLens AI.

Fixes included (BUG 2 & BUG 3):
1. The word 'password', 'sign in', or 'login', or the presence of a password field, is NOT a
   risk indicator by itself. Credential-demand scoring applies ONLY when combined with at least
   one real signal: cross-domain or HTTP form action, homoglyph/brand-lookalike domain,
   suspicious TLD, IP-literal host, blacklisted domain, or explicit urgency/threat wording.
2. An unknown domain with zero signals and benign text scores Low (0-20). Zero signals plus
   weak text evidence (e.g. 'Enter your password' on an unknown domain) reaches at most Medium
   (max 45) and sets needs_ai=True so Gemini confirms before any High alert.
3. High (66+) requires at least one hard signal or two independent medium signals.
4. Indicators, calm_down_message, how_it_affects_user, and recommended_actions ONLY describe
   signals actually detected (never mentioning countdown timers, checkboxes, Win+R, or support
   numbers when those signals were not detected).
5. Popular allow-listed domains and user_allowlist domains are capped at 20 unless a hard signal fires.
6. Blacklist hits set a floor of 80 (not 100) and describe only the blacklist match and detected signals.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from heuristics import (
    BENIGN_ACADEMIC_GOV_SUFFIXES,
    PROTECTED_BRANDS,
    SUSPICIOUS_TLDS,
    WHITELIST_DOMAINS,
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


SIGNAL_HUMAN_NAMES: dict[str, tuple[str, str]] = {
    "cross_domain_password_form": ("Cross-Domain Credential Form", "malicious"),
    "insecure_http_form": ("Insecure HTTP Credential Form", "malicious"),
    "password_or_otp_input": ("Password / OTP Input Field", "malicious"),
    "hidden_or_cross_iframe": ("Hidden Cross-Origin Iframe", "malicious"),
    "clickjack_overlay": ("Transparent Overlay Over Button/Link", "malicious"),
    "deceptive_anchor_mismatch": ("Anchor Text vs. Href Domain Mismatch", "malicious"),
    "suspicious_inline_script": ("Obfuscated Inline Script Calls", "malicious"),
    "document_write_script": ("Dynamic Script Injection via document.write", "malicious"),
    "auto_download_trigger": ("Unprompted Automatic Download Trigger", "malicious"),
    "clipboard_hijack_hook": ("Clipboard Write Override Hook", "malicious"),
    "contextmenu_or_unload_trap": ("Right-Click Block or Unload Trap", "malicious"),
    "unprompted_permission_request": ("Permission Request Without User Gesture", "malicious"),
    "fake_system_dialog": ("Fake System / Virus Alert Dialog", "malicious"),
    "clickfix_command_trap": ("ClickFix Command Execution Prompt", "malicious"),
    "fake_support_urgency": ("Fake Tech-Support Helpline With Urgency", "malicious"),
    "resetting_countdown_timer": ("Countdown Timer Resetting on Reload", "dark_pattern"),
    "fake_urgency_scarcity": ("Artificial Scarcity / Urgency Wording", "dark_pattern"),
    "prechecked_addon_box": ("Pre-Checked Add-On / Continuity Checkbox", "dark_pattern"),
    "forced_continuity_wording": ("Forced Continuity Auto-Renewal Wording", "dark_pattern"),
    "hidden_drip_pricing": ("Late-Stage Drip Pricing Disclosure", "dark_pattern"),
    "confirm_shaming": ("Confirm-Shaming Decline Option", "dark_pattern"),
    "asymmetric_choice_ui": ("Asymmetric Accept vs. Reject Choice Design", "dark_pattern"),
    "disguised_ad_button": ("Disguised Ad Styled as Control Button", "dark_pattern"),
    "misdirection_close_button": ("Misdirection Close Button Linking Externally", "dark_pattern"),
    "nagging_modal": ("Repeated / Unclosable Nagging Modal", "dark_pattern"),
    "sneak_into_basket": ("Unsolicited Sneak-Into-Basket Item", "dark_pattern"),
}


def strip_url_query_and_fragment(raw_url: str) -> str:
    """Strips query strings and fragments from URLs to enforce privacy."""
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
    """Deterministically scores a webpage's structural signals, domain, title, and text sample."""
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
    dark_pattern_names: list[str] = []

    # Check domain-level real risk factors
    is_ip_literal = False
    try:
        ip_obj = ipaddress.ip_address(host)
        is_ip_literal = ip_obj.is_global
    except ValueError:
        is_ip_literal = False

    is_suspicious_tld = (not is_allowlisted) and host.endswith(SUSPICIOUS_TLDS)
    impersonation_info = detect_brand_impersonation(host, extra_allowlist=user_allowlist) if not is_allowlisted else None
    has_urgency_threat = has_explicit_urgency_or_threat(combined_text_low)

    # Check if page title claims a protected brand on an unrelated domain
    claimed_brand_in_title = None
    if not is_allowlisted and clean_title:
        t_low = clean_title.lower()
        for brand, official_doms in PROTECTED_BRANDS.items():
            if len(brand) >= 4 and brand in t_low:
                claimed_brand_in_title = (brand.upper(), official_doms[0])
                break

    if blacklisted:
        malicious_score = max(malicious_score, 80)
        hard_signals_count += 1
        hard_floor = max(hard_floor, 80)
        indicators.append({
            "type": "Blacklisted Threat Domain",
            "target": host,
            "explanation": f"Domain '{host}' is listed on the local threat blacklist (floor score 80).",
            "severity": "High",
        })

    if impersonation_info:
        boost = int(impersonation_info.get("score_boost", 92))
        malicious_score = max(malicious_score, boost)
        hard_signals_count += 1
        hard_floor = max(hard_floor, boost)
        indicators.append({
            "type": impersonation_info["technique"],
            "target": host,
            "explanation": impersonation_info["explanation"],
            "severity": "High",
        })

    if not is_allowlisted:
        if is_suspicious_tld:
            malicious_score += int(weights.get("unverified_tld_penalty", 40))
            medium_signals_count += 1
            indicators.append({
                "type": "Suspicious TLD",
                "target": host,
                "explanation": f"Domain '{host}' uses a high-risk top-level domain.",
                "severity": "Medium",
            })
        if is_ip_literal:
            malicious_score = max(malicious_score, 75)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 75)
            indicators.append({
                "type": "IP-Literal Host",
                "target": host,
                "explanation": "Webpage is hosted on a raw IP address rather than a registered domain name.",
                "severity": "High",
            })
        subdomain, _, _ = split_domain_parts(host)
        if len([p for p in subdomain.split(".") if p]) >= 3:
            malicious_score += 25
            medium_signals_count += 1
            indicators.append({
                "type": "Excessive Subdomains",
                "target": host,
                "explanation": "Hostname chains 3 or more subdomains.",
                "severity": "Medium",
            })
        if has_mixed_scripts(host) or "xn--" in host:
            malicious_score = max(malicious_score, 85)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 85)
            indicators.append({
                "type": "IDN / Mixed-Script Hostname",
                "target": host,
                "explanation": "Hostname mixes character scripts or uses punycode ('xn--').",
                "severity": "High",
            })

    # Inspect structural signals sent by content.js
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
        human_label, group = SIGNAL_HUMAN_NAMES.get(sid, (sig.id.replace("_", " ").title(), "malicious"))
        ev = sig.evidence or f"Detected {sig.count} instance(s)"

        if sid == "cross_domain_password_form":
            pen = int(weights.get("cross_domain_form_penalty", 75))
            malicious_score = max(malicious_score + 35, pen + 15)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 90)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Password/credential form submits to a different registered domain.",
                "severity": "High",
            })
        elif sid == "insecure_http_form":
            pen = int(weights.get("insecure_form_penalty", 45))
            malicious_score = max(malicious_score + pen, 72)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 72)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Sensitive credential form submits over unencrypted HTTP.",
                "severity": "High",
            })
        elif sid == "password_or_otp_input":
            # BUG 2 Rule 1: Presence of a password/OTP input is NOT a risk indicator by itself!
            # Only score it when combined with a real domain/form/urgency signal.
            if has_domain_or_form_threat and not is_allowlisted:
                malicious_score = max(malicious_score + 20, 75 if (impersonation_info or blacklisted or claimed_brand_in_title) else 50)
                if impersonation_info or blacklisted or claimed_brand_in_title:
                    hard_signals_count += 1
                    hard_floor = max(hard_floor, 92)
                else:
                    medium_signals_count += 1
                indicators.append({
                    "type": "Credential Input Combined With Risk Signal",
                    "target": ev,
                    "explanation": "Password or OTP input field is present alongside a domain, form, or urgency risk factor.",
                    "severity": "High" if hard_floor >= 66 else "Medium",
                })
        elif sid == "hidden_or_cross_iframe":
            malicious_score += 25
            medium_signals_count += 1
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Page embeds a hidden cross-origin iframe.",
                "severity": "Medium",
            })
        elif sid == "clickjack_overlay":
            pen = int(weights.get("clickjack_overlay_penalty", 55))
            malicious_score = max(malicious_score + pen, 55)
            medium_signals_count += 1
            if "hidden_or_cross_iframe" in signal_ids or not is_allowlisted:
                hard_floor = max(hard_floor, 55)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Transparent overlay is positioned over interactive buttons or links.",
                "severity": "High" if malicious_score >= 66 else "Medium",
            })
        elif sid == "deceptive_anchor_mismatch":
            pen = int(weights.get("deceptive_link_penalty", 45))
            malicious_score = max(malicious_score + pen, 68)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 68)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Anchor visible text displays a domain name that does not match its href destination.",
                "severity": "High",
            })
        elif sid in ("suspicious_inline_script", "document_write_script"):
            pen = int(weights.get("suspicious_script_penalty", 35))
            malicious_score += pen
            medium_signals_count += 1
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Inline scripts use dynamic code evaluation or script injection.",
                "severity": "Medium",
            })
        elif sid == "auto_download_trigger":
            malicious_score = max(malicious_score + 55, 80)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 80)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Page attempted an automatic download without a user gesture.",
                "severity": "High",
            })
        elif sid in ("clipboard_hijack_hook", "contextmenu_or_unload_trap"):
            malicious_score += 30
            dark_pattern_score += 25
            medium_signals_count += 1
            dark_pattern_names.append(human_label)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Page hooks clipboard copy events, blocks right-click, or traps tab closing.",
                "severity": "Medium",
            })
        elif sid == "unprompted_permission_request":
            pen = int(weights.get("unprompted_permission_penalty", 40))
            malicious_score += pen
            medium_signals_count += 1
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Page requested browser permissions without a user gesture.",
                "severity": "Medium",
            })
        elif sid == "clickfix_command_trap":
            pen = int(weights.get("clickfix_penalty", 95))
            malicious_score = max(malicious_score, pen)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 95)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "ClickFix pattern instructing user to press Win+R and paste a command.",
                "severity": "High",
            })
        elif sid in ("fake_system_dialog", "fake_support_urgency"):
            pen = int(weights.get("fake_system_ui_penalty", 85))
            malicious_score = max(malicious_score, pen)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 85)
            indicators.append({
                "type": human_label,
                "target": ev,
                "explanation": "Displays a fake virus/system dialog or urgent tech-support phone number.",
                "severity": "High",
            })
        elif group == "dark_pattern":
            dark_pattern_names.append(human_label)
            medium_signals_count += 1
            if sid == "resetting_countdown_timer":
                dark_pattern_score += int(weights.get("dark_pattern_timer_penalty", 35)) + 10
            elif sid == "fake_urgency_scarcity":
                dark_pattern_score += int(weights.get("dark_pattern_timer_penalty", 35))
            elif sid in ("prechecked_addon_box", "forced_continuity_wording", "hidden_drip_pricing"):
                dark_pattern_score += int(weights.get("dark_pattern_prechecked_penalty", 25)) + 10
            elif sid == "confirm_shaming":
                dark_pattern_score += int(weights.get("dark_pattern_shaming_penalty", 25)) + 10
            elif sid in ("asymmetric_choice_ui", "disguised_ad_button", "misdirection_close_button", "nagging_modal"):
                dark_pattern_score += int(weights.get("dark_pattern_asymmetric_penalty", 25)) + 10
            elif sid == "sneak_into_basket":
                dark_pattern_score += int(weights.get("dark_pattern_sneak_penalty", 35)) + 10
            else:
                dark_pattern_score += 25

            indicators.append({
                "type": f"Dark Pattern: {human_label}",
                "target": ev,
                "explanation": f"Detected {human_label} on page.",
                "severity": "High" if dark_pattern_score >= 66 else "Medium",
            })

    if claimed_brand_in_title and not is_allowlisted:
        b_name, b_official = claimed_brand_in_title
        if "password_or_otp_input" in signal_ids or has_cross_domain_or_http_form:
            malicious_score = max(malicious_score, 92)
            hard_signals_count += 1
            hard_floor = max(hard_floor, 92)
            indicators.append({
                "type": "Brand Title Claim + Credential Form Mismatch",
                "target": f"Title claims '{b_name}' on '{host}'",
                "explanation": f"Page title claims to be {b_name} ({b_official}) alongside credential inputs on an unverified domain.",
                "severity": "High",
            })

    # BUG 2 Rule 1 & Rule 2: Handle zero-signal pages & weak text evidence
    has_weak_login_text = any(
        w in combined_text_low for w in ("enter your password", "forgot password", "verify your account")
    )
    is_routine_student_or_org_portal = (
        is_academic_or_gov
        or any(w in combined_text_low for w in ("student login", "roll number", "faculty login", "staff login", "employee portal"))
    )

    if len(req.signals) == 0 and hard_signals_count == 0 and medium_signals_count == 0:
        if is_allowlisted or is_routine_student_or_org_portal:
            # e.g. github.com/login or portal.mycollege.ac.in/login with 'Student Login, enter roll number and password' -> Low (0-20)
            malicious_score = 0
            dark_pattern_score = 0
            needs_ai = False
        elif has_urgency_threat:
            # Zero DOM signals, but explicit threat text on an unknown domain -> capped at Medium (45) and requires AI confirmation
            malicious_score = 45
            medium_signals_count = 1
            needs_ai = True
            indicators.append({
                "type": "Urgent Account Threat Text on Unverified Domain",
                "target": clean_sample[:80],
                "explanation": "Page text contains urgent account restriction/verification wording on an unverified domain.",
                "severity": "Medium",
            })
        elif has_weak_login_text:
            # e.g. fake-bank.example/login with 'Enter your password', zero signals -> Medium at most (max 45), needs_ai=True
            malicious_score = 35
            needs_ai = True
            indicators.append({
                "type": "Unverified Domain Login Prompt (Pending AI Confirmation)",
                "target": f"{host} — '{clean_sample[:60]}'",
                "explanation": "Unverified domain prompts for a password with zero structural signals; capped at Medium pending AI review.",
                "severity": "Medium",
            })
        else:
            # Unknown domain with zero signals and benign text -> Low (0-20)
            malicious_score = 0
            dark_pattern_score = 0
            needs_ai = False
    else:
        needs_ai = False

    malicious_score = min(100, malicious_score)
    dark_pattern_score = min(100, dark_pattern_score)

    combined = max(malicious_score, dark_pattern_score)
    if malicious_score >= 25 and dark_pattern_score >= 25:
        combined = min(100, combined + int(min(malicious_score, dark_pattern_score) * 0.25))
    combined = max(combined, hard_floor)

    # BUG 2 Rule 5: Popular allow-listed domains (and user_allowlist) are capped at 20 unless a hard signal fires
    if is_allowlisted and hard_signals_count == 0:
        combined = min(combined, 20)
        malicious_score = min(malicious_score, 20)
        dark_pattern_score = min(dark_pattern_score, 20)

    # BUG 2 Rule 3: High (66+) requires at least one hard signal OR at least two independent medium signals
    if combined >= 66 and hard_signals_count == 0 and medium_signals_count < 2:
        combined = 60
        malicious_score = min(malicious_score, 60)
        dark_pattern_score = min(dark_pattern_score, 60)

    # BUG 2 Rule 2: Zero signals plus weak text evidence only may reach at most Medium (max 45)
    if len(req.signals) == 0 and hard_signals_count == 0 and medium_signals_count <= 1:
        combined = min(combined, 45)
        malicious_score = min(malicious_score, 45)

    level = "High" if combined >= 66 else "Medium" if combined >= 31 else "Low"
    is_suspicious = combined >= 31

    if not needs_ai and not is_allowlisted:
        needs_ai = (25 <= combined <= 75) or (hard_signals_count > 0)

    # BUG 2 Rule 4 & BUG 3 Rule 5: Explanations and recommended actions must ONLY describe actually detected signals!
    detected_types = [i["type"] for i in indicators]
    detected_summary = ", ".join(detected_types[:4]) if detected_types else "None"
    dp_summary = ", ".join(dict.fromkeys(dark_pattern_names)) if dark_pattern_names else "None"

    about_en = f"Webpage '{clean_url}' (host '{host}') analyzed with {len(req.signals)} structural signal(s)."
    about_hi = f"वेबपेज '{clean_url}' (होस्ट '{host}') का {len(req.signals)} संरचनात्मक संकेतों के साथ विश्लेषण किया गया।"

    if not is_suspicious:
        cat = "Verified Clean Webpage"
        calm_en = f"✅ '{host}' shows no suspicious phishing or dark-pattern signals."
        calm_hi = f"✅ '{host}' पर कोई संदिग्ध फ़िशिंग या डार्क पैटर्न संकेत नहीं मिला।"
        seems_en = f"Standard webpage ('{clean_title or host}') with no high-risk indicators."
        seems_hi = f"सामान्य वेबपेज ('{clean_title or host}') जिस पर कोई जोखिम संकेत नहीं है।"
        affects_en = "No malicious form actions, overlays, or manipulative dark patterns were detected."
        affects_hi = "कोई दुर्भावनापूर्ण फॉर्म या डार्क पैटर्न नहीं मिला।"
        actions_en = ["No risky signals detected on this page."]
        actions_hi = ["इस पेज पर कोई जोखिम भरा संकेत नहीं मिला।"]
    else:
        if dark_pattern_score > malicious_score and dark_pattern_names:
            cat = f"Dark Patterns Detected ({dp_summary[:60]})"
        elif impersonation_info:
            cat = f"{impersonation_info['technique']} ({impersonation_info['brand']})"
        elif blacklisted:
            cat = f"Blacklisted Domain ({host})"
        else:
            cat = f"Suspicious Webpage ({detected_types[0] if detected_types else host})"

        calm_en = f"⚠️ Caution on '{host}': Detected {detected_summary}."
        calm_hi = f"⚠️ '{host}' पर सावधानी बरतें: {detected_summary} का पता चला।"
        seems_en = f"Page '{clean_title or host}' triggered the following specific check(s): {detected_summary}."
        seems_hi = f"पेज '{clean_title or host}' पर निम्नलिखित संकेत मिले: {detected_summary}।"
        affects_en = (
            "Based on the detected indicator(s) ("
            + detected_summary
            + "), interacting with untrusted forms or prompts on this page may expose your data or choices."
        )
        affects_hi = f"मिले संकेतों ({detected_summary}) के आधार पर, इस पेज पर संवेदनशील जानकारी साझा करने से जोखिम हो सकता है।"

        actions_en = []
        actions_hi = []
        for i in indicators[:3]:
            actions_en.append(f"Review detected issue — {i['type']}: {i['explanation']}")
            actions_hi.append(f"पहचाने गए संकेत की समीक्षा करें — {i['type']}: {i['explanation']}")
        if not actions_en:
            actions_en.append(f"Verify the identity of '{host}' before submitting sensitive information.")
            actions_hi.append(f"संवेदनशील जानकारी देने से पहले '{host}' की प्रामाणिकता सत्यापित करें।")

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
        "hard_floor": hard_floor,
        "hard_signal_fired": hard_signals_count > 0,
        "needs_ai": needs_ai,
        "pass1_naive_score": malicious_score,
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
            f"Combined Risk {combined}/100 (Malicious: {malicious_score}/100, "
            f"Dark Patterns: {dark_pattern_score}/100, Hard Signals: {hard_signals_count}, "
            f"Medium Signals: {medium_signals_count})."
        ),
        "heuristic_indicators": indicators,
        "recommended_actions": actions_en,
        "recommended_actions_hi": actions_hi,
    }
