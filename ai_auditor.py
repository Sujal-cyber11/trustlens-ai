"""Gemini-backed auditing, startup memory migration, and bounded feedback calibration for TrustLens AI.

Fixes included (BUG 3):
- Startup migration cleans existing agent_memory.json: drops non-domain blacklist entries
  (e.g. alert titles, sentences), drops 127.0.0.1 / localhost / private IPs, clamps every weight
  to [base - 10, base + 10], and deduplicates/sanitizes lessons (rejecting shell commands, URL lists,
  and TrustLens internal alert text, capped at 20 lessons of max 120 chars).
- Blacklist entries only come from the shipped seed list or explicit user 'confirm_scam' feedback
  on a validated registered domain. System-only verdicts never mutate weights or blacklists.
- Weight updates are bounded and idempotent: at most one adjustment per (domain, feedback_type),
  step of +/-1, clamped to [base - 10, base + 10].
- User 'false_positive' ('This is safe') removes the domain from blacklisted_domains and adds it
  to user_allowlist, preventing re-addition and overriding heuristics unless a hard signal fires.
"""
from __future__ import annotations

import copy
import io
import json
import logging
import os
import random
import re
import tempfile
import threading
import time
from typing import Any, Callable

from google import genai
from google.genai import types
from PIL import Image
from pydantic import BaseModel, ValidationError, field_validator

from heuristics import (
    WHITELIST_DOMAINS,
    domain_matches,
    is_local_or_private_host,
    is_trustlens_internal_text,
    normalize_valid_public_domain,
    scrub_pii,
)

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

log = logging.getLogger("trustlens.ai")

MEMORY_FILE = os.environ.get("TRUSTLENS_MEMORY_FILE", "agent_memory.json")
MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

MAX_PROMPT_CHARS = 16_000
MAX_ATTEMPTS = 2
ATTEMPT_TIMEOUT_MS = 14_000
AI_DEADLINE_S = 22
MAX_LESSONS = 20
MAX_LESSON_CHARS = 120
MAX_BLACKLIST = 5000

BASE_WEIGHTS: dict[str, int] = {
    "urgency_penalty": 25,
    "unverified_tld_penalty": 40,
    "missing_https_penalty": 20,
    "brand_spoof_penalty": 45,
    "collect_trap_penalty": 50,
    "vague_bait_penalty": 55,
    "cross_domain_form_penalty": 75,
    "insecure_form_penalty": 45,
    "clickjack_overlay_penalty": 55,
    "deceptive_link_penalty": 45,
    "suspicious_script_penalty": 35,
    "unprompted_permission_penalty": 40,
    "fake_system_ui_penalty": 85,
    "clickfix_penalty": 95,
    "dark_pattern_timer_penalty": 35,
    "dark_pattern_prechecked_penalty": 25,
    "dark_pattern_shaming_penalty": 25,
    "dark_pattern_asymmetric_penalty": 25,
    "dark_pattern_sneak_penalty": 35,
}

SEED_BLACKLIST: list[str] = [
    "sbi-kyc-update.xyz",
    "bses-bill-desk.xyz",
    "gmap-task-bonus.top",
    "indiapost-parcel-verify.xyz",
    "hdfc-reward-points-redeem.click",
    "chatgpi-pro.com",
]

DEFAULT_MEMORY: dict[str, Any] = {
    "blacklisted_domains": list(SEED_BLACKLIST),
    "user_allowlist": [],
    "feedback_history": [],
    "weights": dict(BASE_WEIGHTS),
    "few_shot_lessons": [
        "Visual homoglyphs like arnazon.com or paytrn.in are High Risk brand impersonations.",
        "Vague attention-bait messages with zero verifiable context are at least Medium Risk.",
        "Pages asking to press Win+R and paste a command (ClickFix) are High Risk malware traps.",
        "Password forms submitting to a different registered domain are High Risk credential harvesters.",
    ],
    "metrics": {
        "tp": 6,
        "tn": 4,
        "fp": 0,
        "fn": 0,
        "auto_fp_corrected": 2,
        "auto_fn_caught": 3,
        "browser_pages_scanned": 0,
        "dark_patterns_found": 0,
    },
    "auto_audit_log": [],
}

_memory_lock = threading.RLock()


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def sanitize_lesson_note(raw_note: Any) -> str | None:
    """Validates and normalizes a user feedback lesson (max 120 chars), rejecting shell commands, URL lists, and alert titles."""
    if not raw_note or not isinstance(raw_note, str):
        return None
    normalized = " ".join(raw_note.strip().split())
    if len(normalized) < 6:
        return None
    if is_trustlens_internal_text(normalized):
        return None
    low = normalized.lower()
    if any(
        bad in low
        for bad in (
            "curl ", "curl.exe", "wget ", "invoke-webrequest", "powershell", "cmd.exe",
            " -h ", " -d ", "--header", "x-trustlens-token", "http://127.0.0.1", "http://localhost",
        )
    ):
        return None
    if len(re.findall(r"https?://", low)) >= 2:
        return None
    return normalized[:MAX_LESSON_CHARS]


def _normalize_memory(raw: Any) -> dict[str, Any]:
    """Cleans and migrates memory: drops invalid/private domains, clamps weights to [base-10, base+10], and dedupes lessons."""
    mem = copy.deepcopy(DEFAULT_MEMORY)
    if not isinstance(raw, dict):
        return mem

    # 1. Clean user_allowlist first (valid public domains only, deduped)
    raw_allow = raw.get("user_allowlist")
    clean_allow: list[str] = []
    if isinstance(raw_allow, list):
        for item in raw_allow:
            dom = normalize_valid_public_domain(item)
            if dom and dom not in clean_allow:
                clean_allow.append(dom)
    mem["user_allowlist"] = clean_allow[-MAX_BLACKLIST:]

    # 2. Clean blacklisted_domains (must be valid public registered domains, not in WHITELIST or user_allowlist, deduped)
    raw_domains = raw.get("blacklisted_domains")
    clean_blacklist: list[str] = []
    if isinstance(raw_domains, list):
        for item in raw_domains:
            dom = normalize_valid_public_domain(item)
            if (
                dom
                and not domain_matches(dom, WHITELIST_DOMAINS)
                and not domain_matches(dom, clean_allow)
                and dom not in clean_blacklist
            ):
                clean_blacklist.append(dom)
    mem["blacklisted_domains"] = clean_blacklist[-MAX_BLACKLIST:]

    # 3. Clamp every weight to [base - 10, base + 10]
    raw_weights = raw.get("weights")
    if isinstance(raw_weights, dict):
        for key, base_val in BASE_WEIGHTS.items():
            val = raw_weights.get(key, base_val)
            if _is_number(val):
                clamped = max(base_val - 10, min(base_val + 10, int(round(val))))
                mem["weights"][key] = clamped

    # 4. Sanitize, deduplicate, and cap few_shot_lessons at 20 (max 120 chars each)
    raw_lessons = raw.get("few_shot_lessons")
    clean_lessons: list[str] = []
    if isinstance(raw_lessons, list):
        for item in raw_lessons:
            sanitized = sanitize_lesson_note(item)
            if sanitized and sanitized not in clean_lessons:
                clean_lessons.append(sanitized)
    mem["few_shot_lessons"] = clean_lessons[-MAX_LESSONS:]

    # 5. Feedback history (tracks 'domain|feedback_type' keys for idempotency)
    raw_fb = raw.get("feedback_history")
    if isinstance(raw_fb, list):
        dedup_fb = list(dict.fromkeys(str(x).strip().lower() for x in raw_fb if isinstance(x, str) and x.strip()))
        mem["feedback_history"] = dedup_fb[-2000:]

    # 6. Metrics & audit log
    metrics = raw.get("metrics")
    if isinstance(metrics, dict):
        for k in ("tp", "tn", "fp", "fn", "auto_fp_corrected", "auto_fn_caught", "browser_pages_scanned", "dark_patterns_found"):
            if isinstance(metrics.get(k), int):
                mem["metrics"][k] = max(0, metrics[k])

    audit_log = raw.get("auto_audit_log")
    if isinstance(audit_log, list):
        mem["auto_audit_log"] = [str(x)[:200] for x in audit_log if isinstance(x, str)][-30:]

    return mem


def _atomic_write(data: dict[str, Any]) -> None:
    directory = os.path.dirname(os.path.abspath(MEMORY_FILE)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".memory_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, MEMORY_FILE)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError as e:
            log.debug("Failed to unlink temp file %s: %s", tmp_path, e)
        raise


def save_memory(data: dict[str, Any]) -> bool:
    with _memory_lock:
        try:
            _atomic_write(_normalize_memory(data))
            return True
        except (OSError, TypeError, ValueError) as e:
            log.error("Could not save %s: %s", MEMORY_FILE, e)
            return False


def load_memory() -> dict[str, Any]:
    with _memory_lock:
        try:
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
            log.info("Initializing default memory (%s): %s", MEMORY_FILE, e)
            mem = copy.deepcopy(DEFAULT_MEMORY)
            save_memory(mem)
            return mem
        return _normalize_memory(raw)


def migrate_and_clean_memory_on_startup() -> dict[str, Any]:
    """Startup migration that cleans any poisoned blacklist entries, weights, or lessons on disk."""
    with _memory_lock:
        cleaned = load_memory()
        save_memory(cleaned)
        return cleaned


def mutate_memory(fn: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    with _memory_lock:
        mem = load_memory()
        fn(mem)
        cleaned = _normalize_memory(mem)
        save_memory(cleaned)
        return cleaned


def apply_user_feedback(
    domain: str | None,
    feedback_type: str,
    lesson_note: str = "",
    input_snippet: str = "",
) -> dict[str, Any]:
    """
    Applies explicit user feedback ('confirm_scam', 'false_positive', 'false_negative') with:
    - Strict domain validation (rejects 127.0.0.1, localhost, private IPs, alert titles, sentences).
    - User 'false_positive' ('This is safe') removes domain from blacklist and adds to user_allowlist.
    - User 'confirm_scam' adds valid public domain to blacklist (if not in user_allowlist or WHITELIST).
    - Idempotent +/-1 weight adjustments per (domain, feedback_type), clamped to [base-10, base+10].
    - Sanitized, deduplicated lessons capped at 20 (max 120 chars).
    """
    valid_dom = normalize_valid_public_domain(domain)
    if valid_dom is None and input_snippet and not is_trustlens_internal_text(input_snippet):
        valid_dom = normalize_valid_public_domain(input_snippet)

    clean_lesson = sanitize_lesson_note(lesson_note)

    def _mutate(mem: dict[str, Any]) -> None:
        blacklist: list[str] = mem.setdefault("blacklisted_domains", [])
        allowlist: list[str] = mem.setdefault("user_allowlist", [])
        fb_history: list[str] = mem.setdefault("feedback_history", [])
        weights: dict[str, int] = mem.setdefault("weights", dict(BASE_WEIGHTS))
        metrics: dict[str, int] = mem.setdefault("metrics", {})

        if feedback_type == "false_positive":
            metrics["fp"] = metrics.get("fp", 0) + 1
            metrics["auto_fp_corrected"] = metrics.get("auto_fp_corrected", 0) + 1
            if valid_dom:
                while valid_dom in blacklist:
                    blacklist.remove(valid_dom)
                if valid_dom not in allowlist:
                    allowlist.append(valid_dom)

                fb_key = f"{valid_dom}|false_positive"
                if fb_key not in fb_history:
                    fb_history.append(fb_key)
                    for w_key in ("urgency_penalty", "vague_bait_penalty"):
                        base_w = BASE_WEIGHTS[w_key]
                        curr_w = int(weights.get(w_key, base_w))
                        weights[w_key] = max(base_w - 10, min(base_w + 10, curr_w - 1))

        elif feedback_type in ("confirm_scam", "false_negative"):
            if feedback_type == "false_negative":
                metrics["fn"] = metrics.get("fn", 0) + 1
                metrics["auto_fn_caught"] = metrics.get("auto_fn_caught", 0) + 1
            else:
                metrics["tp"] = metrics.get("tp", 0) + 1

            # Only blacklist if it is a valid public domain, NOT in WHITELIST_DOMAINS, and NOT in user_allowlist
            if (
                valid_dom
                and not domain_matches(valid_dom, WHITELIST_DOMAINS)
                and not domain_matches(valid_dom, allowlist)
            ):
                if valid_dom not in blacklist:
                    blacklist.append(valid_dom)

                fb_key = f"{valid_dom}|{feedback_type}"
                if fb_key not in fb_history:
                    fb_history.append(fb_key)
                    for w_key in ("urgency_penalty", "brand_spoof_penalty"):
                        base_w = BASE_WEIGHTS[w_key]
                        curr_w = int(weights.get(w_key, base_w))
                        weights[w_key] = max(base_w - 10, min(base_w + 10, curr_w + 1))

        if clean_lesson:
            lessons = mem.setdefault("few_shot_lessons", [])
            if clean_lesson not in lessons:
                lessons.append(clean_lesson)
                if len(lessons) > MAX_LESSONS:
                    del lessons[:-MAX_LESSONS]

    return mutate_memory(_mutate)


def _normalize_level(value: Any) -> str:
    s = str(value).strip().lower()
    if s.startswith(("high", "critical", "severe")):
        return "High"
    if s.startswith(("med", "moderate")):
        return "Medium"
    if s.startswith("unable"):
        return "Unable to verify"
    return "Low"


class FraudIndicator(BaseModel):
    indicator_type: str
    target_element: str
    explanation: str
    severity: str

    @field_validator("severity", mode="before")
    @classmethod
    def _severity(cls, v: Any) -> str:
        s = _normalize_level(v)
        return "Medium" if s == "Unable to verify" else s


class PhishingAuditResult(BaseModel):
    is_suspicious: bool
    verification_status: str = "verified_by_ai"
    overall_risk_score: str
    numeric_risk_score: int
    malicious_score: int = 0
    dark_pattern_score: int = 0
    fraud_category: str
    what_input_is_about: str
    what_input_is_about_hi: str = ""
    what_it_seems_to_be: str
    what_it_seems_to_be_hi: str = ""
    how_it_affects_user: str
    how_it_affects_user_hi: str = ""
    confidence_score_explanation: str
    dark_pattern_detected: str
    calm_down_message: str
    calm_down_message_hi: str = ""
    auto_calibration_action: str = "Evaluated by heuristic + AI pipeline."
    indicators: list[FraudIndicator]
    recommended_actions: list[str]
    recommended_actions_hi: list[str] = []

    @field_validator("overall_risk_score", mode="before")
    @classmethod
    def _level(cls, v: Any) -> str:
        return _normalize_level(v)

    @field_validator("numeric_risk_score", "malicious_score", "dark_pattern_score", mode="before")
    @classmethod
    def _numeric(cls, v: Any) -> int:
        try:
            return max(0, min(100, int(float(v))))
        except (TypeError, ValueError):
            return 0


class AIUnavailableError(Exception):
    """Raised when the Gemini API is unreachable, unconfigured, or returns invalid output."""


_client: genai.Client | None = None
_client_key: str | None = None
_client_lock = threading.Lock()


def get_configured_api_key() -> str:
    env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
    cleaned = env_key.strip()
    if cleaned and cleaned != "your_gemini_api_key_here":
        return cleaned
    return ""


def _get_client() -> genai.Client:
    global _client, _client_key
    key = get_configured_api_key()
    if not key:
        raise AIUnavailableError("GEMINI_API_KEY is not set in environment or .env.")
    with _client_lock:
        if _client is None or key != _client_key:
            _client = genai.Client(api_key=key, http_options=types.HttpOptions(timeout=ATTEMPT_TIMEOUT_MS))
            _client_key = key
        return _client


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()


def _parse_response(response: Any) -> PhishingAuditResult:
    parsed = getattr(response, "parsed", None)
    if isinstance(parsed, PhishingAuditResult):
        return parsed
    text = getattr(response, "text", None)
    if not text:
        raise ValidationError.from_exception_data("PhishingAuditResult", [])
    return PhishingAuditResult.model_validate_json(_strip_fences(text))


def _call_gemini(contents: Any) -> PhishingAuditResult:
    client = _get_client()
    deadline = time.monotonic() + AI_DEADLINE_S
    last_error: Exception | None = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=contents,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=PhishingAuditResult,
                    temperature=0.1,
                ),
            )
            return _parse_response(response)
        except Exception as e:
            last_error = e
            log.warning("Gemini call attempt %d/%d failed: %s", attempt, MAX_ATTEMPTS, e)
            delay = min(1.0 * 2 ** (attempt - 1), 3.0) + random.uniform(0.0, 0.25)
            if attempt == MAX_ATTEMPTS or time.monotonic() + delay > deadline:
                break
            time.sleep(delay)

    raise AIUnavailableError(f"Gemini unavailable: {last_error}") from last_error


def apply_post_validator(result: PhishingAuditResult, heuristics: dict[str, Any]) -> PhishingAuditResult:
    """Deterministic post-validator: enforces hard heuristic floors and bilingual completeness."""
    h_score = int(heuristics.get("base_score", 0) or 0)
    hard_floor = int(heuristics.get("hard_floor", h_score if h_score >= 55 else 0) or 0)
    mal_h = int(heuristics.get("malicious_score", h_score) or 0)
    dp_h = int(heuristics.get("dark_pattern_score", 0) or 0)

    result.malicious_score = max(result.malicious_score, mal_h)
    result.dark_pattern_score = max(result.dark_pattern_score, dp_h)

    floor_to_enforce = max(hard_floor, h_score if h_score >= 55 else 0)
    if floor_to_enforce > 0 and result.numeric_risk_score < floor_to_enforce:
        reason = (
            f"Deterministic post-validator enforced floor {floor_to_enforce}/100 "
            f"(rule: {heuristics.get('detected_category')})."
        )
        result.numeric_risk_score = floor_to_enforce
        result.overall_risk_score = "High" if floor_to_enforce >= 66 else "Medium"
        result.is_suspicious = True
        result.fraud_category = heuristics.get("detected_category", result.fraud_category)
        result.confidence_score_explanation = f"{result.confidence_score_explanation} ({reason})".strip()

    if heuristics.get("is_verified_safe") and not heuristics.get("has_url"):
        result.numeric_risk_score = min(result.numeric_risk_score, 10)
        result.overall_risk_score = "Low"
        result.is_suspicious = False
        result.fraud_category = heuristics.get("detected_category", "Legitimate Alert")

    if not result.what_input_is_about_hi:
        result.what_input_is_about_hi = heuristics.get("what_input_is_about_hi", result.what_input_is_about)
    if not result.what_it_seems_to_be_hi:
        result.what_it_seems_to_be_hi = heuristics.get("what_it_seems_to_be_hi", result.what_it_seems_to_be)
    if not result.how_it_affects_user_hi:
        result.how_it_affects_user_hi = heuristics.get("how_it_affects_user_hi", result.how_it_affects_user)
    if not result.calm_down_message_hi:
        result.calm_down_message_hi = heuristics.get("calm_message_hi", result.calm_down_message)
    if not result.recommended_actions_hi:
        result.recommended_actions_hi = heuristics.get("recommended_actions_hi", result.recommended_actions)

    existing_types = {i.indicator_type for i in result.indicators}
    for ind in heuristics.get("heuristic_indicators", []):
        if ind["type"] not in existing_types:
            result.indicators.append(
                FraudIndicator(
                    indicator_type=ind["type"],
                    target_element=ind["target"],
                    explanation=ind["explanation"],
                    severity=ind["severity"],
                )
            )
    return result


def audit_blueprint_with_ai(scrubbed_text: str, heuristics: dict[str, Any]) -> PhishingAuditResult:
    memory = load_memory()
    lessons = memory.get("few_shot_lessons", [])[-6:]
    safe_heuristics_summary = {
        "domain": heuristics.get("domain", ""),
        "whitelisted": heuristics.get("whitelisted", False),
        "blacklisted": heuristics.get("blacklisted", False),
        "impersonation_detected": heuristics.get("impersonation_detected", False),
        "pass1_naive_score": heuristics.get("pass1_naive_score", 0),
        "base_score": heuristics.get("base_score", 0),
        "detected_category": heuristics.get("detected_category", ""),
        "heuristic_indicators": heuristics.get("heuristic_indicators", []),
    }

    prompt = f"""You are TrustLens AI, an ambient Phishing, Impersonation & Digital Fraud Guardian (CC6-AI05).
Evaluate the PII-redacted input below and return JSON matching the schema in both English and Hindi (_hi fields).
IMPORTANT: Only describe signals and indicators that actually exist in the input. Never invent countdown timers, checkboxes, Win+R prompts, or support numbers if they are not present.

Local Deterministic Pre-Analysis: {json.dumps(safe_heuristics_summary, ensure_ascii=False)}
Learned Memory Lessons: {json.dumps(lessons, ensure_ascii=False)}

Redacted Input to Judge:
{scrub_pii(scrubbed_text)[:MAX_PROMPT_CHARS]}"""

    raw_result = _call_gemini(prompt)
    raw_result.verification_status = "verified_by_ai"
    return apply_post_validator(raw_result, heuristics)


def audit_webpage_with_ai(page_summary: dict[str, Any], page_heuristics: dict[str, Any]) -> PhishingAuditResult:
    memory = load_memory()
    lessons = memory.get("few_shot_lessons", [])[-6:]
    prompt = f"""You are TrustLens AI Browser Guardian (CC6-AI05).
Analyze this privacy-safe webpage structural summary.
IMPORTANT RULES:
1. The word 'password', 'login', or 'sign in' alone is NOT a threat. Only flag credential harvesting when combined with a deceptive domain, cross-domain form action, or explicit threat wording.
2. Only describe indicators and recommended actions that match signals actually present in Webpage Summary. Never mention countdown timers, checkboxes, Win+R, or support numbers unless they appear in the signals list.

Webpage Summary: {json.dumps(page_summary, ensure_ascii=False)}
Deterministic Signal Analysis: {json.dumps(page_heuristics.get('heuristic_indicators', []), ensure_ascii=False)}
Malicious Score: {page_heuristics.get('malicious_score', 0)}, Dark Pattern Score: {page_heuristics.get('dark_pattern_score', 0)}
Learned Lessons: {json.dumps(lessons, ensure_ascii=False)}"""

    raw_result = _call_gemini(prompt)
    raw_result.verification_status = "verified_by_ai"
    return apply_post_validator(raw_result, page_heuristics)


def downscale_and_validate_image(image_bytes: bytes) -> tuple[bytes, str]:
    if not image_bytes:
        raise ValueError("Empty image payload.")
    is_png = image_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpg = image_bytes.startswith(b"\xff\xd8\xff")
    is_webp = len(image_bytes) >= 12 and image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP"
    if not (is_png or is_jpg or is_webp):
        raise ValueError("File magic bytes do not match PNG, JPEG, or WebP.")

    with Image.open(io.BytesIO(image_bytes)) as img:
        img_rgb = img.convert("RGB")
        img_rgb.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
        out = io.BytesIO()
        img_rgb.save(out, format="JPEG", quality=82)
        return out.getvalue(), "image/jpeg"


def audit_image_with_ai(image_bytes: bytes, mime_type: str = "image/png") -> PhishingAuditResult:
    scaled_bytes, scaled_mime = downscale_and_validate_image(image_bytes)
    memory = load_memory()
    lessons = memory.get("few_shot_lessons", [])[-5:]
    prompt = f"""You are TrustLens AI Vision Guardian (CC6-AI05).
Inspect this screenshot for phishing URLs, homoglyphs (arnazon.com), fake UPI Collect Requests ('Refund' note on 'Pay' button),
fake AI bots, or vague attention-bait. Only describe elements actually visible in the image.
Learned Lessons: {json.dumps(lessons, ensure_ascii=False)}"""

    res = _call_gemini([types.Part.from_bytes(data=scaled_bytes, mime_type=scaled_mime), prompt])
    res.verification_status = "verified_by_ai_vision"
    return res


def build_offline_heuristic_result(heuristics: dict[str, Any]) -> PhishingAuditResult:
    base = int(heuristics.get("base_score", 0) or 0)
    mal_score = int(heuristics.get("malicious_score", base) or 0)
    dp_score = int(heuristics.get("dark_pattern_score", 0) or 0)
    inconclusive = bool(heuristics.get("inconclusive", False))

    indicators = [
        FraudIndicator(
            indicator_type=ind.get("type", "Heuristic Signal"),
            target_element=ind.get("target", "Input"),
            explanation=ind.get("explanation", "Triggered local deterministic rule."),
            severity=ind.get("severity", "High" if base >= 66 else "Medium" if base >= 31 else "Low"),
        )
        for ind in heuristics.get("heuristic_indicators", [])
    ]

    if inconclusive:
        return PhishingAuditResult(
            is_suspicious=False,
            verification_status="unable_to_verify_ai_offline",
            overall_risk_score="Unable to verify",
            numeric_risk_score=0,
            malicious_score=0,
            dark_pattern_score=0,
            fraud_category="Unable to Verify (Cloud AI Offline & No Local Rule Triggered)",
            what_input_is_about=heuristics.get("what_input_is_about", "Unverified message snippet."),
            what_input_is_about_hi=heuristics.get("what_input_is_about_hi", "असत्यापित संदेश।"),
            what_it_seems_to_be="Local heuristics found no known scam pattern, and cloud AI is currently unreachable.",
            what_it_seems_to_be_hi="स्थानीय जांच में कोई ज्ञात स्कैम पैटर्न नहीं मिला और क्लाउड एआई ऑफ़लाइन है।",
            how_it_affects_user="Cannot confirm safety while AI is offline. Do not click unknown links or share OTPs.",
            how_it_affects_user_hi="एआई ऑफ़लाइन होने के कारण पुष्टि नहीं की जा सकती। अनजान लिंक पर क्लिक न करें।",
            confidence_score_explanation="AI service is unreachable and local heuristics were inconclusive (0 rules fired).",
            dark_pattern_detected="None",
            calm_down_message="ℹ️ Cloud AI is offline and local checks were inconclusive. Verify independently before acting.",
            calm_down_message_hi="ℹ️ क्लाउड एआई ऑफ़लाइन है। कोई भी कदम उठाने से पहले स्वतंत्र रूप से जांचें।",
            auto_calibration_action="Offline mode: Marked as Unable to Verify.",
            indicators=[],
            recommended_actions=["Verify through the official app or website before acting."],
            recommended_actions_hi=["कार्रवाई करने से पहले आधिकारिक ऐप या वेबसाइट से सत्यापित करें।"],
        )

    level = "High" if base >= 66 else "Medium" if base >= 31 else "Low"
    is_susp = base >= 31

    return PhishingAuditResult(
        is_suspicious=is_susp,
        verification_status="verified_by_local_heuristics",
        overall_risk_score=level,
        numeric_risk_score=base,
        malicious_score=mal_score,
        dark_pattern_score=dp_score,
        fraud_category=heuristics.get("detected_category", "Local Heuristic Audit"),
        what_input_is_about=heuristics.get("what_input_is_about", ""),
        what_input_is_about_hi=heuristics.get("what_input_is_about_hi", ""),
        what_it_seems_to_be=heuristics.get("what_it_seems_to_be", ""),
        what_it_seems_to_be_hi=heuristics.get("what_it_seems_to_be_hi", ""),
        how_it_affects_user=heuristics.get("how_it_affects_user", ""),
        how_it_affects_user_hi=heuristics.get("how_it_affects_user_hi", ""),
        confidence_score_explanation=heuristics.get("confidence_score_explanation", ""),
        dark_pattern_detected=heuristics.get("dark_pattern", "None"),
        calm_down_message=heuristics.get("calm_message", ""),
        calm_down_message_hi=heuristics.get("calm_message_hi", ""),
        auto_calibration_action=heuristics.get("auto_calibration_note", "Evaluated by local heuristics."),
        indicators=indicators,
        recommended_actions=heuristics.get("recommended_actions", []),
        recommended_actions_hi=heuristics.get("recommended_actions_hi", []),
    )
