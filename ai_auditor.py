"""Gemini-backed auditing, deterministic post-validation, and atomic agent memory for TrustLens AI."""
from __future__ import annotations

import copy
import io
import json
import logging
import os
import random
import tempfile
import threading
import time
from typing import Any, Callable

from google import genai
from google.genai import types
from PIL import Image
from pydantic import BaseModel, ValidationError, field_validator

from heuristics import scrub_pii

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

log = logging.getLogger("trustlens.ai")

MEMORY_FILE = os.environ.get("TRUSTLENS_MEMORY_FILE", "agent_memory.json")
MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
HARDCODED_API_KEY = "AQ.Ab8RN6KD-N0ukF16FIRVYFYIohMPhNQzj57NOdnLDBm6TY3vbQ"  # REMOVE BEFORE SUBMISSION

MAX_PROMPT_CHARS = 16_000
MAX_ATTEMPTS = 2
ATTEMPT_TIMEOUT_MS = 14_000
AI_DEADLINE_S = 22
MAX_LESSONS = 50
MAX_LESSON_CHARS = 300
MAX_BLACKLIST = 5000

DEFAULT_MEMORY: dict[str, Any] = {
    "blacklisted_domains": [
        "sbi-kyc-update.xyz",
        "bses-bill-desk.xyz",
        "gmap-task-bonus.top",
        "indiapost-parcel-verify.xyz",
        "hdfc-reward-points-redeem.click",
        "chatgpi-pro.com",
    ],
    "weights": {
        "urgency_penalty": 25,
        "unverified_tld_penalty": 40,
        "missing_https_penalty": 20,
        "brand_spoof_penalty": 45,
        "collect_trap_penalty": 50,
        "vague_bait_penalty": 55,
    },
    "few_shot_lessons": [
        "Visual homoglyphs like 'arnazon.com' (rn->m) or 'paytrn.in' are High Risk brand impersonations.",
        "Vague attention-bait messages with zero verifiable context MUST be flagged as at least Medium or High Risk.",
        "Requests asking the user to reply with username, password, PIN, or OTP are High Risk direct credential harvesting scams.",
        "Legitimate bank OTP alerts that explicitly say 'Do NOT share this OTP with anyone' and contain no phishing links are Low Risk (Safe).",
    ],
    "metrics": {
        "tp": 6,
        "tn": 4,
        "fp": 0,
        "fn": 0,
        "auto_fp_corrected": 2,
        "auto_fn_caught": 3,
    },
    "auto_audit_log": [],
}

_memory_lock = threading.RLock()


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _normalize_memory(raw: Any) -> dict[str, Any]:
    mem = copy.deepcopy(DEFAULT_MEMORY)
    if not isinstance(raw, dict):
        return mem
    domains = raw.get("blacklisted_domains")
    if isinstance(domains, list):
        cleaned = [d.strip().lower() for d in domains if isinstance(d, str) and d.strip()]
        mem["blacklisted_domains"] = list(dict.fromkeys(cleaned))[-MAX_BLACKLIST:]
    weights = raw.get("weights")
    if isinstance(weights, dict):
        for key, value in weights.items():
            if _is_number(value):
                mem["weights"][key] = int(value)
    lessons = raw.get("few_shot_lessons")
    if isinstance(lessons, list):
        cleaned = [" ".join(l.split())[:MAX_LESSON_CHARS] for l in lessons if isinstance(l, str) and l.strip()]
        mem["few_shot_lessons"] = cleaned[-MAX_LESSONS:]
    metrics = raw.get("metrics")
    if isinstance(metrics, dict):
        for k in ("tp", "tn", "fp", "fn", "auto_fp_corrected", "auto_fn_caught"):
            if isinstance(metrics.get(k), int):
                mem["metrics"][k] = max(0, metrics[k])
    audit_log = raw.get("auto_audit_log")
    if isinstance(audit_log, list):
        mem["auto_audit_log"] = [str(x)[:260] for x in audit_log[-30:]]
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


def mutate_memory(fn: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    with _memory_lock:
        mem = load_memory()
        fn(mem)
        save_memory(mem)
        return mem


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

    @field_validator("numeric_risk_score", mode="before")
    @classmethod
    def _numeric(cls, v: Any) -> int:
        try:
            return max(0, min(100, int(float(v))))
        except (TypeError, ValueError):
            return 0


class AIUnavailableError(Exception):
    """Raised when the Gemini API is unreachable, rate-limited, or returns invalid output."""


_client: genai.Client | None = None
_client_key: str | None = None
_client_lock = threading.Lock()


def get_configured_api_key() -> str:
    env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if env_key and env_key.strip() and env_key.strip() != "your_gemini_api_key_here":
        return env_key.strip()
    return HARDCODED_API_KEY  # REMOVE BEFORE SUBMISSION


def _get_client() -> genai.Client:
    global _client, _client_key
    key = get_configured_api_key()
    if not key:
        raise AIUnavailableError("GEMINI_API_KEY is not configured.")
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

    # Hard rule 1: If a hard heuristic rule fired (blacklisted, homoglyph, secret demand, collect trap, vague bait),
    # never let an LLM hallucination lower the score below the deterministic floor.
    if h_score >= 55 and result.numeric_risk_score < h_score:
        reason = (
            f"Deterministic post-validator raised score from {result.numeric_risk_score} to {h_score} "
            f"due to hard rule: {heuristics.get('detected_category')}."
        )
        result.numeric_risk_score = h_score
        result.overall_risk_score = "High" if h_score >= 66 else "Medium"
        result.is_suspicious = True
        result.fraud_category = heuristics.get("detected_category", result.fraud_category)
        result.confidence_score_explanation = f"{result.confidence_score_explanation} ({reason})".strip()

    # Hard rule 2: If deterministic allow-list verified a genuine OTP or UPI receipt with no URL, prevent false positives.
    if heuristics.get("is_verified_safe") and not heuristics.get("has_url"):
        result.numeric_risk_score = min(result.numeric_risk_score, 10)
        result.overall_risk_score = "Low"
        result.is_suspicious = False
        result.fraud_category = heuristics.get("detected_category", "Legitimate Alert")

    # Ensure bilingual Hindi fields and indicators are always populated
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

    if not result.indicators and heuristics.get("heuristic_indicators"):
        result.indicators = [
            FraudIndicator(
                indicator_type=ind["type"],
                target_element=ind["target"],
                explanation=ind["explanation"],
                severity=ind["severity"],
            )
            for ind in heuristics["heuristic_indicators"]
        ]

    return result


def audit_blueprint_with_ai(scrubbed_text: str, heuristics: dict[str, Any]) -> PhishingAuditResult:
    """Audits PII-scrubbed text using Gemini and validates with deterministic post-rules."""
    memory = load_memory()
    lessons = memory.get("few_shot_lessons", [])[-6:]
    # Strip any verbose fields before sending heuristics summary to Gemini; never include raw un-scrubbed text
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

Mandatory Evaluation Rules:
1. 'what_input_is_about' / 'what_input_is_about_hi': Literal summary of the input.
2. 'what_it_seems_to_be' / 'what_it_seems_to_be_hi': What persona/disguise it projects vs reality.
3. 'how_it_affects_user' / 'how_it_affects_user_hi': Concrete consequence if the user clicks, replies, or pays.
4. Catch visual homoglyph domains (arnazon.com, g00gle.com, paytrn.in), typosquats (hdfcbnk.com), and fake AI portals (chatgpi-pro.com).
5. Flag vague attention-bait ('5M credited, click here') as at least Medium or High Risk.
6. Flag linkless credential/OTP harvesting ('Reply with username, password, and OTP') as High Risk (95+).
7. Recognize genuine bank OTP warnings ('Do NOT share this OTP') and genuine UPI receipts as Low Risk (0-10).

Local Deterministic Pre-Analysis: {json.dumps(safe_heuristics_summary, ensure_ascii=False)}
Learned Memory Lessons: {json.dumps(lessons, ensure_ascii=False)}

Redacted Input to Judge:
{scrub_pii(scrubbed_text)[:MAX_PROMPT_CHARS]}"""

    raw_result = _call_gemini(prompt)
    raw_result.verification_status = "verified_by_ai"
    return apply_post_validator(raw_result, heuristics)


def downscale_and_validate_image(image_bytes: bytes) -> tuple[bytes, str]:
    """Validates image magic bytes, downscales to max 1024x1024, and converts to JPEG/PNG."""
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
    """Downscales screenshot and audits it with Gemini multimodal vision."""
    scaled_bytes, scaled_mime = downscale_and_validate_image(image_bytes)
    memory = load_memory()
    lessons = memory.get("few_shot_lessons", [])[-5:]
    prompt = f"""You are TrustLens AI Vision Guardian (CC6-AI05).
Inspect this screenshot for phishing URLs, homoglyphs (arnazon.com), fake UPI Collect Requests ('Refund' note on 'Pay' button),
fake AI bots, vague attention-bait, or fake urgency countdowns.
Return bilingual English and Hindi (_hi) fields strictly conforming to the schema.
Learned Lessons: {json.dumps(lessons, ensure_ascii=False)}"""

    res = _call_gemini([types.Part.from_bytes(data=scaled_bytes, mime_type=scaled_mime), prompt])
    res.verification_status = "verified_by_ai_vision"
    return res


def build_offline_heuristic_result(heuristics: dict[str, Any]) -> PhishingAuditResult:
    """Builds an honest offline result from heuristics when Gemini is unreachable."""
    base = int(heuristics.get("base_score", 0) or 0)
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
