"""FastAPI backend for TrustLens AI (with /api/chat, /api/tts, /api/stats/breakdown, and 10/min chat rate limit)."""
from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
import hashlib
import ipaddress
import json
import logging
import os
import secrets
import socket
import threading
import time
from typing import Any, Callable
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
import requests
import uvicorn

from ai_auditor import (
    AIUnavailableError,
    ChatRequest,
    PhishingAuditResult,
    apply_user_feedback,
    audit_blueprint_with_ai,
    audit_image_with_ai,
    audit_webpage_with_ai,
    build_offline_heuristic_result,
    chat_with_trustlens_ai,
    downscale_and_validate_image,
    load_memory,
    migrate_and_clean_memory_on_startup,
    mutate_memory,
)
from collectors import (
    CollectorManager,
    get_extension_token,
    load_settings,
    save_settings,
    should_skip_collected_text,
)
from heuristics import evaluate_heuristics, is_local_or_private_host, scrub_pii
from page_analysis import PageAuditRequest, evaluate_page_signals, strip_url_query_and_fragment
from voice_assistant import OfflineSpeaker, VOICE_STACK_AVAILABLE, get_voice_availability_message

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
log = logging.getLogger("trustlens.api")

MAX_INPUT_CHARS = 20_000
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
MAX_PAGE_AUDIT_BODY_BYTES = 64 * 1024
MIN_AI_CALL_INTERVAL_S = 1.2
ITEM_AUDIT_TIMEOUT_S = 25.0

_STARTUP_TOKEN: str = get_extension_token()
speaker = OfflineSpeaker()

DASHBOARD_BREAKDOWN_CATEGORIES: tuple[tuple[str, str, str], ...] = (
    ("fake_links", "Fake website links", "नकली वेबसाइट लिंक"),
    ("fake_refunds", "Fake refunds or collect requests", "पिन मांगने वाले नकली रिफंड"),
    ("otp_or_password", "OTP or password requests", "OTP या पासवर्ड मांगने वाले मैसेज"),
    ("urgent_money", "Urgent money or bill scares", "तुरंत पैसे या बिल का डर"),
    ("page_tricks", "Webpage tricks", "वेबपेज की चालें"),
    ("safe_items", "Safe items", "सुरक्षित चीजें"),
)


def get_active_token() -> str:
    global _STARTUP_TOKEN
    tok = get_extension_token()
    if tok:
        _STARTUP_TOKEN = tok
    return _STARTUP_TOKEN


async def verify_extension_token(
    x_trustlens_token: str | None = Header(default=None, alias="X-TrustLens-Token"),
) -> str:
    """Enforces X-TrustLens-Token header (401 when missing, 403 when wrong) via secrets.compare_digest."""
    if x_trustlens_token is None or not x_trustlens_token.strip():
        raise HTTPException(status_code=401, detail="Missing X-TrustLens-Token header.")
    expected = get_active_token()
    supplied = x_trustlens_token.strip()
    if not expected or not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=403, detail="Invalid X-TrustLens-Token header.")
    return supplied


def classify_item_for_dashboard_breakdown(record: dict[str, Any]) -> str:
    analysis = record.get("analysis") or {}
    if not analysis.get("is_suspicious") or analysis.get("overall_risk_score") == "Low":
        return "safe_items"

    slice_keys = {str(s.get("key", "")) for s in (analysis.get("score_breakdown") or [])}
    cat_low = str(analysis.get("fraud_category", "")).lower()

    if "fake_refund_trap" in slice_keys or "refund" in cat_low or "collect" in cat_low:
        return "fake_refunds"
    if (
        slice_keys & {"asks_for_otp", "cross_site_login", "call_forward_code"}
        or "otp" in cat_low
        or "password" in cat_low
        or "*401*" in cat_low
    ):
        return "otp_or_password"
    if (
        slice_keys
        & {
            "fake_countdown",
            "pre_ticked_addon",
            "guilt_no_button",
            "unfair_choice_buttons",
            "hidden_button_trap",
            "copy_or_close_block",
            "clickfix_keys",
            "fake_virus_alert",
        }
        or int(analysis.get("dark_pattern_score", 0) or 0) > int(analysis.get("malicious_score", 0) or 0)
    ):
        return "page_tricks"
    if (
        slice_keys & {"fake_website_name", "known_scam_link", "strange_link_ending", "unsafe_connection", "number_only_link", "fake_link_text"}
        or "link" in cat_low
        or "website" in cat_low
    ):
        return "fake_links"
    return "urgent_money"


class AuditRequest(BaseModel):
    input_text: str = Field(..., min_length=1, max_length=MAX_INPUT_CHARS)
    channel: str = "manual"
    language: str = "en"


class FeedbackRequest(BaseModel):
    item_id: str = Field("", max_length=64)
    input_snippet: str = Field("", max_length=2000)
    domain: str | None = Field(None, max_length=300)
    feedback_type: str = Field(..., pattern="^(confirm_scam|false_positive|false_negative)$")
    lesson_note: str = Field("", max_length=300)


class SettingsUpdateRequest(BaseModel):
    consent_given: bool | None = None
    monitor_notifications: bool | None = None
    monitor_clipboard_text: bool | None = None
    monitor_screenshots: bool | None = None
    start_with_windows: bool | None = None
    voice_enabled: bool | None = None
    auto_read_high_risk: bool | None = None
    language: str | None = None
    paused: bool | None = None
    pause_minutes: int = 0


class TTSRequest(BaseModel):
    action: str = Field(..., pattern="^(speak|stop)$")
    text: str = Field("", max_length=1000)
    language: str = Field("en", pattern="^(en|hi)$")


class URLSafetyRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class OriginRateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, origin_key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(origin_key)
            if bucket is None:
                bucket = deque()
                self._buckets[origin_key] = bucket
                while len(self._buckets) > 256:
                    self._buckets.popitem(last=False)
            while bucket and (now - bucket[0]) > self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


class BoundedState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.incoming_queue: deque[dict[str, Any]] = deque(maxlen=150)
        self.judged_feed: deque[dict[str, Any]] = deque(maxlen=100)
        self.recent_results: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.category_counts: dict[str, int] = {k: 0 for k, _, _ in DASHBOARD_BREAKDOWN_CATEGORIES}
        self.last_ai_call_ts: float = 0.0
        self.total_scanned: int = 0
        self.alert_listeners: list[Callable[[dict[str, Any]], None]] = []

    def enqueue(self, event: dict[str, Any]) -> None:
        with self.lock:
            self.incoming_queue.append(event)

    def pop_next(self) -> dict[str, Any] | None:
        with self.lock:
            return self.incoming_queue.popleft() if self.incoming_queue else None

    def record_judged(self, cache_key: str, record: dict[str, Any]) -> None:
        callbacks: list[Callable[[dict[str, Any]], None]] = []
        cat_key = classify_item_for_dashboard_breakdown(record)
        with self.lock:
            self.total_scanned += 1
            self.category_counts[cat_key] = min(1_000_000, self.category_counts.get(cat_key, 0) + 1)
            self.judged_feed.appendleft(record)
            self.recent_results[cache_key] = record
            while len(self.recent_results) > 500:
                self.recent_results.popitem(last=False)
            callbacks = list(self.alert_listeners)
        for cb in callbacks:
            try:
                cb(record)
            except Exception as e:
                log.warning("Alert listener callback error: %s", e)

    def get_cached(self, cache_key: str) -> dict[str, Any] | None:
        with self.lock:
            return self.recent_results.get(cache_key)

    def get_last_5_redacted_summaries(self, lang: str = "en") -> list[dict[str, Any]]:
        """Returns ONLY the last 5 judged items' redacted summary (verdict_line, category, score, plain explanation)."""
        use_hi = lang == "hi"
        with self.lock:
            recent = list(self.judged_feed)[:5]
        summaries: list[dict[str, Any]] = []
        for rec in recent:
            a = rec.get("analysis") or {}
            summaries.append({
                "verdict_line": str((a.get("verdict_line_hi") if use_hi else a.get("verdict_line")) or ""),
                "category": str(a.get("fraud_category", "")),
                "score": int(a.get("numeric_risk_score", 0) or 0),
                "explanation": str((a.get("what_it_seems_to_be_hi") if use_hi else a.get("what_it_seems_to_be")) or "")[:160],
            })
        return summaries

    def get_dashboard_breakdown(self) -> list[dict[str, Any]]:
        with self.lock:
            feed_snapshot = list(self.judged_feed)
            counts_snapshot = dict(self.category_counts)

        if sum(counts_snapshot.values()) == 0 and feed_snapshot:
            for rec in feed_snapshot:
                ck = classify_item_for_dashboard_breakdown(rec)
                counts_snapshot[ck] = counts_snapshot.get(ck, 0) + 1

        out: list[dict[str, Any]] = []
        for key, label_en, label_hi in DASHBOARD_BREAKDOWN_CATEGORIES:
            out.append({
                "key": key,
                "label_en": label_en,
                "label_hi": label_hi,
                "count": int(counts_snapshot.get(key, 0)),
            })
        return out


state = BoundedState()
rate_limiter = OriginRateLimiter(max_requests=60, window_seconds=60.0)
chat_rate_limiter = OriginRateLimiter(max_requests=10, window_seconds=60.0)
collector_manager: CollectorManager | None = None
_worker_stop = threading.Event()


def register_alert_listener(cb: Callable[[dict[str, Any]], None]) -> None:
    with state.lock:
        state.alert_listeners.append(cb)


def _hash_key(data: str | bytes) -> str:
    raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _record_system_metrics_only(heuristics: dict[str, Any], result: PhishingAuditResult) -> None:
    p1_flagged = int(heuristics.get("pass1_naive_score", 0)) >= 31
    final_flagged = result.is_suspicious

    def _update(mem: dict[str, Any]) -> None:
        metrics = mem.setdefault(
            "metrics",
            {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "auto_fp_corrected": 0, "auto_fn_caught": 0, "browser_pages_scanned": 0, "dark_patterns_found": 0},
        )
        if p1_flagged and not final_flagged:
            metrics["auto_fp_corrected"] = metrics.get("auto_fp_corrected", 0) + 1
            metrics["tn"] = metrics.get("tn", 0) + 1
            result.auto_calibration_action = "Cleared safe alert automatically."
        elif not p1_flagged and final_flagged:
            metrics["auto_fn_caught"] = metrics.get("auto_fn_caught", 0) + 1
            metrics["tp"] = metrics.get("tp", 0) + 1
            result.auto_calibration_action = "Caught hidden scam automatically."
        else:
            if final_flagged:
                metrics["tp"] = metrics.get("tp", 0) + 1
            else:
                metrics["tn"] = metrics.get("tn", 0) + 1

    mutate_memory(_update)


def _respect_ai_rate_limit() -> None:
    with state.lock:
        now = time.monotonic()
        elapsed = now - state.last_ai_call_ts
        wait_for = max(0.0, MIN_AI_CALL_INTERVAL_S - elapsed)
        state.last_ai_call_ts = now + wait_for
    if wait_for > 0:
        time.sleep(wait_for)


async def perform_text_audit(text: str, source: str = "Manual Input", record_in_feed: bool = True) -> dict[str, Any]:
    cleaned = text.strip()[:MAX_INPUT_CHARS]
    if not cleaned:
        raise HTTPException(status_code=400, detail="Input text is empty.")

    cache_key = "txt_" + _hash_key(cleaned)
    cached = state.get_cached(cache_key)
    if cached is not None:
        return cached

    memory = load_memory()
    heuristics = evaluate_heuristics(cleaned, memory)
    scrubbed_input = scrub_pii(cleaned)

    def _run_sync() -> PhishingAuditResult:
        _respect_ai_rate_limit()
        return audit_blueprint_with_ai(scrubbed_input, heuristics)

    try:
        ai_res = await asyncio.wait_for(asyncio.to_thread(_run_sync), timeout=ITEM_AUDIT_TIMEOUT_S)
    except (AIUnavailableError, asyncio.TimeoutError, Exception) as e:
        log.info("Using offline heuristic verdict (%s)", type(e).__name__)
        ai_res = build_offline_heuristic_result(heuristics)

    _record_system_metrics_only(heuristics, ai_res)

    item_id = cache_key[:12]
    payload: dict[str, Any] = {
        "status": "success",
        "id": item_id,
        "source": source,
        "timestamp": time.strftime("%I:%M:%S %p"),
        "input": scrubbed_input,
        "heuristics": heuristics,
        "analysis": ai_res.model_dump(),
    }
    if record_in_feed:
        state.record_judged(cache_key, payload)
    return payload


async def perform_page_audit(req: PageAuditRequest, record_in_feed: bool = True) -> dict[str, Any]:
    host = req.hostname.lower().strip(".")
    if is_local_or_private_host(host):
        clean_url = strip_url_query_and_fragment(req.url)
        if not req.signals:
            safe_heur = evaluate_page_signals(req, load_memory())
            safe_res = build_offline_heuristic_result(safe_heur)
            return {
                "status": "success",
                "id": "local_safe",
                "source": "Browser",
                "timestamp": time.strftime("%I:%M:%S %p"),
                "input": clean_url,
                "heuristics": safe_heur,
                "analysis": safe_res.model_dump(),
            }

    clean_url = strip_url_query_and_fragment(req.url)
    sig_fingerprint = "|".join(f"{s.id}:{s.count}:{s.evidence[:30]}" for s in req.signals)
    cache_key = "page_" + _hash_key(f"{clean_url}|{sig_fingerprint}|{req.language}")

    cached = state.get_cached(cache_key)
    if cached is not None:
        return cached

    memory = load_memory()
    page_heur = evaluate_page_signals(req, memory)
    redacted_sample = scrub_pii(req.text_sample[:500])

    if page_heur.get("needs_ai"):
        summary_for_ai = {
            "url": clean_url,
            "hostname": host,
            "title": scrub_pii(req.title[:200]),
            "signals": [s.model_dump() for s in req.signals],
            "text_sample": redacted_sample,
        }

        def _run_page_ai() -> PhishingAuditResult:
            _respect_ai_rate_limit()
            return audit_webpage_with_ai(summary_for_ai, page_heur)

        try:
            ai_res = await asyncio.wait_for(asyncio.to_thread(_run_page_ai), timeout=ITEM_AUDIT_TIMEOUT_S)
        except (AIUnavailableError, asyncio.TimeoutError, Exception) as e:
            log.info("Page audit using deterministic result (%s)", type(e).__name__)
            ai_res = build_offline_heuristic_result(page_heur)
    else:
        ai_res = build_offline_heuristic_result(page_heur)

    dp_found_count = int(page_heur.get("dark_pattern_count", 0))

    def _update_browser_metrics(mem: dict[str, Any]) -> None:
        metrics = mem.setdefault(
            "metrics",
            {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "auto_fp_corrected": 0, "auto_fn_caught": 0, "browser_pages_scanned": 0, "dark_patterns_found": 0},
        )
        metrics["browser_pages_scanned"] = metrics.get("browser_pages_scanned", 0) + 1
        if dp_found_count > 0 or ai_res.dark_pattern_score >= 31:
            metrics["dark_patterns_found"] = metrics.get("dark_patterns_found", 0) + max(1, dp_found_count)
        if ai_res.is_suspicious:
            metrics["tp"] = metrics.get("tp", 0) + 1
        else:
            metrics["tn"] = metrics.get("tn", 0) + 1

    mutate_memory(_update_browser_metrics)

    payload: dict[str, Any] = {
        "status": "success",
        "id": cache_key[:12],
        "source": "Browser",
        "timestamp": time.strftime("%I:%M:%S %p"),
        "input": f"{clean_url} ({scrub_pii(req.title)[:60]})",
        "heuristics": page_heur,
        "analysis": ai_res.model_dump(),
    }
    if record_in_feed:
        state.record_judged(cache_key, payload)
    return payload


async def perform_image_audit(image_bytes: bytes, mime_type: str, source: str = "Screenshot", record_in_feed: bool = True) -> dict[str, Any]:
    if not image_bytes or len(image_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=400, detail="Image is empty or exceeds 8 MB limit.")

    try:
        scaled_bytes, scaled_mime = downscale_and_validate_image(image_bytes)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    cache_key = "img_" + _hash_key(scaled_bytes)
    cached = state.get_cached(cache_key)
    if cached is not None:
        return cached

    fallback_heuristics = evaluate_heuristics("", load_memory())
    fallback_heuristics["inconclusive"] = True

    def _run_vision_sync() -> PhishingAuditResult:
        _respect_ai_rate_limit()
        return audit_image_with_ai(scaled_bytes, scaled_mime)

    try:
        ai_res = await asyncio.wait_for(asyncio.to_thread(_run_vision_sync), timeout=ITEM_AUDIT_TIMEOUT_S)
    except (AIUnavailableError, asyncio.TimeoutError, Exception) as e:
        log.warning("Vision AI unavailable (%s); returning honest unverified status.", e)
        ai_res = build_offline_heuristic_result(fallback_heuristics)

    heuristics_summary = {
        "has_url": False,
        "domain": "",
        "pass1_naive_score": ai_res.numeric_risk_score,
        "base_score": ai_res.numeric_risk_score,
        "score_breakdown": [s.model_dump() for s in ai_res.score_breakdown],
        "malicious_score": ai_res.malicious_score or ai_res.numeric_risk_score,
        "dark_pattern_score": ai_res.dark_pattern_score,
        "impersonation_detected": False,
    }

    payload: dict[str, Any] = {
        "status": "success",
        "id": cache_key[:12],
        "source": source,
        "timestamp": time.strftime("%I:%M:%S %p"),
        "input": f"[{source}]",
        "heuristics": heuristics_summary,
        "analysis": ai_res.model_dump(),
    }
    if record_in_feed:
        state.record_judged(cache_key, payload)
    return payload


async def _queue_consumer_loop() -> None:
    log.info("Sequential queue processor started.")
    while not _worker_stop.is_set():
        item = state.pop_next()
        if item is not None:
            try:
                if item.get("type") == "text":
                    content = str(item.get("content", ""))
                    if not should_skip_collected_text(content, str(item.get("source", ""))):
                        await perform_text_audit(content, source=str(item.get("source", "Background")), record_in_feed=True)
                elif item.get("type") == "image":
                    await perform_image_audit(
                        item["content"],
                        str(item.get("mime_type", "image/png")),
                        source=str(item.get("source", "Screenshot")),
                        record_in_feed=True,
                    )
            except Exception as e:
                log.error("Queue item processing failed: %s", e)
        await asyncio.sleep(0.8)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global collector_manager, _STARTUP_TOKEN
    _worker_stop.clear()
    _STARTUP_TOKEN = get_extension_token()
    migrate_and_clean_memory_on_startup()
    collector_manager = CollectorManager(on_event_callback=state.enqueue)
    collector_manager.start()
    consumer_task = asyncio.create_task(_queue_consumer_loop())
    yield
    _worker_stop.set()
    if collector_manager is not None:
        collector_manager.stop()
    speaker.shutdown()
    consumer_task.cancel()


app = FastAPI(title="TrustLens AI — Ambient Desktop & Browser Guardian (CC6-AI05)", lifespan=lifespan)

_configured_ext_origins = [
    o.strip()
    for o in os.environ.get("TRUSTLENS_EXTENSION_ORIGINS", "").split(",")
    if o.strip().startswith("chrome-extension://")
]
_allowed_origins = ["http://127.0.0.1:8000", "http://localhost:8000"] + _configured_ext_origins


@app.middleware("http")
async def security_and_rate_limit_middleware(request: Request, call_next: Callable[[Request], Any]) -> Any:
    if request.method == "OPTIONS":
        return await call_next(request)

    origin = (request.headers.get("origin") or "").strip()
    client_host = request.client.host if request.client else "127.0.0.1"
    rate_key = origin or client_host

    if not rate_limiter.allow(rate_key):
        return JSONResponse(status_code=429, content={"status": "error", "detail": "Rate limit exceeded for origin."})

    if origin and origin not in _allowed_origins:
        return JSONResponse(status_code=403, content={"status": "error", "detail": "Origin not in allowed CORS origins."})

    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-TrustLens-Token"],
)


@app.get("/api/local-token")
async def get_local_dashboard_token(request: Request) -> dict[str, str]:
    origin = (request.headers.get("origin") or "").strip()
    if origin and origin not in ("http://127.0.0.1:8000", "http://localhost:8000"):
        raise HTTPException(status_code=403, detail="Forbidden origin.")
    return {"token": get_active_token()}


@app.post("/api/chat")
async def api_chat(
    req: ChatRequest,
    request: Request,
    _token: str = Depends(verify_extension_token),
) -> dict[str, Any]:
    """
    Token-protected 'Ask TrustLens' chatbot endpoint.
    - Rate limited to 10 messages per minute.
    - Redacts PII/OTPs before cloud calls, runs deterministic heuristics first,
      and never leaks the API key or extension token.
    """
    client_key = f"chat_{request.client.host if request.client else 'local'}"
    if not chat_rate_limiter.allow(client_key):
        raise HTTPException(status_code=429, detail="Too many chat messages. Please wait a minute.")

    recent_summaries = state.get_last_5_redacted_summaries(req.language)
    res = await asyncio.to_thread(chat_with_trustlens_ai, req, recent_summaries)
    return res.model_dump()


@app.post("/api/tts")
async def api_tts(
    req: TTSRequest,
    _token: str = Depends(verify_extension_token),
) -> dict[str, Any]:
    """Triggers or stops offline Windows SAPI speech via pyttsx3 on a worker thread."""
    if req.action == "stop":
        speaker.stop()
        return {"status": "stopped"}
    info = speaker.speak(req.text, req.language)
    return info


@app.get("/api/stats/breakdown")
async def api_stats_breakdown(
    _token: str = Depends(verify_extension_token),
) -> dict[str, Any]:
    mem = load_memory()
    metrics = mem.get("metrics", {})
    categories = state.get_dashboard_breakdown()
    total_categorized = sum(c["count"] for c in categories)
    return {
        "status": "ok",
        "total_scanned": state.total_scanned,
        "total_categorized": total_categorized,
        "categories": categories,
        "metrics": {
            "tp": int(metrics.get("tp", 0)),
            "tn": int(metrics.get("tn", 0)),
            "fp": int(metrics.get("fp", 0)),
            "fn": int(metrics.get("fn", 0)),
            "browser_pages_scanned": int(metrics.get("browser_pages_scanned", 0)),
            "dark_patterns_found": int(metrics.get("dark_patterns_found", 0)),
        },
    }


@app.get("/health")
async def get_health() -> dict[str, Any]:
    mem = load_memory()
    settings = load_settings()
    metrics = mem.get("metrics", {})
    tp = int(metrics.get("tp", 0))
    tn = int(metrics.get("tn", 0))
    fp = int(metrics.get("fp", 0))
    fn = int(metrics.get("fn", 0))
    total_eval = tp + tn + fp + fn
    accuracy = round(((tp + tn) / total_eval) * 100.0, 1) if total_eval > 0 else 100.0

    public_settings = {k: v for k, v in settings.items() if k != "extension_token"}
    return {
        "status": "ok",
        "paused": collector_manager.paused if collector_manager else False,
        "voice_available": VOICE_STACK_AVAILABLE,
        "voice_message": get_voice_availability_message(settings.get("language", "en")),
        "settings": public_settings,
        "total_scanned": state.total_scanned,
        "queue_pending": len(state.incoming_queue),
        "blacklisted_domains": mem.get("blacklisted_domains", []),
        "user_allowlist": mem.get("user_allowlist", []),
        "weights": mem.get("weights", {}),
        "metrics": metrics,
        "accuracy_pct": accuracy,
        "auto_audit_log": mem.get("auto_audit_log", [])[-15:],
    }


@app.post("/api/audit-page")
async def api_audit_page(
    request: Request,
    _token: str = Depends(verify_extension_token),
) -> dict[str, Any]:
    raw_body = await request.body()
    if len(raw_body) > MAX_PAGE_AUDIT_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request payload exceeds 64 KB limit.")
    try:
        data = json.loads(raw_body.decode("utf-8"))
        page_req = PageAuditRequest.model_validate(data)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid page audit payload: {e}") from e

    if collector_manager and collector_manager.paused:
        return {"status": "paused", "detail": "TrustLens protection is currently paused."}

    return await perform_page_audit(page_req, record_in_feed=True)


@app.post("/api/audit")
async def api_audit_text(req: AuditRequest) -> dict[str, Any]:
    return await perform_text_audit(req.input_text, source=f"Dashboard ({req.channel})", record_in_feed=True)


@app.post("/api/audit-image")
@app.post("/api/audit/upload")
async def api_audit_image(file: UploadFile = File(...)) -> dict[str, Any]:
    content_type = (file.content_type or "").lower()
    if content_type not in ("image/png", "image/jpeg", "image/jpg", "image/webp"):
        raise HTTPException(status_code=400, detail="Unsupported MIME type. Use PNG, JPEG, or WebP.")
    raw_bytes = await file.read(MAX_UPLOAD_BYTES + 1)
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded image file is empty.")
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded image exceeds 8 MB limit.")
    return await perform_image_audit(raw_bytes, content_type, source=f"Upload ({file.filename or 'image'})", record_in_feed=True)


@app.get("/api/feed")
async def api_get_feed() -> dict[str, Any]:
    mem = load_memory()
    metrics = mem.get("metrics", {})
    tp = int(metrics.get("tp", 0))
    tn = int(metrics.get("tn", 0))
    fp = int(metrics.get("fp", 0))
    fn = int(metrics.get("fn", 0))
    total_eval = tp + tn + fp + fn
    accuracy = round(((tp + tn) / total_eval) * 100.0, 1) if total_eval > 0 else 100.0

    with state.lock:
        items = list(state.judged_feed)
        pending = len(state.incoming_queue)
        scanned = state.total_scanned

    return {
        "status": "ok",
        "paused": collector_manager.paused if collector_manager else False,
        "queue_pending": pending,
        "total_scanned": scanned,
        "metrics": metrics,
        "accuracy_pct": accuracy,
        "items": items,
    }


@app.post("/api/feedback")
async def api_submit_feedback(
    req: FeedbackRequest,
    _token: str = Depends(verify_extension_token),
) -> dict[str, Any]:
    updated = apply_user_feedback(
        domain=req.domain,
        feedback_type=req.feedback_type,
        lesson_note=req.lesson_note,
        input_snippet=req.input_snippet,
    )
    return {
        "status": "success",
        "message": "Memory weights and lists updated.",
        "blacklisted_domains": updated.get("blacklisted_domains", []),
        "user_allowlist": updated.get("user_allowlist", []),
        "weights": updated.get("weights", {}),
        "metrics": updated.get("metrics", {}),
    }


@app.post("/api/settings")
async def api_update_settings(req: SettingsUpdateRequest) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    for field_name in (
        "consent_given",
        "monitor_notifications",
        "monitor_clipboard_text",
        "monitor_screenshots",
        "start_with_windows",
        "voice_enabled",
        "auto_read_high_risk",
        "language",
    ):
        val = getattr(req, field_name)
        if val is not None:
            updates[field_name] = val
    if updates:
        save_settings(updates)
    if req.paused is not None and collector_manager is not None:
        if req.paused:
            speaker.stop()
        collector_manager.set_paused(req.paused, duration_seconds=req.pause_minutes * 60)
    public_settings = {k: v for k, v in load_settings().items() if k != "extension_token"}
    return {"status": "success", "settings": public_settings, "paused": collector_manager.paused if collector_manager else False}


def _query_iana_whois(domain: str) -> str:
    try:
        tld = domain.split(".")[-1]
        with socket.create_connection(("whois.iana.org", 43), timeout=2.5) as s:
            s.sendall((tld + "\r\n").encode("ascii", errors="ignore"))
            resp = s.recv(4096).decode("utf-8", errors="ignore")
        refer_server = ""
        for line in resp.splitlines():
            if line.lower().startswith("refer:"):
                refer_server = line.split(":", 1)[1].strip()
                break
        if not refer_server:
            return "Unknown (WHOIS server not listed)"
        with socket.create_connection((refer_server, 43), timeout=3.0) as s2:
            s2.sendall((domain + "\r\n").encode("ascii", errors="ignore"))
            chunks: list[bytes] = []
            while True:
                data = s2.recv(4096)
                if not data or sum(len(c) for c in chunks) > 16_384:
                    break
                chunks.append(data)
        whois_text = b"".join(chunks).decode("utf-8", errors="ignore")
        for line in whois_text.splitlines():
            low = line.lower().strip()
            if any(low.startswith(k) for k in ("creation date:", "created on:", "registered on:", "created:")):
                return line.split(":", 1)[1].strip()[:40]
        return "Creation date not published by registry"
    except Exception as e:
        log.debug("WHOIS lookup note for %s: %s", domain, e)
        return "Unavailable (WHOIS timeout or restricted)"


@app.post("/api/url-safety")
async def api_url_safety(req: URLSafetyRequest) -> dict[str, Any]:
    raw_url = req.url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise HTTPException(status_code=400, detail="Invalid URL hostname.")

    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        for info in infos:
            ip_obj = ipaddress.ip_address(info[4][0].split("%")[0])
            if not ip_obj.is_global:
                raise HTTPException(status_code=400, detail="Refusing to probe private or local network address.")
    except socket.gaierror:
        return {
            "status": "unreachable",
            "requested_url": raw_url,
            "final_url": raw_url,
            "domain": host,
            "http_status": None,
            "domain_created": await asyncio.to_thread(_query_iana_whois, host),
            "note": "Domain does not resolve in DNS.",
        }

    def _safe_head() -> tuple[str, int | None]:
        try:
            resp = requests.head(raw_url, timeout=4.0, allow_redirects=True, headers={"User-Agent": "TrustLens-SafetyCheck/1.0"})
            return resp.url, resp.status_code
        except requests.RequestException:
            return raw_url, None

    final_url, status_code = await asyncio.to_thread(_safe_head)
    created_date = await asyncio.to_thread(_query_iana_whois, host)
    return {
        "status": "ok",
        "requested_url": raw_url,
        "final_url": final_url,
        "domain": host,
        "http_status": status_code,
        "domain_created": created_date,
    }


DEMO_SAMPLES: list[tuple[str, str]] = [
    ("Demo 1 (Homoglyph URL)", "arnazon.com"),
    ("Demo 2 (Vague Bait SMS)", "5M credited to your account, click here"),
    (
        "Demo 3 (Linkless Credential Trap)",
        "SECURITY ALERT: Your bank account is temporarily restricted. Reply with your internet banking username, password, and OTP to reactivate it.",
    ),
    (
        "Demo 4 (UPI Collect Trap)",
        "Ramesh (OLX Buyer) has requested Rs. 4,500. Note: 'Cashback/Refund for Sofa'. Tap 'Pay ₹4,500' and enter your UPI PIN to receive money.",
    ),
    ("Demo 5 (Fake AI Portal)", "https://chatgpi-pro.com/login"),
    (
        "Demo 6 (Genuine Bank OTP)",
        "482910 is your One Time Password (OTP) for netbanking login at SBI. Do NOT share this OTP with anyone. Bank employees never ask for OTP.",
    ),
]


@app.post("/api/demo")
async def api_trigger_demo() -> dict[str, Any]:
    for label, text in DEMO_SAMPLES:
        state.enqueue({"type": "text", "source": label, "content": text})
    return {"status": "success", "queued_count": len(DEMO_SAMPLES)}


@app.get("/demo/dark-patterns")
async def serve_dark_patterns_demo() -> Any:
    demo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo", "dark_patterns_demo.html")
    if os.path.exists(demo_path):
        return FileResponse(demo_path)
    raise HTTPException(status_code=404, detail="demo/dark_patterns_demo.html not found.")


@app.get("/demo/clean")
async def serve_clean_demo() -> Any:
    demo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo", "clean_demo.html")
    if os.path.exists(demo_path):
        return FileResponse(demo_path)
    raise HTTPException(status_code=404, detail="demo/clean_demo.html not found.")


@app.get("/vendor/chart.umd.js")
async def serve_vendored_chart_js() -> Any:
    vendor_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "vendor", "chart.umd.js")
    if os.path.exists(vendor_path):
        return FileResponse(vendor_path, media_type="application/javascript")
    raise HTTPException(status_code=404, detail="static/vendor/chart.umd.js not found.")


@app.get("/")
async def serve_dashboard() -> Any:
    ui_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
    if os.path.exists(ui_path):
        return FileResponse(ui_path)
    return {"status": "ok", "message": "TrustLens AI API running."}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("TRUSTLENS_PORT", "8000")))
