"""FastAPI backend, sequential queue processor, rate limiter, and unified audit service for TrustLens AI."""
from __future__ import annotations

import asyncio
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
import hashlib
import ipaddress
import logging
import os
import socket
import time
import threading
from typing import Any, Callable
from urllib.parse import urlparse

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import requests
import uvicorn

from ai_auditor import (
    AIUnavailableError,
    PhishingAuditResult,
    audit_blueprint_with_ai,
    audit_image_with_ai,
    build_offline_heuristic_result,
    downscale_and_validate_image,
    load_memory,
    mutate_memory,
)
from collectors import CollectorManager, load_settings, save_settings
from heuristics import WHITELIST_DOMAINS, domain_matches, evaluate_heuristics, scrub_pii

logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
log = logging.getLogger("trustlens.api")

MAX_INPUT_CHARS = 20_000
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
MIN_AI_CALL_INTERVAL_S = 1.2
ITEM_AUDIT_TIMEOUT_S = 25.0


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
    language: str | None = None
    paused: bool | None = None
    pause_minutes: int = 0


class URLSafetyRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class BoundedState:
    """Thread-safe container for the incoming queue, judged feed, and deduplication cache."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.incoming_queue: deque[dict[str, Any]] = deque(maxlen=150)
        self.judged_feed: deque[dict[str, Any]] = deque(maxlen=100)
        self.recent_results: OrderedDict[str, dict[str, Any]] = OrderedDict()
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
        with self.lock:
            self.total_scanned += 1
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


state = BoundedState()
collector_manager: CollectorManager | None = None
_worker_stop = threading.Event()


def register_alert_listener(cb: Callable[[dict[str, Any]], None]) -> None:
    """Allows the desktop UI and system tray to receive real-time callbacks when an item is judged."""
    with state.lock:
        state.alert_listeners.append(cb)


def _hash_key(data: str | bytes) -> str:
    raw = data.encode("utf-8", errors="replace") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _apply_auto_calibration_and_metrics(raw_text: str, heuristics: dict[str, Any], result: PhishingAuditResult) -> None:
    """Updates agent_memory.json metrics, blacklists, and Pass-1 vs Pass-2 auto-calibration."""
    p1_flagged = int(heuristics.get("pass1_naive_score", 0)) >= 31
    final_flagged = result.is_suspicious
    host = str(heuristics.get("domain") or "").lower().strip()
    whitelisted = bool(heuristics.get("whitelisted", False))
    redacted_snippet = scrub_pii(raw_text)[:60]

    def _update(mem: dict[str, Any]) -> None:
        metrics = mem.setdefault("metrics", {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "auto_fp_corrected": 0, "auto_fn_caught": 0})
        weights = mem.setdefault("weights", {})
        audit_log = mem.setdefault("auto_audit_log", [])

        if p1_flagged and not final_flagged:
            metrics["auto_fp_corrected"] = metrics.get("auto_fp_corrected", 0) + 1
            metrics["tn"] = metrics.get("tn", 0) + 1
            weights["urgency_penalty"] = max(10, int(weights.get("urgency_penalty", 25)) - 1)
            entry = f"[AUTO-FP SUPPRESSED] Cleared safe alert: '{redacted_snippet}'"
            if entry not in audit_log:
                audit_log.append(entry)
            result.auto_calibration_action = (
                "🤖 AUTO-FP SUPPRESSED: Naive keyword pass flagged urgency/OTP terms, "
                "but Contextual Judge verified safe intent and reduced urgency_penalty (-1)."
            )
        elif not p1_flagged and final_flagged:
            metrics["auto_fn_caught"] = metrics.get("auto_fn_caught", 0) + 1
            metrics["tp"] = metrics.get("tp", 0) + 1
            weights["brand_spoof_penalty"] = min(75, int(weights.get("brand_spoof_penalty", 45)) + 2)
            if host and not whitelisted and result.numeric_risk_score >= 70:
                if host not in mem["blacklisted_domains"]:
                    mem["blacklisted_domains"].append(host)
            entry = f"[AUTO-FN CAUGHT] Caught stealthy threat: '{host or redacted_snippet}'"
            if entry not in audit_log:
                audit_log.append(entry)
            result.auto_calibration_action = (
                f"🤖 AUTO-FN INTERCEPTED: Naive keyword pass missed this ({heuristics.get('pass1_naive_score')}/100), "
                f"but Deep Homoglyph/Context Judge caught '{result.fraud_category}' ({result.numeric_risk_score}/100)."
            )
        else:
            if final_flagged:
                metrics["tp"] = metrics.get("tp", 0) + 1
                if host and not whitelisted and result.numeric_risk_score >= 75:
                    if host not in mem["blacklisted_domains"]:
                        mem["blacklisted_domains"].append(host)
            else:
                metrics["tn"] = metrics.get("tn", 0) + 1

    mutate_memory(_update)


def _respect_ai_rate_limit() -> None:
    """Enforces a minimum interval between Gemini calls so clipboard bursts cannot exhaust quota."""
    with state.lock:
        now = time.monotonic()
        elapsed = now - state.last_ai_call_ts
        wait_for = max(0.0, MIN_AI_CALL_INTERVAL_S - elapsed)
        state.last_ai_call_ts = now + wait_for
    if wait_for > 0:
        time.sleep(wait_for)


async def perform_text_audit(text: str, source: str = "Manual Input", record_in_feed: bool = True) -> dict[str, Any]:
    """Unified service function used by both REST endpoints and the background queue worker."""
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

    _apply_auto_calibration_and_metrics(cleaned, heuristics, ai_res)

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


async def perform_image_audit(image_bytes: bytes, mime_type: str, source: str = "Screenshot", record_in_feed: bool = True) -> dict[str, Any]:
    """Unified service function for screenshot auditing (clipboard, folder watchdog, and upload API)."""
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
    fallback_heuristics["what_input_is_about"] = f"Screenshot captured from {source}."
    fallback_heuristics["what_input_is_about_hi"] = f"{source} से लिया गया स्क्रीनशॉट।"

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
        "impersonation_detected": "impersonat" in ai_res.fraud_category.lower() or "homoglyph" in ai_res.fraud_category.lower(),
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
    """Async background task pulling items one-by-one from the collector queue."""
    log.info("Sequential queue processor started.")
    while not _worker_stop.is_set():
        item = state.pop_next()
        if item is not None:
            try:
                if item.get("type") == "text":
                    await perform_text_audit(str(item["content"]), source=str(item.get("source", "Background")), record_in_feed=True)
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
    global collector_manager
    _worker_stop.clear()
    collector_manager = CollectorManager(on_event_callback=state.enqueue)
    collector_manager.start()
    consumer_task = asyncio.create_task(_queue_consumer_loop())
    yield
    _worker_stop.set()
    if collector_manager is not None:
        collector_manager.stop()
    consumer_task.cancel()


app = FastAPI(title="TrustLens AI — Ambient Phishing & Fraud Guardian (CC6-AI05)", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


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

    return {
        "status": "ok",
        "paused": collector_manager.paused if collector_manager else False,
        "settings": settings,
        "total_scanned": state.total_scanned,
        "queue_pending": len(state.incoming_queue),
        "blacklisted_domains": mem.get("blacklisted_domains", []),
        "weights": mem.get("weights", {}),
        "metrics": metrics,
        "accuracy_pct": accuracy,
        "auto_audit_log": mem.get("auto_audit_log", [])[-15:],
    }


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
async def api_submit_feedback(req: FeedbackRequest) -> dict[str, Any]:
    clean_domain = (req.domain or "").lower().strip()
    clean_lesson = " ".join(req.lesson_note.split())[:300]

    def _apply(mem: dict[str, Any]) -> None:
        metrics = mem.setdefault("metrics", {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "auto_fp_corrected": 0, "auto_fn_caught": 0})
        weights = mem.setdefault("weights", {})
        audit_log = mem.setdefault("auto_audit_log", [])

        if req.feedback_type == "false_positive":
            metrics["fp"] = metrics.get("fp", 0) + 1
            metrics["auto_fp_corrected"] = metrics.get("auto_fp_corrected", 0) + 1
            weights["urgency_penalty"] = max(5, int(weights.get("urgency_penalty", 25)) - 3)
            weights["vague_bait_penalty"] = max(20, int(weights.get("vague_bait_penalty", 55)) - 3)
            if clean_domain and clean_domain in mem.get("blacklisted_domains", []):
                mem["blacklisted_domains"].remove(clean_domain)
            audit_log.append(f"[USER FEEDBACK: SAFE] Lowered urgency/bait weights (-3) on '{scrub_pii(req.input_snippet)[:45]}'")

        elif req.feedback_type in ("confirm_scam", "false_negative"):
            if req.feedback_type == "false_negative":
                metrics["fn"] = metrics.get("fn", 0) + 1
                metrics["auto_fn_caught"] = metrics.get("auto_fn_caught", 0) + 1
            else:
                metrics["tp"] = metrics.get("tp", 0) + 1
            weights["urgency_penalty"] = min(65, int(weights.get("urgency_penalty", 25)) + 3)
            weights["brand_spoof_penalty"] = min(80, int(weights.get("brand_spoof_penalty", 45)) + 3)
            if clean_domain and not domain_matches(clean_domain, WHITELIST_DOMAINS):
                if clean_domain not in mem["blacklisted_domains"]:
                    mem["blacklisted_domains"].append(clean_domain)
            audit_log.append(f"[USER FEEDBACK: SCAM] Boosted weights (+3) & blacklisted '{clean_domain or scrub_pii(req.input_snippet)[:45]}'")

        if clean_lesson and clean_lesson not in mem["few_shot_lessons"]:
            mem["few_shot_lessons"].append(clean_lesson)

    updated = mutate_memory(_apply)
    return {
        "status": "success",
        "message": "Memory weights and metrics updated.",
        "weights": updated.get("weights", {}),
        "metrics": updated.get("metrics", {}),
    }


@app.post("/api/settings")
async def api_update_settings(req: SettingsUpdateRequest) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    for field_name in ("consent_given", "monitor_notifications", "monitor_clipboard_text", "monitor_screenshots", "start_with_windows", "language"):
        val = getattr(req, field_name)
        if val is not None:
            updates[field_name] = val
    if updates:
        save_settings(updates)
    if req.paused is not None and collector_manager is not None:
        collector_manager.set_paused(req.paused, duration_seconds=req.pause_minutes * 60)
    return {"status": "success", "settings": load_settings(), "paused": collector_manager.paused if collector_manager else False}


def _query_iana_whois(domain: str) -> str:
    """Performs a lightweight, dependency-free socket WHOIS query for domain creation date, failing gracefully."""
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

    # SSRF guard: block private/loopback IPs
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
    """Enqueues all 6 hackathon demo scenarios into the background queue for live evaluation."""
    for label, text in DEMO_SAMPLES:
        state.enqueue({"type": "text", "source": label, "content": text})
    return {"status": "success", "queued_count": len(DEMO_SAMPLES)}


@app.get("/")
async def serve_dashboard() -> Any:
    ui_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "index.html")
    if os.path.exists(ui_path):
        return FileResponse(ui_path)
    return {"status": "ok", "message": "TrustLens AI API running."}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("TRUSTLENS_PORT", "8000")))
