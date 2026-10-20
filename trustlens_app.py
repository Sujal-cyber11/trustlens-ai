"""Unified single-process background entry point for TrustLens AI (with Push-to-Talk & Offline SAPI)."""
from __future__ import annotations

import ctypes
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any
import webbrowser

import pyperclip
import uvicorn

from collectors import load_settings, save_settings
from desktop_sentinel import AmbientDesktopUI
import main as backend_main
from tray import TrayManager, send_high_risk_windows_toast, set_autostart_enabled
from voice_assistant import (
    PushToTalkController,
    build_alert_speech_text,
    parse_voice_command,
)

APP_DATA_DIR = Path(os.path.expandvars(r"%LOCALAPPDATA%\TrustLens"))
LOG_DIR = APP_DATA_DIR / "logs"
LOCK_FILE = APP_DATA_DIR / "trustlens.lock"
PORT = int(os.environ.get("TRUSTLENS_PORT", "8000"))
DASHBOARD_URL = f"http://127.0.0.1:{PORT}"


def setup_rotating_logger() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "trustlens.log"
    handler = RotatingFileHandler(str(log_file), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    return logging.getLogger("trustlens.app")


log = setup_rotating_logger()


class SingleInstanceGuard:
    def __init__(self) -> None:
        self.mutex_handle: Any = None
        self.lock_fd: int | None = None

    def acquire(self) -> bool:
        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            mutex_name = "Global\\TrustLensAISingleInstanceMutex_v2"
            handle = kernel32.CreateMutexW(None, True, mutex_name)
            last_err = kernel32.GetLastError()
            if last_err == 183:
                return False
            self.mutex_handle = handle
            return True

        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(fd, str(os.getpid()).encode("ascii"))
            self.lock_fd = fd
            return True
        except OSError:
            return False

    def release(self) -> None:
        if sys.platform == "win32" and self.mutex_handle:
            try:
                ctypes.windll.kernel32.ReleaseMutex(self.mutex_handle)
                ctypes.windll.kernel32.CloseHandle(self.mutex_handle)
            except Exception as e:
                log.debug("Mutex release note: %s", e)
            self.mutex_handle = None
        if self.lock_fd is not None:
            try:
                os.close(self.lock_fd)
                os.unlink(str(LOCK_FILE))
            except OSError:
                pass
            self.lock_fd = None


class UnifiedApplication:
    def __init__(self) -> None:
        self.guard = SingleInstanceGuard()
        self.uvicorn_server: uvicorn.Server | None = None
        self.server_thread: threading.Thread | None = None
        self.ui: AmbientDesktopUI | None = None
        self.tray: TrayManager | None = None
        self.ptt: PushToTalkController | None = None

    def start(self) -> None:
        if not self.guard.acquire():
            log.info("TrustLens AI is already running; opening dashboard in browser.")
            webbrowser.open(DASHBOARD_URL)
            sys.exit(0)

        log.info("Starting TrustLens AI unified process on %s", DASHBOARD_URL)
        settings = load_settings()
        if settings.get("consent_given") and settings.get("start_with_windows", True):
            set_autostart_enabled(True)

        config = uvicorn.Config(
            backend_main.app,
            host="127.0.0.1",
            port=PORT,
            log_level="warning",
            access_log=False,
        )
        self.uvicorn_server = uvicorn.Server(config)
        self.server_thread = threading.Thread(target=self.uvicorn_server.run, name="UvicornThread", daemon=True)
        self.server_thread.start()

        self.ui = AmbientDesktopUI(speaker=backend_main.speaker, on_status_change=self._on_ui_badge_change)

        self.tray = TrayManager(
            dashboard_url=DASHBOARD_URL,
            on_open_alerts=self.ui.request_open_drawer,
            on_open_chat=lambda: self.ui.request_open_chat("", False),
            on_pause_change=self._on_tray_pause_change,
            on_quit=self.shutdown,
        )
        self.tray.start_in_thread()

        self.ptt = PushToTalkController(
            is_voice_allowed_fn=self._is_voice_allowed,
            get_hotkey_fn=lambda: str(load_settings().get("ptt_hotkey", "ctrl+alt+t")),
            on_listening_change=lambda active, txt: self.ui.set_voice_listening_indicator(active, txt) if self.ui else None,
            on_transcript_ready=self._handle_voice_transcript,
            on_escape_pressed=backend_main.speaker.stop,
        )
        self.ptt.start()

        backend_main.register_alert_listener(self._on_item_judged)

        if "--demo" in sys.argv:
            threading.Thread(target=self._trigger_cli_demo, daemon=True).start()

        try:
            self.ui.mainloop()
        finally:
            self._cleanup()

    def _is_voice_allowed(self) -> bool:
        if backend_main.collector_manager and backend_main.collector_manager.paused:
            return False
        s = load_settings()
        return bool(s.get("consent_given", False)) and bool(s.get("voice_enabled", False))

    def _handle_voice_transcript(self, transcript: str) -> None:
        if not self._is_voice_allowed() or self.ui is None:
            return
        parsed = parse_voice_command(transcript)
        act = parsed["action"]
        lang = load_settings().get("language", "en")
        reply = parsed["reply_hi"] if lang == "hi" else parsed["reply_en"]

        if act == "stop_reading":
            backend_main.speaker.stop()
            return
        if act == "blocked_dangerous":
            self.ui.request_open_chat("", False)
            backend_main.speaker.speak(reply, lang)
            return
        if act == "check_clipboard":
            clip = pyperclip.paste().strip()
            if clip:
                backend_main.state.enqueue({"type": "text", "source": "Voice Clipboard Check", "content": clip})
            backend_main.speaker.speak(reply, lang)
            return
        if act in ("read_last_alert", "what_is_wrong"):
            self.ui.request_open_drawer()
            with backend_main.state.lock:
                latest = backend_main.state.judged_feed[0] if backend_main.state.judged_feed else None
            if latest:
                speech = build_alert_speech_text(latest.get("analysis", {}), lang)
                backend_main.speaker.speak(speech, lang)
            else:
                backend_main.speaker.speak("No alerts found yet." if lang == "en" else "अभी कोई अलर्ट नहीं है।", lang)
            return
        if act == "explain_in_hindi":
            save_settings({"language": "hi"})
            self.ui.request_open_drawer()
            backend_main.speaker.speak(parsed["reply_hi"], "hi")
            return
        if act == "explain_in_english":
            save_settings({"language": "en"})
            self.ui.request_open_drawer()
            backend_main.speaker.speak(parsed["reply_en"], "en")
            return
        if act == "pause_minutes":
            mins = int(parsed["params"].get("minutes", 15))
            self._on_tray_pause_change(True, mins)
            backend_main.speaker.speak(reply, lang)
            return
        if act == "resume":
            self._on_tray_pause_change(False, 0)
            backend_main.speaker.speak(reply, lang)
            return
        if act == "open_dashboard":
            webbrowser.open(DASHBOARD_URL)
            backend_main.speaker.speak(reply, lang)
            return
        if act == "ask_chatbot":
            # Send to chatbot and speak reply aloud ONCE because user used push-to-talk
            self.ui.request_open_chat(initial_context=transcript, speak_reply=True)

    def _trigger_cli_demo(self) -> None:
        time.sleep(2.5)
        for label, text in backend_main.DEMO_SAMPLES:
            backend_main.state.enqueue({"type": "text", "source": label, "content": text})

    def _on_item_judged(self, record: dict[str, Any]) -> None:
        if self.ui is not None:
            self.ui.push_judged_record(record)
        analysis = record.get("analysis", {})
        if analysis.get("is_suspicious") and analysis.get("overall_risk_score") == "High":
            lang = load_settings().get("language", "en")
            calm = analysis.get("calm_down_message_hi" if lang == "hi" else "calm_down_message") or analysis.get("calm_down_message", "")
            cat = analysis.get("fraud_category", "High Risk Threat")
            send_high_risk_windows_toast(f"⚠️ TrustLens: {cat}", calm, DASHBOARD_URL)

    def _on_ui_badge_change(self, color: str, unread_count: int) -> None:
        if self.tray is not None:
            self.tray.update_visual_state(color, unread_count)

    def _on_tray_pause_change(self, paused: bool, minutes: int) -> None:
        if paused:
            backend_main.speaker.stop()
        if backend_main.collector_manager is not None:
            backend_main.collector_manager.set_paused(paused, duration_seconds=minutes * 60)

    def shutdown(self) -> None:
        log.info("Shutdown requested from system tray.")
        if self.ui is not None:
            self.ui.request_shutdown()

    def _cleanup(self) -> None:
        log.info("Performing clean shutdown of collectors, Uvicorn, tray, PTT, and mutex...")
        if self.ptt is not None:
            self.ptt.stop()
        backend_main.speaker.shutdown()
        if backend_main.collector_manager is not None:
            backend_main.collector_manager.stop()
        if self.uvicorn_server is not None:
            self.uvicorn_server.should_exit = True
        if self.tray is not None:
            self.tray.stop()
        self.guard.release()
        log.info("TrustLens AI exited cleanly.")


if __name__ == "__main__":
    UnifiedApplication().start()
