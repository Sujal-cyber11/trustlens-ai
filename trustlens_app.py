"""Unified single-process background entry point for TrustLens AI.

Runnable with python.exe or pythonw.exe (zero console windows):
- Configures RotatingFileHandler at %LOCALAPPDATA%\\TrustLens\\logs\\trustlens.log.
- Enforces single-instance lock via Windows named mutex (or lockfile fallback);
  if a second instance is launched, brings the dashboard forward and exits cleanly.
- Runs the FastAPI Uvicorn server in a daemon thread bound to 127.0.0.1:8000.
- Runs the system tray icon (pystray) and withdrawn CustomTkinter UI in the same process.
"""
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

import uvicorn

from collectors import load_settings
from desktop_sentinel import AmbientDesktopUI
import main as backend_main
from tray import TrayManager, send_high_risk_windows_toast, set_autostart_enabled

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
    """Acquires a Windows named mutex and lockfile so a second launch opens the dashboard and exits."""

    def __init__(self) -> None:
        self.mutex_handle: Any = None
        self.lock_fd: int | None = None

    def acquire(self) -> bool:
        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32
            mutex_name = "Global\\TrustLensAISingleInstanceMutex_v2"
            handle = kernel32.CreateMutexW(None, True, mutex_name)
            last_err = kernel32.GetLastError()
            if last_err == 183:  # ERROR_ALREADY_EXISTS
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
    """Coordinates FastAPI Uvicorn server, collectors, tray icon, and CustomTkinter UI in one process."""

    def __init__(self) -> None:
        self.guard = SingleInstanceGuard()
        self.uvicorn_server: uvicorn.Server | None = None
        self.server_thread: threading.Thread | None = None
        self.ui: AmbientDesktopUI | None = None
        self.tray: TrayManager | None = None

    def start(self) -> None:
        if not self.guard.acquire():
            log.info("TrustLens AI is already running; opening dashboard in browser.")
            webbrowser.open(DASHBOARD_URL)
            sys.exit(0)

        log.info("Starting TrustLens AI unified process on %s", DASHBOARD_URL)
        settings = load_settings()
        if settings.get("consent_given") and settings.get("start_with_windows", True):
            set_autostart_enabled(True)

        # 1. Start FastAPI Uvicorn server in daemon thread
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

        # 2. Initialize withdrawn CustomTkinter UI on main thread
        self.ui = AmbientDesktopUI(on_status_change=self._on_ui_badge_change)

        # 3. Initialize System Tray icon
        self.tray = TrayManager(
            dashboard_url=DASHBOARD_URL,
            on_open_alerts=self.ui.request_open_drawer,
            on_pause_change=self._on_tray_pause_change,
            on_quit=self.shutdown,
        )
        self.tray.start_in_thread()

        # 4. Subscribe to real-time backend audit completions
        backend_main.register_alert_listener(self._on_item_judged)

        if "--demo" in sys.argv:
            threading.Thread(target=self._trigger_cli_demo, daemon=True).start()

        # Run Tk mainloop on main thread
        try:
            self.ui.mainloop()
        finally:
            self._cleanup()

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
        if backend_main.collector_manager is not None:
            backend_main.collector_manager.set_paused(paused, duration_seconds=minutes * 60)

    def shutdown(self) -> None:
        log.info("Shutdown requested from system tray.")
        if self.ui is not None:
            self.ui.request_shutdown()

    def _cleanup(self) -> None:
        log.info("Performing clean shutdown of collectors, Uvicorn, tray, and mutex...")
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
