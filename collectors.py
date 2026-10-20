"""Supervised, crash-resilient OS background collectors for TrustLens AI.

Monitors:
1. Windows Toast Notifications (tries winsdk UserNotificationListener first, falls back to
   copying %LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpndatabase.db + -wal + -shm).
2. System Clipboard Text (pyperclip, 1.0s interval, skips trivial short numbers, LRU deduped).
3. System Clipboard Images (PIL.ImageGrab.grabclipboard, 2.0s interval, SHA-256 deduped).
4. User Screenshots Directory (watchdog observer on %USERPROFILE%\\Pictures\\Screenshots).
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from typing import Any, Callable
import xml.etree.ElementTree as ET

from PIL import ImageGrab
import pyperclip
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

log = logging.getLogger("trustlens.collectors")

SETTINGS_PATH = Path(os.path.expandvars(r"%LOCALAPPDATA%\TrustLens\settings.json"))

DEFAULT_SETTINGS: dict[str, Any] = {
    "consent_given": False,
    "monitor_notifications": True,
    "monitor_clipboard_text": True,
    "monitor_screenshots": True,
    "start_with_windows": True,
    "language": "en",
    "paused_until": 0.0,
}

_settings_lock = threading.RLock()


def load_settings() -> dict[str, Any]:
    """Loads user consent and source preferences from %LOCALAPPDATA%\\TrustLens\\settings.json."""
    with _settings_lock:
        if not SETTINGS_PATH.exists():
            return dict(DEFAULT_SETTINGS)
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            merged = dict(DEFAULT_SETTINGS)
            if isinstance(raw, dict):
                merged.update(raw)
            return merged
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Could not read settings.json (%s); using defaults.", e)
            return dict(DEFAULT_SETTINGS)


def save_settings(new_settings: dict[str, Any]) -> bool:
    """Atomically writes user settings to %LOCALAPPDATA%\\TrustLens\\settings.json."""
    with _settings_lock:
        try:
            SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
            merged = load_settings()
            merged.update(new_settings)
            fd, tmp_path = tempfile.mkstemp(dir=str(SETTINGS_PATH.parent), prefix=".settings_", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(merged, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, str(SETTINGS_PATH))
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            return True
        except OSError as e:
            log.error("Failed to save settings.json: %s", e)
            return False


class BoundedSet:
    """Thread-safe FIFO-bounded set to prevent unbounded memory growth."""

    def __init__(self, max_items: int = 2000) -> None:
        self.max_items = max_items
        self._data: OrderedDict[Any, float] = OrderedDict()
        self._lock = threading.Lock()

    def add_if_new(self, key: Any) -> bool:
        """Returns True if key was not present and adds it; False if already seen."""
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                return False
            self._data[key] = time.monotonic()
            while len(self._data) > self.max_items:
                self._data.popitem(last=False)
            return True

    def seed(self, keys: list[Any]) -> None:
        with self._lock:
            now = time.monotonic()
            for k in keys[-self.max_items :]:
                self._data[k] = now
            while len(self._data) > self.max_items:
                self._data.popitem(last=False)


def parse_toast_xml(raw_payload: bytes | str) -> str:
    """Extracts all <text> nodes and attribution from a Windows toast XML payload."""
    text_str = raw_payload.decode("utf-8", errors="ignore") if isinstance(raw_payload, bytes) else str(raw_payload)
    text_str = text_str.strip()
    if not text_str:
        return ""
    try:
        root = ET.fromstring(text_str)
        texts: list[str] = []
        for elem in root.iter("text"):
            if elem.text and elem.text.strip():
                texts.append(elem.text.strip())
        if texts:
            return " — ".join(texts)
    except ET.ParseError:
        chunks = re.findall(r"<text[^>]*>(.*?)</text>", text_str, flags=re.DOTALL | re.IGNORECASE)
        cleaned = [re.sub(r"<[^>]+>", "", c).strip() for c in chunks if c and c.strip()]
        if cleaned:
            return " — ".join(cleaned)
    return ""


class _ScreenshotFolderHandler(FileSystemEventHandler):
    """Watchdog event handler that reads newly saved screenshot files."""

    def __init__(self, manager: CollectorManager) -> None:
        super().__init__()
        self.manager = manager

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        src_path = str(event.src_path)
        if not src_path.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            return
        if not self.manager.is_source_active("monitor_screenshots"):
            return
        threading.Thread(target=self._read_file_delayed, args=(src_path,), daemon=True).start()

    def _read_file_delayed(self, path: str) -> None:
        time.sleep(0.6)
        try:
            if not os.path.exists(path):
                return
            size = os.path.getsize(path)
            if size <= 0 or size > 8 * 1024 * 1024:
                return
            with open(path, "rb") as f:
                data = f.read()
            digest = hashlib.sha256(data).hexdigest()
            if self.manager.seen_images.add_if_new(digest):
                log.info("New screenshot file detected: %s", os.path.basename(path))
                self.manager.emit_event({
                    "type": "image",
                    "source": f"Screenshots Folder ({os.path.basename(path)})",
                    "content": data,
                    "mime_type": "image/png" if path.lower().endswith(".png") else "image/jpeg",
                })
        except OSError as e:
            log.warning("Could not read new screenshot %s: %s", path, e)


class CollectorManager:
    """Manages and supervises all background OS collectors with clean shutdown."""

    def __init__(self, on_event_callback: Callable[[dict[str, Any]], None]) -> None:
        self.on_event_callback = on_event_callback
        self._stop_event = threading.Event()
        self.seen_texts = BoundedSet(max_items=2000)
        self.seen_images = BoundedSet(max_items=500)
        self.seen_notifs = BoundedSet(max_items=3000)
        self._observer: Any = None
        self._threads: list[threading.Thread] = []
        self._manual_paused = False
        self._lock = threading.Lock()

    @property
    def paused(self) -> bool:
        with self._lock:
            if self._manual_paused:
                return True
        settings = load_settings()
        paused_until = float(settings.get("paused_until", 0.0) or 0.0)
        return time.time() < paused_until

    def set_paused(self, paused: bool, duration_seconds: int = 0) -> None:
        with self._lock:
            self._manual_paused = paused
        if paused and duration_seconds > 0:
            save_settings({"paused_until": time.time() + duration_seconds})
        elif not paused:
            save_settings({"paused_until": 0.0})
        log.info("Collector protection state updated: paused=%s (duration=%ds)", paused, duration_seconds)

    def is_source_active(self, setting_key: str) -> bool:
        if self._stop_event.is_set() or self.paused:
            return False
        settings = load_settings()
        if not settings.get("consent_given", False):
            return False
        return bool(settings.get(setting_key, True))

    def emit_event(self, item: dict[str, Any]) -> None:
        if not self._stop_event.is_set() and not self.paused:
            self.on_event_callback(item)

    def start(self) -> None:
        if self._threads:
            return
        self._stop_event.clear()
        self._seed_initial_state()

        workers = [
            ("ClipboardTextCollector", self._clipboard_text_worker),
            ("ClipboardImageCollector", self._clipboard_image_worker),
            ("WindowsNotificationCollector", self._notification_worker),
        ]
        for name, target in workers:
            t = threading.Thread(target=self._supervised_runner, args=(name, target), name=name, daemon=True)
            t.start()
            self._threads.append(t)

        self._start_screenshots_watchdog()
        log.info("All background collectors started (platform=%s).", sys.platform)

    def stop(self) -> None:
        self._stop_event.set()
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=2.0)
            except Exception as e:
                log.debug("Watchdog observer stop note: %s", e)
        log.info("All background collectors signaled to stop.")

    def _supervised_runner(self, name: str, worker_fn: Callable[[], None]) -> None:
        """Supervisor wrapper: logs exceptions and restarts crashed collector threads with backoff."""
        backoff = 1.0
        while not self._stop_event.is_set():
            try:
                worker_fn()
                break
            except Exception as e:
                log.exception("Collector thread %s crashed (%s); restarting in %.1fs", name, e, backoff)
                self._stop_event.wait(backoff)
                backoff = min(backoff * 2.0, 30.0)

    def _seed_initial_state(self) -> None:
        """Seeds initial clipboard content and existing notification IDs so startup does not re-scan old items."""
        try:
            initial_clip = pyperclip.paste().strip()
            if initial_clip:
                h = hashlib.sha256(initial_clip.encode("utf-8", errors="replace")).hexdigest()
                self.seen_texts.add_if_new(h)
        except Exception as e:
            log.debug("Initial clipboard seed note: %s", e)

        if sys.platform != "win32":
            return

        db_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db")
        if not os.path.exists(db_path):
            return
        tmp_dir = tempfile.mkdtemp(prefix="tl_seed_")
        try:
            for ext in ("", "-wal", "-shm"):
                src = db_path + ext
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(tmp_dir, "wpndatabase.db" + ext))
            conn = sqlite3.connect(os.path.join(tmp_dir, "wpndatabase.db"), timeout=3.0)
            try:
                cur = conn.cursor()
                cur.execute("SELECT Id FROM Notification ORDER BY Id ASC")
                ids = [row[0] for row in cur.fetchall() if row and row[0] is not None]
                self.seen_notifs.seed(ids)
                log.info("Seeded %d existing Windows notification IDs.", len(ids))
            finally:
                conn.close()
        except Exception as e:
            log.debug("Could not seed Windows notification DB: %s", e)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _clipboard_text_worker(self) -> None:
        last_raw = ""
        while not self._stop_event.is_set():
            if self.is_source_active("monitor_clipboard_text"):
                try:
                    curr = pyperclip.paste().strip()
                    if curr and curr != last_raw and 5 <= len(curr) <= 10_000:
                        last_raw = curr
                        # Skip trivial pure numbers (e.g. copying a 4-digit number or calculator output)
                        if not re.fullmatch(r"[\d\s.,+-]+", curr):
                            digest = hashlib.sha256(curr.encode("utf-8", errors="replace")).hexdigest()
                            if self.seen_texts.add_if_new(digest):
                                log.info("Clipboard text captured (%d chars).", len(curr))
                                self.emit_event({
                                    "type": "text",
                                    "source": "Clipboard (Ctrl+C)",
                                    "content": curr,
                                })
                except Exception as e:
                    log.debug("Clipboard text poll warning: %s", e)
            self._stop_event.wait(1.0)

    def _clipboard_image_worker(self) -> None:
        if sys.platform not in ("win32", "darwin"):
            return
        while not self._stop_event.is_set():
            if self.is_source_active("monitor_screenshots"):
                try:
                    clip_obj = ImageGrab.grabclipboard()
                    if clip_obj is not None and hasattr(clip_obj, "save"):
                        thumb = clip_obj.copy()
                        thumb.thumbnail((128, 128))
                        raw_thumb = thumb.tobytes()
                        digest = hashlib.sha256(raw_thumb).hexdigest()
                        if self.seen_images.add_if_new(digest):
                            buf = io.BytesIO()
                            clip_obj.convert("RGB").save(buf, format="PNG")
                            img_bytes = buf.getvalue()
                            if 100 < len(img_bytes) <= 8 * 1024 * 1024:
                                log.info("Clipboard screenshot captured (%d bytes).", len(img_bytes))
                                self.emit_event({
                                    "type": "image",
                                    "source": "Clipboard Screenshot (Win+Shift+S)",
                                    "content": img_bytes,
                                    "mime_type": "image/png",
                                })
                except Exception as e:
                    log.debug("Clipboard image poll warning: %s", e)
            self._stop_event.wait(2.0)

    def _try_winsdk_notifications(self) -> list[tuple[Any, str, str]] | None:
        """Optional primary method via winsdk UserNotificationListener; returns None if unavailable or denied."""
        if sys.platform != "win32":
            return None
        try:
            from winsdk.windows.ui.notifications import NotificationKinds
            from winsdk.windows.ui.notifications.management import (
                UserNotificationListener,
                UserNotificationListenerAccessStatus,
            )

            listener = UserNotificationListener.current
            if listener is None:
                return None
            access = listener.get_access_status()
            if access != UserNotificationListenerAccessStatus.ALLOWED:
                return None
            notifs = listener.get_notifications_async(NotificationKinds.TOAST).get()
            results: list[tuple[Any, str, str]] = []
            for n in notifs:
                n_id = f"winsdk_{n.id}"
                app_name = "Windows App"
                try:
                    if n.app_info and n.app_info.display_info:
                        app_name = n.app_info.display_info.display_name or app_name
                except Exception as e:
                    log.debug("winsdk app_info read note: %s", e)
                binding = n.notification.visual.get_binding("ToastGeneric")
                if binding:
                    elems = binding.get_text_elements()
                    text = " — ".join(el.text.strip() for el in elems if el.text and el.text.strip())
                    if len(text) >= 5:
                        results.append((n_id, app_name, text))
            return results
        except Exception as e:
            log.debug("winsdk notification listener unavailable (%s); using SQLite DB fallback.", e)
            return None

    def _poll_wpndatabase(self) -> list[tuple[Any, str, str]]:
        """Reads new toast rows by copying wpndatabase.db + -wal + -shm to a temp directory."""
        if sys.platform != "win32":
            return []
        db_path = os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db")
        if not os.path.exists(db_path):
            return []

        rows_out: list[tuple[Any, str, str]] = []
        tmp_dir = tempfile.mkdtemp(prefix="tl_wpn_")
        try:
            for ext in ("", "-wal", "-shm"):
                src = db_path + ext
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(tmp_dir, "wpndatabase.db" + ext))

            copied_db = os.path.join(tmp_dir, "wpndatabase.db")
            conn = sqlite3.connect(copied_db, timeout=3.0)
            try:
                cur = conn.cursor()
                try:
                    cur.execute(
                        """
                        SELECT n.Id, IFNULL(h.PrimaryId, 'Windows Notification'), n.Payload
                        FROM Notification n
                        LEFT JOIN NotificationHandler h ON n.HandlerId = h.RecordId
                        WHERE n.Payload IS NOT NULL
                        ORDER BY n.Id ASC
                        """
                    )
                    fetched = cur.fetchall()[-25:]
                except sqlite3.OperationalError:
                    cur.execute("SELECT Id, 'Windows Notification', Payload FROM Notification WHERE Payload IS NOT NULL ORDER BY Id ASC")
                    fetched = cur.fetchall()[-25:]

                for r_id, handler_name, payload in fetched:
                    parsed_text = parse_toast_xml(payload)
                    if len(parsed_text) >= 5:
                        app_label = str(handler_name or "Windows Notification").split("!")[-1][:40]
                        rows_out.append((r_id, app_label, parsed_text))
            finally:
                conn.close()
        except Exception as e:
            log.debug("wpndatabase.db poll warning: %s", e)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        return rows_out

    def _notification_worker(self) -> None:
        if sys.platform != "win32":
            return
        while not self._stop_event.is_set():
            if self.is_source_active("monitor_notifications"):
                entries = self._try_winsdk_notifications()
                if entries is None:
                    entries = self._poll_wpndatabase()

                for notif_id, app_label, msg_text in entries:
                    if self.seen_notifs.add_if_new(notif_id):
                        # Also check text hash so identical toast updates don't spam
                        text_digest = hashlib.sha256(msg_text.encode("utf-8", errors="replace")).hexdigest()
                        if self.seen_texts.add_if_new(text_digest):
                            log.info("Windows Toast captured from %s: %s", app_label, msg_text[:60])
                            self.emit_event({
                                "type": "text",
                                "source": f"Notification ({app_label})",
                                "content": msg_text,
                            })
            self._stop_event.wait(2.5)

    def _start_screenshots_watchdog(self) -> None:
        candidates = [
            Path(os.path.expandvars(r"%USERPROFILE%\Pictures\Screenshots")),
            Path(os.path.expandvars(r"%USERPROFILE%\OneDrive\Pictures\Screenshots")),
        ]
        watched_any = False
        observer = Observer()
        for folder in candidates:
            if folder.exists() and folder.is_dir():
                try:
                    observer.schedule(_ScreenshotFolderHandler(self), str(folder), recursive=False)
                    watched_any = True
                    log.info("Watching Screenshots folder: %s", folder)
                except Exception as e:
                    log.warning("Could not watch folder %s: %s", folder, e)
        if watched_any:
            try:
                observer.daemon = True
                observer.start()
                self._observer = observer
            except Exception as e:
                log.warning("Failed to start watchdog observer: %s", e)
