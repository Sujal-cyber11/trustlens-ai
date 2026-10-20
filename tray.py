"""System tray controller for TrustLens AI (with Voice Push-to-Talk & Auto-Read toggles)."""
from __future__ import annotations

import logging
import os
import sys
import threading
from typing import Any, Callable
import webbrowser

from PIL import Image, ImageDraw
import pyperclip
import pystray

from collectors import get_extension_token, load_settings, save_settings
from voice_assistant import VOICE_STACK_AVAILABLE, get_voice_availability_message

log = logging.getLogger("trustlens.tray")

if sys.platform == "win32":
    import winreg
    try:
        from winotify import Notification, audio
    except ImportError:
        Notification = None
        audio = None
else:
    winreg = None
    Notification = None
    audio = None

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_NAME = "TrustLensAI"


def is_autostart_enabled() -> bool:
    if sys.platform != "win32" or winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_REG_NAME)
            return bool(val)
    except OSError:
        return False


def set_autostart_enabled(enabled: bool) -> bool:
    if sys.platform != "win32" or winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                script_path = os.path.abspath(sys.argv[0])
                if getattr(sys, "frozen", False):
                    cmd = f'"{sys.executable}"'
                else:
                    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
                    runner = pythonw if os.path.exists(pythonw) else sys.executable
                    cmd = f'"{runner}" "{script_path}"'
                winreg.SetValueEx(key, APP_REG_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, APP_REG_NAME)
                except OSError:
                    pass
        save_settings({"start_with_windows": enabled})
        log.info("Windows autostart registry updated: enabled=%s", enabled)
        return True
    except OSError as e:
        log.error("Failed to modify Windows Run registry key: %s", e)
        return False


def _create_shield_icon(state_color: str) -> Image.Image:
    palette = {
        "green": (16, 185, 129),
        "red": (239, 68, 68),
        "grey": (100, 116, 139),
    }
    fill_rgb = palette.get(state_color, palette["green"])
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([4, 4, 60, 60], fill=(15, 23, 42, 255), outline=fill_rgb, width=4)
    draw.polygon([(32, 14), (48, 20), (45, 39), (32, 50), (19, 39), (16, 20)], fill=fill_rgb)
    return img


def send_high_risk_windows_toast(title: str, message: str, dashboard_url: str) -> None:
    if sys.platform != "win32" or Notification is None:
        return
    try:
        toast = Notification(
            app_id="TrustLens AI Guardian",
            title=title[:64],
            msg=message[:200],
            duration="short",
            launch=dashboard_url,
        )
        if audio is not None:
            toast.set_audio(audio.Default, loop=False)
        toast.show()
    except Exception as e:
        log.debug("Native Windows toast error: %s", e)


class TrayManager:
    """Manages the pystray system tray icon and menu options, including Voice Push-to-Talk switch."""

    def __init__(
        self,
        dashboard_url: str,
        on_open_alerts: Callable[[], None],
        on_open_chat: Callable[[], None],
        on_pause_change: Callable[[bool, int], None],
        on_quit: Callable[[], None],
    ) -> None:
        self.dashboard_url = dashboard_url
        self.on_open_alerts = on_open_alerts
        self.on_open_chat = on_open_chat
        self.on_pause_change = on_pause_change
        self.on_quit = on_quit
        self.state_color = "green"
        self.unread_count = 0
        self.is_paused = False
        self.icon: pystray.Icon | None = None

    def start_in_thread(self) -> None:
        voice_label = (
            "Voice Push-to-Talk (Hold Ctrl+Alt+T)"
            if VOICE_STACK_AVAILABLE
            else "Voice Push-to-Talk (Packages not installed)"
        )
        menu = pystray.Menu(
            pystray.MenuItem("Open Dashboard", self._open_dashboard, default=True),
            pystray.MenuItem("Recent Alerts / Explanation Card", lambda icon, item: self.on_open_alerts()),
            pystray.MenuItem("Ask TrustLens (Chat Helper)", lambda icon, item: self.on_open_chat()),
            pystray.MenuItem(
                voice_label,
                self._toggle_voice,
                checked=lambda item: bool(load_settings().get("voice_enabled", False)) and VOICE_STACK_AVAILABLE,
                enabled=VOICE_STACK_AVAILABLE,
            ),
            pystray.MenuItem(
                "Auto-Read High-Risk Alerts Aloud",
                self._toggle_auto_read,
                checked=lambda item: bool(load_settings().get("auto_read_high_risk", False)),
            ),
            pystray.MenuItem("Copy Extension Token", self._copy_extension_token),
            pystray.MenuItem("Pause Protection for 15 Min", self._pause_15m),
            pystray.MenuItem(
                lambda item: "Resume Protection" if self.is_paused else "Pause Until Resumed",
                self._toggle_pause,
            ),
            pystray.MenuItem(
                "Start with Windows",
                self._toggle_autostart,
                checked=lambda item: is_autostart_enabled(),
            ),
            pystray.MenuItem(
                lambda item: f"Language: {'हिंदी (HI)' if load_settings().get('language') == 'hi' else 'English (EN)'}",
                self._toggle_language,
            ),
            pystray.MenuItem("Quit TrustLens AI", self._quit),
        )
        self.icon = pystray.Icon(
            "TrustLensAI",
            _create_shield_icon("green"),
            "TrustLens AI — Watching (All Clear)",
            menu,
        )
        threading.Thread(target=self.icon.run, name="TrustLensTray", daemon=True).start()

    def _toggle_voice(self, icon: Any, item: Any) -> None:
        if not VOICE_STACK_AVAILABLE:
            send_high_risk_windows_toast("TrustLens Voice", get_voice_availability_message("en"), self.dashboard_url)
            return
        curr = bool(load_settings().get("voice_enabled", False))
        save_settings({"voice_enabled": not curr})
        if self.icon is not None:
            self.icon.update_menu()

    def _toggle_auto_read(self, icon: Any, item: Any) -> None:
        curr = bool(load_settings().get("auto_read_high_risk", False))
        save_settings({"auto_read_high_risk": not curr})
        if self.icon is not None:
            self.icon.update_menu()

    def _copy_extension_token(self, icon: Any, item: Any) -> None:
        tok = get_extension_token()
        try:
            pyperclip.copy(tok)
            log.info("Extension token copied to clipboard via tray menu.")
            send_high_risk_windows_toast(
                "🔑 Extension Token Copied",
                "Paste this token into the TrustLens Browser Extension Options page.",
                self.dashboard_url,
            )
        except Exception as e:
            log.warning("Could not copy extension token to clipboard: %s", e)

    def update_visual_state(self, color: str, unread_count: int = 0) -> None:
        self.unread_count = unread_count
        if self.is_paused:
            self.state_color = "grey"
            title = "TrustLens AI — Paused"
        elif unread_count > 0 or color == "red":
            self.state_color = "red"
            title = f"TrustLens AI — {unread_count} Unread Threat(s)"
        else:
            self.state_color = "green"
            title = "TrustLens AI — Watching (All Clear)"

        if self.icon is not None:
            try:
                self.icon.icon = _create_shield_icon(self.state_color)
                self.icon.title = title
            except Exception as e:
                log.debug("Tray icon update note: %s", e)

    def _open_dashboard(self, icon: Any, item: Any) -> None:
        webbrowser.open(self.dashboard_url)

    def _pause_15m(self, icon: Any, item: Any) -> None:
        self.is_paused = True
        self.on_pause_change(True, 15)
        self.update_visual_state("grey", self.unread_count)

    def _toggle_pause(self, icon: Any, item: Any) -> None:
        self.is_paused = not self.is_paused
        self.on_pause_change(self.is_paused, 0)
        self.update_visual_state("grey" if self.is_paused else "green", self.unread_count)

    def _toggle_autostart(self, icon: Any, item: Any) -> None:
        curr = is_autostart_enabled()
        set_autostart_enabled(not curr)

    def _toggle_language(self, icon: Any, item: Any) -> None:
        curr = load_settings().get("language", "en")
        new_lang = "hi" if curr == "en" else "en"
        save_settings({"language": new_lang})
        if self.icon is not None:
            self.icon.update_menu()

    def _quit(self, icon: Any, item: Any) -> None:
        if self.icon is not None:
            self.icon.stop()
        self.on_quit()

    def stop(self) -> None:
        if self.icon is not None:
            try:
                self.icon.stop()
            except Exception as e:
                log.debug("Tray stop note: %s", e)
