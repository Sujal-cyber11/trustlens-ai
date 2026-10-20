"""CustomTkinter ambient desktop UI for TrustLens AI.

Fixes included (BUG 3):
- Tags all copied cybercrime report strings with TRUSTLENS_INTERNAL_MARKER ('[TL_INTERNAL]')
  so the background clipboard collector never re-scans text copied from the TrustLens UI.
"""
from __future__ import annotations

from collections import deque
import logging
import os
import queue
import threading
from typing import Any, Callable
import webbrowser

import customtkinter as ctk
import pyperclip
import requests

from collectors import get_extension_token, load_settings, save_settings
from heuristics import TRUSTLENS_INTERNAL_MARKER

log = logging.getLogger("trustlens.ui")

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

API_BASE = f"http://127.0.0.1:{os.environ.get('TRUSTLENS_PORT', '8000')}"


class FirstRunConsentDialog(ctk.CTkToplevel):
    """First-run privacy & source consent dialog."""

    def __init__(self, master: ctk.CTk, on_complete: Callable[[], None]) -> None:
        super().__init__(master)
        self.on_complete = on_complete
        self.title("TrustLens AI — Privacy & Protection Setup")
        self.geometry("540x450")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.configure(fg_color="#0B1120")

        ctk.CTkLabel(
            self,
            text="🛡️ Welcome to TrustLens AI Guardian",
            font=("Segoe UI", 18, "bold"),
            text_color="#14B8A6",
        ).pack(anchor="w", padx=20, pady=(18, 6))

        ctk.CTkLabel(
            self,
            text=(
                "TrustLens runs quietly in the background to protect you from phishing links, "
                "visual homoglyphs (arnazon.com), UPI collect traps, and web dark patterns.\n\n"
                "🔒 Privacy Guarantee: Phone numbers, card numbers, emails, and OTPs are automatically "
                "redacted ([REDACTED]) on your device BEFORE any cloud AI check."
            ),
            font=("Segoe UI", 12),
            text_color="#CBD5E1",
            wraplength=495,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 12))

        settings = load_settings()
        self.var_notif = ctk.BooleanVar(value=bool(settings.get("monitor_notifications", True)))
        self.var_clip = ctk.BooleanVar(value=bool(settings.get("monitor_clipboard_text", True)))
        self.var_screen = ctk.BooleanVar(value=bool(settings.get("monitor_screenshots", True)))
        self.var_autostart = ctk.BooleanVar(value=bool(settings.get("start_with_windows", True)))

        box = ctk.CTkFrame(self, fg_color="#1E293B", corner_radius=10)
        box.pack(fill="x", padx=20, pady=6)

        ctk.CTkSwitch(box, text="Monitor Windows Toast Notifications", variable=self.var_notif, font=("Segoe UI", 12, "bold")).pack(
            anchor="w", padx=16, pady=(12, 6)
        )
        ctk.CTkSwitch(box, text="Monitor Copied Text & Links (Ctrl+C)", variable=self.var_clip, font=("Segoe UI", 12, "bold")).pack(
            anchor="w", padx=16, pady=6
        )
        ctk.CTkSwitch(box, text="Monitor Clipboard & Folder Screenshots", variable=self.var_screen, font=("Segoe UI", 12, "bold")).pack(
            anchor="w", padx=16, pady=6
        )
        ctk.CTkSwitch(box, text="Start TrustLens Automatically with Windows", variable=self.var_autostart, font=("Segoe UI", 12, "bold")).pack(
            anchor="w", padx=16, pady=(6, 12)
        )

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(16, 16), side="bottom")

        ctk.CTkButton(
            btn_row,
            text="✅ Enable Ambient Protection",
            fg_color="#0D9488",
            hover_color="#0F766E",
            height=40,
            font=("Segoe UI", 13, "bold"),
            command=self._save_and_close,
        ).pack(fill="x")

    def _save_and_close(self) -> None:
        save_settings({
            "consent_given": True,
            "monitor_notifications": self.var_notif.get(),
            "monitor_clipboard_text": self.var_clip.get(),
            "monitor_screenshots": self.var_screen.get(),
            "start_with_windows": self.var_autostart.get(),
        })
        self.destroy()
        self.on_complete()


class FloatingBadgeWindow(ctk.CTkToplevel):
    """Small floating shield icon that stays hidden until at least one unread threat exists."""

    def __init__(self, master: ctk.CTk, on_click: Callable[[], None]) -> None:
        super().__init__(master)
        self.on_click = on_click
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.width = 62
        self.height = 62

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = screen_w - self.width - 24
        y = screen_h - self.height - 72
        self.geometry(f"{self.width}x{self.height}+{x}+{y}")
        self.configure(fg_color="#0B1120")

        self.shield_btn = ctk.CTkButton(
            self,
            text="🛡️",
            width=58,
            height=58,
            corner_radius=29,
            fg_color="#991B1B",
            hover_color="#DC2626",
            border_width=2,
            border_color="#FCA5A5",
            font=("Segoe UI", 22),
            command=self.on_click,
        )
        self.shield_btn.pack(expand=True, fill="both", padx=2, pady=2)

        self.count_lbl = ctk.CTkLabel(
            self,
            text="1",
            width=24,
            height=24,
            fg_color="#EF4444",
            text_color="#FFFFFF",
            corner_radius=12,
            font=("Segoe UI", 11, "bold"),
        )
        self.count_lbl.place(x=36, y=2)
        self.withdraw()

    def update_count(self, unread_count: int) -> None:
        if unread_count <= 0:
            self.withdraw()
        else:
            self.count_lbl.configure(text=str(unread_count))
            self.deiconify()
            self.lift()


class ThreatExplanationDrawer(ctk.CTkToplevel):
    """Scrollable explanation popup showing all unread threats (newest first) with full text, EN/HI, and actions."""

    def __init__(self, master: AmbientDesktopUI) -> None:
        super().__init__(master)
        self.ui = master
        self.title("TrustLens AI — Threat Explanation & Guidance")
        self.width = 540
        self.height = 620

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = screen_w - self.width - 28
        y = screen_h - self.height - 85
        self.geometry(f"{self.width}x{self.height}+{x}+{y}")
        self.attributes("-topmost", True)
        self.configure(fg_color="#0B1120")
        self.protocol("WM_DELETE_WINDOW", self.close_drawer)

        self.current_index = 0
        self.lang = load_settings().get("language", "en")

        top = ctk.CTkFrame(self, fg_color="#1E293B", corner_radius=8)
        top.pack(fill="x", padx=12, pady=(12, 6))

        self.nav_lbl = ctk.CTkLabel(top, text="Threat 1 of 1", font=("Segoe UI", 13, "bold"), text_color="#F8FAFC")
        self.nav_lbl.pack(side="left", padx=12, pady=8)

        ctk.CTkButton(
            top, text="Next ▶", width=64, height=28, fg_color="#334155", command=self.next_threat
        ).pack(side="right", padx=(4, 10), pady=6)
        ctk.CTkButton(
            top, text="◀ Prev", width=64, height=28, fg_color="#334155", command=self.prev_threat
        ).pack(side="right", padx=4, pady=6)

        self.lang_btn = ctk.CTkButton(
            top,
            text="🌐 हिंदी" if self.lang == "en" else "🌐 English",
            width=80,
            height=28,
            fg_color="#0D9488",
            command=self.toggle_language,
        )
        self.lang_btn.pack(side="right", padx=6, pady=6)

        self.scroll = ctk.CTkScrollableFrame(self, fg_color="#0F172A", corner_radius=8)
        self.scroll.pack(fill="both", expand=True, padx=12, pady=6)

        self.risk_banner = ctk.CTkFrame(self.scroll, fg_color="#991B1B", corner_radius=8)
        self.risk_banner.pack(fill="x", padx=6, pady=(6, 8))

        self.risk_title = ctk.CTkLabel(
            self.risk_banner,
            text="⚠️ HIGH RISK",
            font=("Segoe UI", 15, "bold"),
            text_color="#FFFFFF",
            wraplength=470,
            justify="left",
        )
        self.risk_title.pack(anchor="w", padx=12, pady=10)

        self.calm_lbl = self._add_section("🧘 Calm-Down Reality Check", "#38BDF8")
        self.about_lbl = self._add_section("📌 What This Input Is About", "#CBD5E1")
        self.seems_lbl = self._add_section("🎭 What It Seems To Be (Disguise vs. Reality)", "#FBBF24")
        self.affects_lbl = self._add_section("💥 How It Affects You", "#F87171")
        self.actions_lbl = self._add_section("✅ Recommended Safe Actions", "#6EE7B7")
        self.indicators_lbl = self._add_section("🔍 Technical Indicators & Score Math", "#94A3B8")

        ctk.CTkLabel(
            self,
            text="🔒 Privacy: Phone numbers, card numbers, emails & OTPs are redacted locally before cloud analysis.",
            font=("Segoe UI", 10.5),
            text_color="#64748B",
        ).pack(padx=12, pady=(2, 2))

        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=12, pady=(4, 12))

        ctk.CTkButton(
            bottom,
            text="✅ This Was Safe (False Positive)",
            fg_color="#065F46",
            hover_color="#047857",
            height=34,
            font=("Segoe UI", 11.5, "bold"),
            command=lambda: self.submit_feedback("false_positive"),
        ).pack(side="left", expand=True, fill="x", padx=(0, 4))

        ctk.CTkButton(
            bottom,
            text="🚨 Confirm Scam",
            fg_color="#334155",
            hover_color="#475569",
            height=34,
            font=("Segoe UI", 11.5, "bold"),
            command=lambda: self.submit_feedback("confirm_scam"),
        ).pack(side="left", expand=True, fill="x", padx=4)

        ctk.CTkButton(
            bottom,
            text="📞 Report (1930 / Cybercrime)",
            fg_color="#DC2626",
            hover_color="#B91C1C",
            height=34,
            font=("Segoe UI", 11.5, "bold"),
            command=self.report_to_cybercrime,
        ).pack(side="right", expand=True, fill="x", padx=(4, 0))

        self.render_current()

    def _add_section(self, heading: str, color: str) -> ctk.CTkLabel:
        frame = ctk.CTkFrame(self.scroll, fg_color="#1E293B", corner_radius=8)
        frame.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(frame, text=heading, font=("Segoe UI", 12, "bold"), text_color=color).pack(
            anchor="w", padx=12, pady=(8, 2)
        )
        lbl = ctk.CTkLabel(
            frame,
            text="",
            font=("Segoe UI", 12),
            text_color="#F8FAFC",
            wraplength=465,
            justify="left",
        )
        lbl.pack(anchor="w", padx=12, pady=(2, 10))
        return lbl

    def toggle_language(self) -> None:
        self.lang = "hi" if self.lang == "en" else "en"
        save_settings({"language": self.lang})
        self.lang_btn.configure(text="🌐 हिंदी" if self.lang == "en" else "🌐 English")
        self.render_current()

    def prev_threat(self) -> None:
        if self.ui.unread_threats and self.current_index > 0:
            self.current_index -= 1
            self.render_current()

    def next_threat(self) -> None:
        if self.ui.unread_threats and self.current_index < len(self.ui.unread_threats) - 1:
            self.current_index += 1
            self.render_current()

    def render_current(self) -> None:
        items = list(self.ui.unread_threats)
        if not items:
            self.close_drawer()
            return
        self.current_index = max(0, min(self.current_index, len(items) - 1))
        item = items[self.current_index]
        analysis = item.get("analysis", {})
        risk = analysis.get("overall_risk_score", "High")
        score = analysis.get("numeric_risk_score", 85)
        mal_s = analysis.get("malicious_score", score)
        dp_s = analysis.get("dark_pattern_score", 0)
        cat = analysis.get("fraud_category", "Suspicious Activity")
        src = item.get("source", "Background")
        ts = item.get("timestamp", "")

        self.nav_lbl.configure(text=f"Threat {self.current_index + 1} of {len(items)}  •  {src} ({ts})")
        self.risk_banner.configure(fg_color="#991B1B" if risk == "High" else "#B45309")
        self.risk_title.configure(
            text=f"⚠️ {risk.upper()} RISK ({score}/100) — {cat}\n[Malicious: {mal_s}/100 | Dark Patterns: {dp_s}/100]"
        )

        use_hi = self.lang == "hi"
        calm = analysis.get("calm_down_message_hi" if use_hi else "calm_down_message") or analysis.get("calm_down_message", "")
        about = analysis.get("what_input_is_about_hi" if use_hi else "what_input_is_about") or analysis.get("what_input_is_about", "")
        seems = analysis.get("what_it_seems_to_be_hi" if use_hi else "what_it_seems_to_be") or analysis.get("what_it_seems_to_be", "")
        affects = analysis.get("how_it_affects_user_hi" if use_hi else "how_it_affects_user") or analysis.get("how_it_affects_user", "")
        acts = analysis.get("recommended_actions_hi" if use_hi else "recommended_actions") or analysis.get("recommended_actions", [])

        self.calm_lbl.configure(text=calm)
        self.about_lbl.configure(text=f"{about}\n\nRedacted Payload: {item.get('input', '')}")
        self.seems_lbl.configure(text=seems)
        self.affects_lbl.configure(text=affects)
        self.actions_lbl.configure(text="\n".join(f"✔ {a}" for a in acts))

        inds = analysis.get("indicators", [])
        ind_lines = [
            f"• [{i.get('severity')}] {i.get('indicator_type')}: {i.get('target_element')} — {i.get('explanation')}"
            for i in inds
        ]
        ind_lines.append(f"\nScore Math: {analysis.get('confidence_score_explanation', '')}")
        ind_lines.append(f"Auto-Calibration: {analysis.get('auto_calibration_action', '')}")
        self.indicators_lbl.configure(text="\n".join(ind_lines))

    def submit_feedback(self, fb_type: str) -> None:
        items = list(self.ui.unread_threats)
        if not items:
            return
        item = items[self.current_index]
        heur = item.get("heuristics", {})
        dom = heur.get("domain") or None

        def _post() -> None:
            try:
                requests.post(
                    f"{API_BASE}/api/feedback",
                    headers={"X-TrustLens-Token": get_extension_token()},
                    json={
                        "item_id": item.get("id", ""),
                        "input_snippet": dom or "",
                        "domain": dom,
                        "feedback_type": fb_type,
                        "lesson_note": f"Verified {fb_type} on domain {dom}" if dom else "",
                    },
                    timeout=5.0,
                )
            except requests.RequestException as e:
                log.warning("Feedback submission failed: %s", e)

        threading.Thread(target=_post, daemon=True).start()
        del self.ui.unread_threats[self.current_index]
        self.ui.sync_badge()
        self.render_current()

    def report_to_cybercrime(self) -> None:
        items = list(self.ui.unread_threats)
        if not items:
            return
        item = items[self.current_index]
        analysis = item.get("analysis", {})
        report_text = (
            f"{TRUSTLENS_INTERNAL_MARKER} === TRUSTLENS AI CYBERCRIME INCIDENT REPORT ===\n"
            f"Timestamp: {item.get('timestamp')}\n"
            f"Source Channel: {item.get('source')}\n"
            f"Risk Score: {analysis.get('overall_risk_score')} ({analysis.get('numeric_risk_score')}/100)\n"
            f"Category: {analysis.get('fraud_category')}\n"
            f"Redacted Content: {item.get('input')}\n"
            f"Summary: {analysis.get('what_it_seems_to_be')}\n"
            "National Cyber Crime Helpline: 1930 | Portal: https://cybercrime.gov.in\n"
        )
        try:
            pyperclip.copy(report_text)
        except Exception as e:
            log.debug("Could not copy report to clipboard: %s", e)
        webbrowser.open("https://cybercrime.gov.in")

    def close_drawer(self) -> None:
        self.ui.unread_threats.clear()
        self.ui.sync_badge()
        self.destroy()


class AmbientDesktopUI(ctk.CTk):
    """Withdrawn main Tk root coordinating the floating badge, explanation drawer, and thread-safe UI queue."""

    def __init__(self, on_status_change: Callable[[str, int], None] | None = None) -> None:
        super().__init__()
        self.withdraw()
        self.on_status_change = on_status_change
        self.ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.unread_threats: deque[dict[str, Any]] = deque(maxlen=50)
        self.history_threats: deque[dict[str, Any]] = deque(maxlen=100)
        self.badge = FloatingBadgeWindow(self, on_click=self.open_explanation_drawer)
        self.drawer: ThreatExplanationDrawer | None = None

        self.after(250, self._process_ui_queue)
        self.after(400, self._check_consent_on_startup)

    def _check_consent_on_startup(self) -> None:
        settings = load_settings()
        if not settings.get("consent_given", False):
            FirstRunConsentDialog(self, on_complete=lambda: log.info("First-run consent completed."))

    def push_judged_record(self, record: dict[str, Any]) -> None:
        self.ui_queue.put(("record", record))

    def request_open_drawer(self) -> None:
        self.ui_queue.put(("open_drawer", None))

    def request_shutdown(self) -> None:
        self.ui_queue.put(("shutdown", None))

    def _process_ui_queue(self) -> None:
        try:
            while True:
                cmd, payload = self.ui_queue.get_nowait()
                if cmd == "record":
                    self._handle_record_on_main_thread(payload)
                elif cmd == "open_drawer":
                    self.open_explanation_drawer()
                elif cmd == "shutdown":
                    self.destroy()
                    return
        except queue.Empty:
            pass
        self.after(250, self._process_ui_queue)

    def _handle_record_on_main_thread(self, record: dict[str, Any]) -> None:
        self.history_threats.appendleft(record)
        analysis = record.get("analysis", {})
        if analysis.get("is_suspicious") and analysis.get("overall_risk_score") in ("High", "Medium"):
            self.unread_threats.appendleft(record)
            self.sync_badge()
            if self.drawer is not None and self.drawer.winfo_exists():
                self.drawer.current_index = 0
                self.drawer.render_current()

    def sync_badge(self) -> None:
        count = len(self.unread_threats)
        self.badge.update_count(count)
        if self.on_status_change is not None:
            self.on_status_change("red" if count > 0 else "green", count)

    def open_explanation_drawer(self) -> None:
        if not self.unread_threats and self.history_threats:
            self.unread_threats.appendleft(self.history_threats[0])
        if not self.unread_threats:
            webbrowser.open(API_BASE)
            return
        if self.drawer is not None and self.drawer.winfo_exists():
            self.drawer.deiconify()
            self.drawer.lift()
            self.drawer.render_current()
        else:
            self.drawer = ThreatExplanationDrawer(self)
