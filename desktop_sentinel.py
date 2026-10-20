"""CustomTkinter ambient desktop UI for TrustLens AI (with 'Ask TrustLens' Chatbot, Offline SAPI Read-Aloud & Push-to-Talk Indicator)."""
from __future__ import annotations

from collections import deque
import logging
import os
import queue
import threading
import tkinter as tk
from typing import Any, Callable
import webbrowser

import customtkinter as ctk
import pyperclip
import requests

from collectors import get_extension_token, load_settings, save_settings
from heuristics import TRUSTLENS_INTERNAL_MARKER, default_verdict_line
from voice_assistant import (
    VOICE_STACK_AVAILABLE,
    OfflineSpeaker,
    build_alert_speech_text,
    get_voice_availability_message,
)

log = logging.getLogger("trustlens.ui")

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

API_BASE = f"http://127.0.0.1:{os.environ.get('TRUSTLENS_PORT', '8000')}"

SLICE_PALETTE: tuple[str, ...] = (
    "#EF4444",
    "#F97316",
    "#EAB308",
    "#A855F7",
    "#38BDF8",
    "#10B981",
)


class FirstRunConsentDialog(ctk.CTkToplevel):
    """Simple, non-technical first-run consent window including the Voice switch (OFF by default)."""

    def __init__(self, master: ctk.CTk, on_complete: Callable[[], None]) -> None:
        super().__init__(master)
        self.on_complete = on_complete
        self.title("TrustLens AI — Welcome")
        self.geometry("550x510")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.configure(fg_color="#0B1120")

        ctk.CTkLabel(
            self,
            text="🛡️ Welcome to TrustLens Helper",
            font=("Segoe UI", 20, "bold"),
            text_color="#14B8A6",
        ).pack(anchor="w", padx=20, pady=(18, 6))

        ctk.CTkLabel(
            self,
            text=(
                "TrustLens watches quietly in the background and warns you in simple words "
                "if a message, link, or screen looks like a scam.\n\n"
                "🔒 Your Privacy: Phone numbers, card numbers, emails, and OTPs are hidden "
                "on your computer before anything is checked."
            ),
            font=("Segoe UI", 14),
            text_color="#E2E8F0",
            wraplength=505,
            justify="left",
        ).pack(anchor="w", padx=20, pady=(0, 12))

        settings = load_settings()
        self.var_notif = ctk.BooleanVar(value=bool(settings.get("monitor_notifications", True)))
        self.var_clip = ctk.BooleanVar(value=bool(settings.get("monitor_clipboard_text", True)))
        self.var_screen = ctk.BooleanVar(value=bool(settings.get("monitor_screenshots", True)))
        self.var_voice = ctk.BooleanVar(value=False)  # Voice is OFF by default
        self.var_autostart = ctk.BooleanVar(value=bool(settings.get("start_with_windows", True)))

        box = ctk.CTkFrame(self, fg_color="#1E293B", corner_radius=10)
        box.pack(fill="x", padx=20, pady=6)

        ctk.CTkSwitch(box, text="Check Windows Notifications", variable=self.var_notif, font=("Segoe UI", 14, "bold")).pack(
            anchor="w", padx=16, pady=(12, 6)
        )
        ctk.CTkSwitch(box, text="Check Copied Text and Links (Ctrl+C)", variable=self.var_clip, font=("Segoe UI", 14, "bold")).pack(
            anchor="w", padx=16, pady=6
        )
        ctk.CTkSwitch(box, text="Check Screenshots", variable=self.var_screen, font=("Segoe UI", 14, "bold")).pack(
            anchor="w", padx=16, pady=6
        )
        voice_sw = ctk.CTkSwitch(
            box,
            text=(
                "Voice Push-to-Talk (Hold Ctrl+Alt+T — Off by default)"
                if VOICE_STACK_AVAILABLE
                else "Voice Push-to-Talk (Optional voice packages not installed)"
            ),
            variable=self.var_voice,
            font=("Segoe UI", 14, "bold"),
            state="normal" if VOICE_STACK_AVAILABLE else "disabled",
        )
        voice_sw.pack(anchor="w", padx=16, pady=6)

        ctk.CTkSwitch(box, text="Start Automatically with Windows", variable=self.var_autostart, font=("Segoe UI", 14, "bold")).pack(
            anchor="w", padx=16, pady=(6, 12)
        )

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(14, 16), side="bottom")

        ctk.CTkButton(
            btn_row,
            text="✅ Turn On Protection",
            fg_color="#0D9488",
            hover_color="#0F766E",
            height=44,
            font=("Segoe UI", 15, "bold"),
            command=self._save_and_close,
        ).pack(fill="x")

    def _save_and_close(self) -> None:
        save_settings({
            "consent_given": True,
            "monitor_notifications": self.var_notif.get(),
            "monitor_clipboard_text": self.var_clip.get(),
            "monitor_screenshots": self.var_screen.get(),
            "voice_enabled": bool(self.var_voice.get() and VOICE_STACK_AVAILABLE),
            "start_with_windows": self.var_autostart.get(),
        })
        self.destroy()
        self.on_complete()


class FloatingBadgeWindow(ctk.CTkToplevel):
    """Floating shield icon that stays hidden until an unread alert exists OR Push-to-Talk is listening."""

    def __init__(self, master: ctk.CTk, on_click: Callable[[], None]) -> None:
        super().__init__(master)
        self.on_click = on_click
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.width = 160
        self.height = 64

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = screen_w - self.width - 24
        y = screen_h - self.height - 72
        self.geometry(f"{self.width}x{self.height}+{x}+{y}")
        self.configure(fg_color="#0B1120")

        self.shield_btn = ctk.CTkButton(
            self,
            text="🛡️",
            width=156,
            height=60,
            corner_radius=30,
            fg_color="#991B1B",
            hover_color="#DC2626",
            border_width=2,
            border_color="#FCA5A5",
            font=("Segoe UI", 16, "bold"),
            command=self.on_click,
        )
        self.shield_btn.pack(expand=True, fill="both", padx=2, pady=2)
        self.unread_count = 0
        self.is_listening = False
        self.status_note = ""
        self.withdraw()

    def set_listening_state(self, listening: bool, status_text: str = "") -> None:
        self.is_listening = listening
        self.status_note = status_text
        self._refresh_visibility()

    def update_count(self, unread_count: int) -> None:
        self.unread_count = unread_count
        self._refresh_visibility()

    def _refresh_visibility(self) -> None:
        if self.is_listening:
            self.shield_btn.configure(text="🎤 Listening...", fg_color="#1D4ED8", border_color="#93C5FD")
            self.deiconify()
            self.lift()
        elif self.status_note:
            self.shield_btn.configure(text="⏳ Voice...", fg_color="#0F766E", border_color="#5EEAD4")
            self.deiconify()
            self.lift()
        elif self.unread_count > 0:
            self.shield_btn.configure(text=f"🛡️ {self.unread_count} Alert", fg_color="#991B1B", border_color="#FCA5A5")
            self.deiconify()
            self.lift()
        else:
            self.withdraw()


class AskTrustLensChatWindow(ctk.CTkToplevel):
    """'Ask TrustLens' friendly desktop chatbot window (in-memory history only, 16px readable font)."""

    def __init__(self, master: AmbientDesktopUI, speaker: OfflineSpeaker, initial_context: str = "") -> None:
        super().__init__(master)
        self.ui = master
        self.speaker = speaker
        self.title("Ask TrustLens — Safety Chat Helper")
        self.geometry("560x620")
        self.attributes("-topmost", True)
        self.configure(fg_color="#0B1120")

        self.lang = load_settings().get("language", "en")
        self.history: list[dict[str, str]] = []
        self.last_bot_speech = ""

        top = ctk.CTkFrame(self, fg_color="#1E293B", corner_radius=8)
        top.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(top, text="💬 Ask TrustLens", font=("Segoe UI", 17, "bold"), text_color="#14B8A6").pack(
            side="left", padx=12, pady=8
        )

        ctk.CTkButton(
            top,
            text="🗑️ Clear chat",
            width=95,
            height=30,
            fg_color="#334155",
            font=("Segoe UI", 12, "bold"),
            command=self.clear_chat,
        ).pack(side="right", padx=8, pady=6)

        ctk.CTkButton(
            top,
            text="⏹️ Stop",
            width=72,
            height=30,
            fg_color="#991B1B",
            font=("Segoe UI", 12, "bold"),
            command=self.speaker.stop,
        ).pack(side="right", padx=4, pady=6)

        ctk.CTkButton(
            top,
            text="🔊 Read aloud",
            width=105,
            height=30,
            fg_color="#2563EB",
            font=("Segoe UI", 12, "bold"),
            command=lambda: self.speaker.speak(self.last_bot_speech, self.lang),
        ).pack(side="right", padx=4, pady=6)

        self.chat_scroll = ctk.CTkScrollableFrame(self, fg_color="#0F172A", corner_radius=8)
        self.chat_scroll.pack(fill="both", expand=True, padx=12, pady=6)

        input_row = ctk.CTkFrame(self, fg_color="transparent")
        input_row.pack(fill="x", padx=12, pady=(4, 12))

        self.entry = ctk.CTkEntry(
            input_row,
            placeholder_text="Paste a message or ask a question...",
            height=40,
            font=("Segoe UI", 15),
        )
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.entry.bind("<Return>", lambda e: self.send_from_entry())

        ctk.CTkButton(
            input_row,
            text="Send",
            width=84,
            height=40,
            fg_color="#0D9488",
            font=("Segoe UI", 14, "bold"),
            command=self.send_from_entry,
        ).pack(side="right")

        self.append_bubble(
            "TrustLens Helper",
            "Ask me about any message, link, or call. Never type your real OTP or password here.",
            is_user=False,
        )

        if initial_context.strip():
            self.send_message(initial_context.strip(), speak_reply=False)

    def clear_chat(self) -> None:
        self.history.clear()
        self.last_bot_speech = ""
        for child in self.chat_scroll.winfo_children():
            child.destroy()
        self.append_bubble("TrustLens Helper", "Chat cleared. How can I help you?", is_user=False)

    def append_bubble(self, sender_label: str, text: str, is_user: bool) -> None:
        bg = "#1E3A8A" if is_user else "#1E293B"
        frame = ctk.CTkFrame(self.chat_scroll, fg_color=bg, corner_radius=10)
        frame.pack(fill="x", padx=6, pady=5)

        ctk.CTkLabel(
            frame,
            text=sender_label,
            font=("Segoe UI", 12, "bold"),
            text_color="#93C5FD" if is_user else "#5EEAD4",
        ).pack(anchor="w", padx=12, pady=(8, 2))

        ctk.CTkLabel(
            frame,
            text=text,
            font=("Segoe UI", 16),
            text_color="#FFFFFF",
            wraplength=480,
            justify="left",
        ).pack(anchor="w", padx=12, pady=(0, 10))

    def send_from_entry(self) -> None:
        msg = self.entry.get().strip()
        if not msg:
            return
        self.entry.delete(0, "end")
        self.send_message(msg, speak_reply=False)

    def send_message(self, msg: str, speak_reply: bool = False) -> None:
        self.lang = load_settings().get("language", "en")
        self.append_bubble("You", msg, is_user=True)

        def _worker() -> None:
            try:
                resp = requests.post(
                    f"{API_BASE}/api/chat",
                    headers={"X-TrustLens-Token": get_extension_token()},
                    json={
                        "message": msg[:4000],
                        "language": self.lang,
                        "history": self.history[-6:],
                    },
                    timeout=18.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    use_hi = self.lang == "hi"
                    verdict = (data.get("verdict_line_hi") if use_hi else data.get("verdict_line")) or data.get("verdict_line", "")
                    rep = (data.get("reply_hi") if use_hi and data.get("reply_hi") else data.get("reply")) or ""
                    steps = (data.get("steps_hi") if use_hi and data.get("steps_hi") else data.get("steps")) or []
                    step_txt = "\n".join(f"{i}. {s}" for i, s in enumerate(steps[:3], 1))
                    full_txt = f"{verdict}\n{rep}" + (f"\n\n{step_txt}" if step_txt else "")
                    speech_txt = ". ".join([verdict, rep, *steps[:3]])
                else:
                    full_txt = "Could not reach chat helper right now."
                    speech_txt = full_txt
            except Exception as e:
                log.warning("Desktop chat error: %s", e)
                full_txt = "I can only do basic checks right now."
                speech_txt = full_txt

            self.history.append({"role": "user", "content": msg[:500]})
            self.history.append({"role": "assistant", "content": full_txt[:500]})
            self.last_bot_speech = speech_txt
            self.after(0, lambda: self.append_bubble("TrustLens Helper", full_txt, is_user=False))
            if speak_reply:
                self.speaker.speak(speech_txt, self.lang)

        threading.Thread(target=_worker, daemon=True).start()


class ThreatExplanationDrawer(ctk.CTkToplevel):
    """Plain-language explanation popup with Read Aloud, Stop, Ask TrustLens, and Why? Pie Chart."""

    def __init__(self, master: AmbientDesktopUI, speaker: OfflineSpeaker) -> None:
        super().__init__(master)
        self.ui = master
        self.speaker = speaker
        self.title("TrustLens Helper")
        self.width = 570
        self.height = 690

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
        self.why_open = False
        self.details_open = False

        top = ctk.CTkFrame(self, fg_color="#1E293B", corner_radius=8)
        top.pack(fill="x", padx=12, pady=(12, 6))

        self.nav_lbl = ctk.CTkLabel(top, text="Alert 1 of 1", font=("Segoe UI", 14, "bold"), text_color="#F8FAFC")
        self.nav_lbl.pack(side="left", padx=10, pady=8)

        self.next_btn = ctk.CTkButton(
            top, text="▶", width=36, height=30, fg_color="#334155", font=("Segoe UI", 12, "bold"), command=self.next_threat
        )
        self.next_btn.pack(side="right", padx=(2, 8), pady=6)

        self.prev_btn = ctk.CTkButton(
            top, text="◀", width=36, height=30, fg_color="#334155", font=("Segoe UI", 12, "bold"), command=self.prev_threat
        )
        self.prev_btn.pack(side="right", padx=2, pady=6)

        self.lang_btn = ctk.CTkButton(
            top,
            text="🌐 हिंदी" if self.lang == "en" else "🌐 English",
            width=80,
            height=30,
            fg_color="#0D9488",
            font=("Segoe UI", 12, "bold"),
            command=self.toggle_language,
        )
        self.lang_btn.pack(side="right", padx=4, pady=6)

        self.stop_btn = ctk.CTkButton(
            top,
            text="⏹️ Stop",
            width=68,
            height=30,
            fg_color="#991B1B",
            font=("Segoe UI", 12, "bold"),
            command=self.speaker.stop,
        )
        self.stop_btn.pack(side="right", padx=3, pady=6)

        self.speak_btn = ctk.CTkButton(
            top,
            text="🔊 Read aloud",
            width=105,
            height=30,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            font=("Segoe UI", 12, "bold"),
            command=self.read_current_aloud,
        )
        self.speak_btn.pack(side="right", padx=3, pady=6)

        self.scroll = ctk.CTkScrollableFrame(self, fg_color="#0F172A", corner_radius=8)
        self.scroll.pack(fill="both", expand=True, padx=12, pady=6)

        self.verdict_banner = ctk.CTkFrame(self.scroll, fg_color="#991B1B", corner_radius=10)
        self.verdict_banner.pack(fill="x", padx=6, pady=(6, 8))

        self.verdict_lbl = ctk.CTkLabel(
            self.verdict_banner,
            text="🛑 This is a scam",
            font=("Segoe UI", 20, "bold"),
            text_color="#FFFFFF",
            wraplength=490,
            justify="left",
        )
        self.verdict_lbl.pack(anchor="w", padx=14, pady=(12, 4))

        self.calm_lbl = ctk.CTkLabel(
            self.verdict_banner,
            text="Stay calm. Nothing bad has happened yet.",
            font=("Segoe UI", 15, "bold"),
            text_color="#BAE6FD",
            wraplength=490,
            justify="left",
        )
        self.calm_lbl.pack(anchor="w", padx=14, pady=(0, 12))

        self.lines_card = ctk.CTkFrame(self.scroll, fg_color="#1E293B", corner_radius=10)
        self.lines_card.pack(fill="x", padx=6, pady=6)

        self.about_lbl = ctk.CTkLabel(
            self.lines_card,
            text="",
            font=("Segoe UI", 15),
            text_color="#F8FAFC",
            wraplength=485,
            justify="left",
        )
        self.about_lbl.pack(anchor="w", padx=14, pady=(12, 6))

        self.seems_lbl = ctk.CTkLabel(
            self.lines_card,
            text="",
            font=("Segoe UI", 15),
            text_color="#FDE68A",
            wraplength=485,
            justify="left",
        )
        self.seems_lbl.pack(anchor="w", padx=14, pady=6)

        self.affects_lbl = ctk.CTkLabel(
            self.lines_card,
            text="",
            font=("Segoe UI", 15, "bold"),
            text_color="#FCA5A5",
            wraplength=485,
            justify="left",
        )
        self.affects_lbl.pack(anchor="w", padx=14, pady=(6, 12))

        self.why_btn = ctk.CTkButton(
            self.scroll,
            text="🥧 Why is this risky?",
            fg_color="#1E293B",
            hover_color="#334155",
            height=36,
            font=("Segoe UI", 14, "bold"),
            command=self.toggle_why_chart,
        )
        self.why_btn.pack(fill="x", padx=6, pady=(4, 4))

        self.why_frame = ctk.CTkFrame(self.scroll, fg_color="#111827", corner_radius=10)
        self.pie_canvas = tk.Canvas(self.why_frame, bg="#111827", width=480, height=195, highlightthickness=0)
        self.pie_canvas.pack(fill="x", padx=10, pady=(10, 4))
        self.why_list_lbl = ctk.CTkLabel(
            self.why_frame,
            text="",
            font=("Segoe UI", 14),
            text_color="#E2E8F0",
            wraplength=470,
            justify="left",
        )
        self.why_list_lbl.pack(anchor="w", padx=14, pady=(2, 10))

        self.steps_card = ctk.CTkFrame(self.scroll, fg_color="#064E3B", corner_radius=10)
        self.steps_card.pack(fill="x", padx=6, pady=6)

        self.steps_heading = ctk.CTkLabel(
            self.steps_card,
            text="✅ What to do now:",
            font=("Segoe UI", 15, "bold"),
            text_color="#A7F3D0",
        )
        self.steps_heading.pack(anchor="w", padx=14, pady=(10, 4))

        self.steps_lbl = ctk.CTkLabel(
            self.steps_card,
            text="",
            font=("Segoe UI", 15, "bold"),
            text_color="#FFFFFF",
            wraplength=485,
            justify="left",
        )
        self.steps_lbl.pack(anchor="w", padx=14, pady=(2, 12))

        self.details_btn = ctk.CTkButton(
            self.scroll,
            text="▼ More details",
            fg_color="#1E293B",
            hover_color="#334155",
            height=34,
            font=("Segoe UI", 13, "bold"),
            command=self.toggle_details,
        )
        self.details_btn.pack(fill="x", padx=6, pady=(6, 4))

        self.details_frame = ctk.CTkFrame(self.scroll, fg_color="#111827", corner_radius=8)
        self.details_lbl = ctk.CTkLabel(
            self.details_frame,
            text="",
            font=("Consolas", 12),
            text_color="#94A3B8",
            wraplength=480,
            justify="left",
        )
        self.details_lbl.pack(anchor="w", padx=12, pady=10)

        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=12, pady=(6, 12))

        self.ask_btn = ctk.CTkButton(
            bottom,
            text="💬 Ask TrustLens",
            fg_color="#4F46E5",
            hover_color="#4338CA",
            height=38,
            font=("Segoe UI", 13, "bold"),
            command=self.ask_about_current,
        )
        self.ask_btn.pack(side="left", expand=True, fill="x", padx=(0, 3))

        self.safe_btn = ctk.CTkButton(
            bottom,
            text="✅ Safe",
            fg_color="#065F46",
            hover_color="#047857",
            height=38,
            font=("Segoe UI", 13, "bold"),
            command=lambda: self.submit_feedback("false_positive"),
        )
        self.safe_btn.pack(side="left", expand=True, fill="x", padx=3)

        self.scam_btn = ctk.CTkButton(
            bottom,
            text="🚨 Scam",
            fg_color="#334155",
            hover_color="#475569",
            height=38,
            font=("Segoe UI", 13, "bold"),
            command=lambda: self.submit_feedback("confirm_scam"),
        )
        self.scam_btn.pack(side="left", expand=True, fill="x", padx=3)

        self.report_btn = ctk.CTkButton(
            bottom,
            text="📞 1930",
            fg_color="#DC2626",
            hover_color="#B91C1C",
            height=38,
            font=("Segoe UI", 13, "bold"),
            command=self.report_to_cybercrime,
        )
        self.report_btn.pack(side="right", expand=True, fill="x", padx=(3, 0))

        self.render_current()

    def ask_about_current(self) -> None:
        items = list(self.ui.unread_threats)
        if not items:
            self.ui.open_chat_window()
            return
        item = items[self.current_index]
        ctx_q = f"Is this safe and what should I do? {item.get('input', '')[:250]}"
        self.ui.open_chat_window(initial_context=ctx_q)

    def toggle_why_chart(self) -> None:
        self.why_open = not self.why_open
        if self.why_open:
            self.why_frame.pack(fill="x", padx=6, pady=(2, 8), after=self.why_btn)
        else:
            self.why_frame.pack_forget()
        self._update_toggle_labels()

    def toggle_details(self) -> None:
        self.details_open = not self.details_open
        if self.details_open:
            self.details_frame.pack(fill="x", padx=6, pady=(2, 8))
        else:
            self.details_frame.pack_forget()
        self._update_toggle_labels()

    def _update_toggle_labels(self) -> None:
        use_hi = self.lang == "hi"
        if self.why_open:
            self.why_btn.configure(text="▲ चार्ट छुपाएं (Why?)" if use_hi else "▲ Hide chart (Why?)")
        else:
            self.why_btn.configure(text="🥧 क्यों? (Why is this risky?)" if use_hi else "🥧 Why? (Show reason chart)")

        if self.details_open:
            self.details_btn.configure(text="▲ जानकारी छुपाएं" if use_hi else "▲ Hide details")
        else:
            self.details_btn.configure(text="▼ और जानकारी देखें" if use_hi else "▼ More details")

    def _draw_pie_chart_on_main_thread(self, breakdown: list[dict[str, Any]], total_score: int) -> None:
        self.pie_canvas.delete("all")
        if not breakdown:
            return

        use_hi = self.lang == "hi"
        cx, cy, r = 90, 96, 68
        inner_r = 38

        total_pts = sum(max(0, int(s.get("points", 0) or 0)) for s in breakdown)
        if total_pts <= 0:
            self.pie_canvas.create_oval(cx - r, cy - r, cx + r, cy + r, fill="#10B981", outline="#0F172A", width=2)
            self.pie_canvas.create_oval(cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r, fill="#111827", outline="")
            self.pie_canvas.create_text(cx, cy, text="0/100", fill="#10B981", font=("Segoe UI", 14, "bold"))
            lbl = breakdown[0].get("label_hi" if use_hi else "label_en") or "Nothing suspicious found"
            self.pie_canvas.create_rectangle(185, 84, 200, 99, fill="#10B981", outline="")
            self.pie_canvas.create_text(208, 91, text=f"{lbl} (0)", fill="#F8FAFC", font=("Segoe UI", 12, "bold"), anchor="w")
            self.why_list_lbl.configure(text=f"• {lbl}: 0")
            return

        start_ang = 90.0
        list_lines: list[str] = []
        legend_y = 26

        for idx, s in enumerate(breakdown[:6]):
            pts = max(0, int(s.get("points", 0) or 0))
            if pts <= 0:
                continue
            color = SLICE_PALETTE[idx % len(SLICE_PALETTE)]
            extent = -(pts / float(total_pts)) * 360.0
            if abs(extent) >= 359.5:
                self.pie_canvas.create_oval(cx - r, cy - r, cx + r, cy + r, fill=color, outline="#111827", width=2)
            else:
                self.pie_canvas.create_arc(
                    cx - r, cy - r, cx + r, cy + r,
                    start=start_ang, extent=extent, fill=color, outline="#111827", width=2, style=tk.PIESLICE
                )
            start_ang += extent

            lbl = (s.get("label_hi") if use_hi else s.get("label_en")) or s.get("label_en", "Reason")
            pts_word = "अंक" if use_hi else "pts"
            self.pie_canvas.create_rectangle(180, legend_y, 194, legend_y + 14, fill=color, outline="")
            self.pie_canvas.create_text(
                202, legend_y + 7,
                text=f"{lbl}: +{pts} {pts_word}",
                fill="#F8FAFC",
                font=("Segoe UI", 11, "bold"),
                anchor="w",
            )
            legend_y += 28
            list_lines.append(f"• {lbl}: +{pts} {pts_word}")

        self.pie_canvas.create_oval(cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r, fill="#111827", outline="")
        self.pie_canvas.create_text(cx, cy, text=f"{total_score}/100", fill="#F8FAFC", font=("Segoe UI", 14, "bold"))
        self.why_list_lbl.configure(text="\n".join(list_lines))

    def toggle_language(self) -> None:
        self.lang = "hi" if self.lang == "en" else "en"
        save_settings({"language": self.lang})
        self.render_current()

    def read_current_aloud(self) -> None:
        """Reads ONLY the verdict line, the 3 short lines, and the steps via offline SAPI."""
        items = list(self.ui.unread_threats)
        if not items:
            return
        item = items[self.current_index]
        a = item.get("analysis", {})
        speech_txt = build_alert_speech_text(a, self.lang)
        self.speaker.speak(speech_txt, self.lang)

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
        a = item.get("analysis", {})
        risk = str(a.get("overall_risk_score", "High"))
        score = int(a.get("numeric_risk_score", 0) or 0)
        use_hi = self.lang == "hi"

        self.lang_btn.configure(text="🌐 English" if use_hi else "🌐 हिंदी")
        self.speak_btn.configure(text="🔊 बोलकर सुनें" if use_hi else "🔊 Read aloud")
        self.stop_btn.configure(text="⏹️ रोकें" if use_hi else "⏹️ Stop")
        self.steps_heading.configure(text="✅ अब क्या करें:" if use_hi else "✅ What to do now:")
        self.ask_btn.configure(text="💬 पूछें" if use_hi else "💬 Ask TrustLens")
        self._update_toggle_labels()

        if use_hi:
            self.nav_lbl.configure(text=f"अलर्ट {self.current_index + 1} / {len(items)}")
        else:
            self.nav_lbl.configure(text=f"Alert {self.current_index + 1} of {len(items)}")

        bg_col = "#991B1B" if risk == "High" else "#B45309" if risk == "Medium" else "#065F46"
        self.verdict_banner.configure(fg_color=bg_col)

        verdict_txt = (
            (a.get("verdict_line_hi") if use_hi else a.get("verdict_line"))
            or default_verdict_line(risk, self.lang)
        )
        calm_txt = (a.get("calm_down_message_hi") if use_hi else a.get("calm_down_message")) or a.get("calm_down_message", "")
        about_txt = (a.get("what_input_is_about_hi") if use_hi else a.get("what_input_is_about")) or a.get("what_input_is_about", "")
        seems_txt = (a.get("what_it_seems_to_be_hi") if use_hi else a.get("what_it_seems_to_be")) or a.get("what_it_seems_to_be", "")
        affects_txt = (a.get("how_it_affects_user_hi") if use_hi else a.get("how_it_affects_user")) or a.get("how_it_affects_user", "")
        acts = (
            (a.get("recommended_actions_hi") if use_hi and a.get("recommended_actions_hi") else a.get("recommended_actions"))
            or []
        )[:3]

        self.verdict_lbl.configure(text=verdict_txt)
        self.calm_lbl.configure(text=calm_txt)
        self.about_lbl.configure(text=about_txt)
        self.seems_lbl.configure(text=seems_txt)
        self.affects_lbl.configure(text=affects_txt)
        self.steps_lbl.configure(text="\n".join(f"{idx}. {step}" for idx, step in enumerate(acts, 1)))

        breakdown = a.get("score_breakdown") or []
        if breakdown:
            self.why_btn.pack(fill="x", padx=6, pady=(4, 4), after=self.lines_card)
            self._draw_pie_chart_on_main_thread(breakdown, score)
            if self.why_open:
                self.why_frame.pack(fill="x", padx=6, pady=(2, 8), after=self.why_btn)
        else:
            self.why_btn.pack_forget()
            self.why_frame.pack_forget()

        inds = a.get("indicators", [])
        detail_lines = [
            f"Source: {item.get('source', '')} ({item.get('timestamp', '')})",
            f"Score: {score}/100 ({risk}) — {a.get('confidence_score_explanation', '')}",
            f"Checked text: {item.get('input', '')}",
        ]
        for ind in inds:
            detail_lines.append(
                f"• [{ind.get('severity')}] {ind.get('indicator_type')}: {ind.get('target_element')} — {ind.get('explanation')}"
            )
        self.details_lbl.configure(text="\n".join(detail_lines))

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
                        "lesson_note": f"User marked {dom} as {fb_type}" if dom else "",
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
        a = item.get("analysis", {})
        report_text = (
            f"{TRUSTLENS_INTERNAL_MARKER} TrustLens Cybercrime Report\n"
            f"Time: {item.get('timestamp')}\n"
            f"Verdict: {a.get('verdict_line')} ({a.get('numeric_risk_score')}/100)\n"
            f"What happened: {a.get('what_input_is_about')}\n"
            f"Details: {item.get('input')}\n"
            "Call 1930 or visit https://cybercrime.gov.in\n"
        )
        try:
            pyperclip.copy(report_text)
        except Exception as e:
            log.debug("Clipboard copy note: %s", e)
        webbrowser.open("https://cybercrime.gov.in")

    def close_drawer(self) -> None:
        self.speaker.stop()
        try:
            self.pie_canvas.delete("all")
        except Exception:
            pass
        self.ui.unread_threats.clear()
        self.ui.sync_badge()
        self.destroy()


class AmbientDesktopUI(ctk.CTk):
    """Withdrawn main Tk root coordinating the floating badge, explanation drawer, chat window, and voice callbacks."""

    def __init__(self, speaker: OfflineSpeaker, on_status_change: Callable[[str, int], None] | None = None) -> None:
        super().__init__()
        self.withdraw()
        self.speaker = speaker
        self.on_status_change = on_status_change
        self.ui_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.unread_threats: deque[dict[str, Any]] = deque(maxlen=50)
        self.history_threats: deque[dict[str, Any]] = deque(maxlen=100)
        self.badge = FloatingBadgeWindow(self, on_click=self.open_explanation_drawer)
        self.drawer: ThreatExplanationDrawer | None = None
        self.chat_win: AskTrustLensChatWindow | None = None

        self.after(200, self._process_ui_queue)
        self.after(400, self._check_consent_on_startup)

    def _check_consent_on_startup(self) -> None:
        settings = load_settings()
        if not settings.get("consent_given", False):
            FirstRunConsentDialog(self, on_complete=lambda: log.info("First-run consent completed."))

    def push_judged_record(self, record: dict[str, Any]) -> None:
        self.ui_queue.put(("record", record))

    def request_open_drawer(self) -> None:
        self.ui_queue.put(("open_drawer", None))

    def request_open_chat(self, initial_context: str = "", speak_reply: bool = False) -> None:
        self.ui_queue.put(("open_chat", (initial_context, speak_reply)))

    def set_voice_listening_indicator(self, listening: bool, status_text: str = "") -> None:
        self.ui_queue.put(("voice_state", (listening, status_text)))

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
                elif cmd == "open_chat":
                    ctx, spk = payload
                    self.open_chat_window(initial_context=ctx, speak_reply=spk)
                elif cmd == "voice_state":
                    listening, status_txt = payload
                    self.badge.set_listening_state(listening, status_txt)
                elif cmd == "shutdown":
                    self.destroy()
                    return
        except queue.Empty:
            pass
        self.after(200, self._process_ui_queue)

    def _handle_record_on_main_thread(self, record: dict[str, Any]) -> None:
        self.history_threats.appendleft(record)
        analysis = record.get("analysis", {})
        if analysis.get("is_suspicious") and analysis.get("overall_risk_score") in ("High", "Medium"):
            self.unread_threats.appendleft(record)
            self.sync_badge()
            if self.drawer is not None and self.drawer.winfo_exists():
                self.drawer.current_index = 0
                self.drawer.render_current()

            # Auto-read High-risk alerts ONLY if the user explicitly enabled auto_read_high_risk (default OFF)
            settings = load_settings()
            if analysis.get("overall_risk_score") == "High" and bool(settings.get("auto_read_high_risk", False)):
                lang = settings.get("language", "en")
                self.speaker.speak(build_alert_speech_text(analysis, lang), lang)

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
            self.drawer = ThreatExplanationDrawer(self, self.speaker)

    def open_chat_window(self, initial_context: str = "", speak_reply: bool = False) -> None:
        if self.chat_win is not None and self.chat_win.winfo_exists():
            self.chat_win.deiconify()
            self.chat_win.lift()
            if initial_context.strip():
                self.chat_win.send_message(initial_context.strip(), speak_reply=speak_reply)
        else:
            self.chat_win = AskTrustLensChatWindow(self, self.speaker, initial_context="")
            if initial_context.strip():
                self.chat_win.send_message(initial_context.strip(), speak_reply=speak_reply)
