"""Offline SAPI Read-Aloud (pyttsx3) and Push-to-Talk Local Voice Commands (faster-whisper) for TrustLens AI.

Safety & Privacy Guarantees:
- Voice is OFF by default. Nothing opens the microphone unless `voice_enabled` is True and the app is not paused.
- Push-to-Talk opens the microphone ONLY while the hotkey (default Ctrl+Alt+T) is physically held down
  (capped at 8 seconds) and closes it immediately on release. No wake word, no background listening.
- Audio stays in RAM only (float32 numpy array), is never written to disk, never sent to the cloud,
  and is explicitly deleted immediately after local transcription.
- Fixed allow-list command parser (`parse_voice_command`): never calls eval, exec, or shell commands.
  Dangerous or irreversible requests ('delete everything', 'format disk', 'quit', 'blacklist') are refused safely.
"""
from __future__ import annotations

import ctypes
import logging
import queue
import re
import sys
import threading
import time
from typing import Any, Callable

log = logging.getLogger("trustlens.voice")

# Optional dependency detection (never crashes startup if missing)
try:
    import pyttsx3  # type: ignore

    PYTTSX3_AVAILABLE = True
except Exception as e:
    pyttsx3 = None
    PYTTSX3_AVAILABLE = False
    log.info("pyttsx3 not installed (%s); using fallback speech status.", e)

try:
    import numpy as np  # type: ignore
    import sounddevice as sd  # type: ignore

    AUDIO_CAPTURE_AVAILABLE = True
except Exception as e:
    np = None
    sd = None
    AUDIO_CAPTURE_AVAILABLE = False
    log.info("sounddevice/numpy not installed (%s); push-to-talk audio disabled.", e)

try:
    from faster_whisper import WhisperModel  # type: ignore

    FASTER_WHISPER_AVAILABLE = True
except Exception as e:
    WhisperModel = None
    FASTER_WHISPER_AVAILABLE = False
    log.info("faster-whisper not installed (%s); local transcription disabled.", e)

VOICE_STACK_AVAILABLE = AUDIO_CAPTURE_AVAILABLE and FASTER_WHISPER_AVAILABLE

MAX_HOLD_SECONDS = 8.0
SAMPLE_RATE = 16000


def get_voice_availability_message(lang: str = "en") -> str:
    """Returns a plain-language explanation if optional voice packages are missing."""
    if VOICE_STACK_AVAILABLE:
        return (
            "आवाज़ की सुविधा तैयार है (बोलने के लिए Ctrl+Alt+T दबाए रखें)।"
            if lang == "hi"
            else "Voice is ready (Hold Ctrl+Alt+T to talk)."
        )
    if lang == "hi":
        return "आवाज़ की सुविधा अभी बंद है क्योंकि इसके पैकेज इंस्टॉल नहीं हैं। बाकी सभी सुरक्षा जांच चालू हैं।"
    return "Voice is unavailable because optional voice packages are not installed. All other safety checks work normally."


def _play_beep(freq_hz: int, duration_ms: int) -> None:
    """Plays a short start or stop tone on Windows without blocking."""
    if sys.platform != "win32":
        return
    try:
        import winsound

        winsound.Beep(freq_hz, duration_ms)
    except Exception as e:
        log.debug("Beep note: %s", e)


# --------------------------------------------------------------------------- #
# PART 2: Offline SAPI Read-Aloud Worker (pyttsx3, never blocks Tk main thread)
# --------------------------------------------------------------------------- #
class OfflineSpeaker:
    """Thread-safe offline speech worker using pyttsx3 on Windows SAPI."""

    def __init__(self, on_notice: Callable[[str], None] | None = None) -> None:
        self.on_notice = on_notice
        self._cmd_queue: queue.Queue[tuple[str, str, str]] = queue.Queue()
        self._stop_flag = threading.Event()
        self._shutdown_flag = threading.Event()
        self._speaking_lock = threading.Lock()
        self._is_speaking = False
        self._engine: Any = None
        self._worker = threading.Thread(target=self._run_loop, name="TrustLensTTSWorker", daemon=True)
        self._worker.start()

    @property
    def is_speaking(self) -> bool:
        with self._speaking_lock:
            return self._is_speaking

    def speak(self, text: str, lang: str = "en") -> dict[str, Any]:
        """Queues text to be spoken aloud on the background SAPI worker thread."""
        cleaned = " ".join((text or "").strip().split())[:900]
        if not cleaned:
            return {"status": "empty", "notice": ""}

        # Drain any queued speech so new speech starts right away
        while not self._cmd_queue.empty():
            try:
                self._cmd_queue.get_nowait()
            except queue.Empty:
                break

        self._stop_flag.set()
        self._cmd_queue.put(("speak", cleaned, lang))
        return {"status": "queued", "notice": ""}

    def stop(self) -> None:
        """Immediately stops ongoing speech."""
        self._stop_flag.set()
        while not self._cmd_queue.empty():
            try:
                self._cmd_queue.get_nowait()
            except queue.Empty:
                break
        if self._engine is not None:
            try:
                self._engine.stop()
            except Exception as e:
                log.debug("pyttsx3 stop note: %s", e)

    def shutdown(self) -> None:
        self.stop()
        self._shutdown_flag.set()
        self._cmd_queue.put(("quit", "", "en"))

    def _select_voice(self, engine: Any, lang: str) -> str:
        """Selects a Hindi SAPI voice if requested and installed; returns plain notice if missing."""
        try:
            voices = engine.getProperty("voices") or []
        except Exception:
            return ""

        want_hi = lang == "hi"
        hi_voice_id = None
        en_voice_id = None

        for v in voices:
            vid = str(getattr(v, "id", "") or "")
            vname = str(getattr(v, "name", "") or "").lower()
            vlangs = str(getattr(v, "languages", "") or "").lower()
            if any(k in vname or k in vid.lower() or k in vlangs for k in ("hindi", "hi-in", "hi_in", "hemant", "kalpana")):
                hi_voice_id = vid
            elif en_voice_id is None and any(k in vname or k in vid.lower() for k in ("english", "en-", "zira", "david", "hazel", "ravi", "heera")):
                en_voice_id = vid

        if want_hi:
            if hi_voice_id:
                try:
                    engine.setProperty("voice", hi_voice_id)
                except Exception:
                    pass
                return ""
            if en_voice_id:
                try:
                    engine.setProperty("voice", en_voice_id)
                except Exception:
                    pass
            return "Hindi voice is not installed on this computer. Reading in the default voice."

        if en_voice_id:
            try:
                engine.setProperty("voice", en_voice_id)
            except Exception:
                pass
        return ""

    def _run_loop(self) -> None:
        while not self._shutdown_flag.is_set():
            try:
                cmd, text, lang = self._cmd_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if cmd == "quit":
                break
            if cmd != "speak" or not text:
                continue

            self._stop_flag.clear()
            with self._speaking_lock:
                self._is_speaking = True

            try:
                if PYTTSX3_AVAILABLE and pyttsx3 is not None:
                    engine = pyttsx3.init()
                    self._engine = engine
                    engine.setProperty("rate", 165)
                    notice = self._select_voice(engine, lang)
                    if notice and self.on_notice is not None:
                        try:
                            self.on_notice(notice)
                        except Exception:
                            pass

                    # Split by sentence so Esc / Stop button can interrupt quickly between sentences
                    sentences = [s.strip() for s in re.split(r"(?:\.(?!\d)|[!?।\n])+", text) if s.strip()]
                    for sent in sentences:
                        if self._stop_flag.is_set() or self._shutdown_flag.is_set():
                            break
                        engine.say(sent)
                        engine.runAndWait()
                    self._engine = None
                else:
                    if self.on_notice is not None:
                        self.on_notice("Offline speech library (pyttsx3) is not installed.")
            except Exception as e:
                log.warning("Offline TTS worker error: %s", e)
            finally:
                with self._speaking_lock:
                    self._is_speaking = False


def build_alert_speech_text(analysis: dict[str, Any], lang: str = "en") -> str:
    """Builds speech text containing ONLY the verdict line, the 3 short lines, and the steps."""
    use_hi = lang == "hi"
    verdict = (analysis.get("verdict_line_hi") if use_hi else analysis.get("verdict_line")) or analysis.get("verdict_line", "")
    about = (analysis.get("what_input_is_about_hi") if use_hi else analysis.get("what_input_is_about")) or analysis.get("what_input_is_about", "")
    seems = (analysis.get("what_it_seems_to_be_hi") if use_hi else analysis.get("what_it_seems_to_be")) or analysis.get("what_it_seems_to_be", "")
    affects = (analysis.get("how_it_affects_user_hi") if use_hi else analysis.get("how_it_affects_user")) or analysis.get("how_it_affects_user", "")
    steps = (
        (analysis.get("recommended_actions_hi") if use_hi and analysis.get("recommended_actions_hi") else analysis.get("recommended_actions"))
        or []
    )[:3]
    parts = [p for p in [verdict, about, seems, affects, *steps] if p]
    return ". ".join(parts)


# --------------------------------------------------------------------------- #
# PART 3: Fixed Allow-List Voice Command Parser (EN, HI, Hinglish)
# --------------------------------------------------------------------------- #
DANGEROUS_VOICE_PATTERNS: tuple[str, ...] = (
    "delete everything",
    "delete memory",
    "clear memory",
    "wipe memory",
    "format my disk",
    "format disk",
    "format c:",
    "rm -rf",
    "del /f",
    "blacklist this",
    "add to blacklist",
    "mark this safe",
    "this is safe",
    "mark as safe",
    "quit app",
    "exit app",
    "close trustlens",
    "shutdown computer",
    "सब डिलीट करो",
    "मेमोरी डिलीट करो",
)

HINDI_NUM_WORDS: dict[str, int] = {
    "एक": 1, "दो": 2, "तीन": 3, "चार": 4, "पांच": 5, "पाँच": 5,
    "दस": 10, "पंद्रह": 15, "बीस": 20, "तीस": 30, "साठ": 60,
    "one": 1, "two": 2, "three": 3, "five": 5, "ten": 10, "fifteen": 15, "twenty": 20, "thirty": 30,
}


def parse_voice_command(transcript: str) -> dict[str, Any]:
    """
    Parses a voice transcript against a strict, fixed allow-list.
    Never executes arbitrary commands.
    Returns:
      {"action": <command_id>, "params": {...}, "is_blocked": bool, "reply_en": str, "reply_hi": str}
    Allowed actions:
      - check_clipboard
      - read_last_alert
      - stop_reading
      - explain_in_hindi
      - explain_in_english
      - pause_minutes
      - resume
      - open_dashboard
      - what_is_wrong
      - blocked_dangerous (refuses dangerous/irreversible requests)
      - ask_chatbot (falls through to /api/chat for general questions)
    """
    raw = (transcript or "").strip()
    if not raw:
        return {
            "action": "empty",
            "params": {},
            "is_blocked": False,
            "reply_en": "I did not hear anything. Hold Ctrl+Alt+T and speak.",
            "reply_hi": "मुझे कुछ सुनाई नहीं दिया। बोलने के लिए Ctrl+Alt+T दबाए रखें।",
        }

    low = re.sub(r"[.!?,।]+", " ", raw.lower()).strip()
    low = " ".join(low.split())

    # 1. Block dangerous or irreversible voice actions explicitly
    for bad in DANGEROUS_VOICE_PATTERNS:
        if bad in low:
            return {
                "action": "blocked_dangerous",
                "params": {"query": raw},
                "is_blocked": True,
                "reply_en": "For your safety, I cannot delete data, change safety lists, or close the app by voice.",
                "reply_hi": "आपकी सुरक्षा के लिए, मैं आवाज़ से डेटा डिलीट करने या ऐप बंद करने का काम नहीं कर सकता।",
            }

    # 2. Stop reading ("stop reading", "stop speaking", "chup ho jao", "पढ़ना बंद करो", "रुको")
    if any(
        p in low
        for p in (
            "stop reading", "stop speaking", "stop talking", "be quiet", "shh",
            "padhna band", "bolna band", "chup ho", "ruk jao", "पढ़ना बंद", "बोलना बंद", "रुक जाओ", "चुप",
        )
    ) or low in ("stop", "रुको", "बंद करो"):
        return {
            "action": "stop_reading",
            "params": {},
            "is_blocked": False,
            "reply_en": "Stopped reading.",
            "reply_hi": "पढ़ना बंद कर दिया।",
        }

    # 3. Check clipboard ("check my clipboard", "scan clipboard", "mera clipboard check karo", "क्लिपबोर्ड जांचें")
    if any(
        p in low
        for p in (
            "check my clipboard", "check clipboard", "scan my clipboard", "scan clipboard",
            "clipboard check", "clipboard janch", "क्लिपबोर्ड", "कॉपी किया हुआ चेक करो",
        )
    ):
        return {
            "action": "check_clipboard",
            "params": {},
            "is_blocked": False,
            "reply_en": "Checking what you copied on your clipboard now.",
            "reply_hi": "आपके क्लिपबोर्ड पर कॉपी किए गए टेक्स्ट की जांच हो रही है।",
        }

    # 4. Read last alert ("read the last alert", "read last alert", "pichla alert padho", "आखिरी अलर्ट पढ़ो")
    if any(
        p in low
        for p in (
            "read the last alert", "read last alert", "read latest alert", "repeat the alert",
            "pichla alert", "aakhri alert", "alert padho", "alert sunao",
            "आखिरी अलर्ट", "पिछला अलर्ट", "अलर्ट पढ़ो", "अलर्ट सुनाओ",
        )
    ):
        return {
            "action": "read_last_alert",
            "params": {},
            "is_blocked": False,
            "reply_en": "Reading the last alert aloud.",
            "reply_hi": "आखिरी अलर्ट पढ़कर सुना रहा हूँ।",
        }

    # 5. Explain in Hindi ("explain in hindi", "hindi mein batao", "हिंदी में समझाओ")
    if any(
        p in low
        for p in (
            "explain in hindi", "switch to hindi", "speak in hindi", "hindi mein batao",
            "hindi me batao", "hindi mein samjhao", "hindi me samjhao",
            "हिंदी में बताओ", "हिंदी में समझाओ", "हिंदी में बोलो",
        )
    ):
        return {
            "action": "explain_in_hindi",
            "params": {"language": "hi"},
            "is_blocked": False,
            "reply_en": "Switched to Hindi.",
            "reply_hi": "अब मैं हिंदी में समझाऊँगा।",
        }

    # 6. Explain in English ("explain in english", "english mein batao", "अंग्रेजी में बताओ")
    if any(
        p in low
        for p in (
            "explain in english", "switch to english", "speak in english",
            "english mein batao", "english me batao", "english mein samjhao",
            "अंग्रेजी में बताओ", "अंग्रेजी में समझाओ", "इंग्लिश में बताओ",
        )
    ):
        return {
            "action": "explain_in_english",
            "params": {"language": "en"},
            "is_blocked": False,
            "reply_en": "Switched to English.",
            "reply_hi": "Switched to English.",
        }

    # 7. Pause for N minutes ("pause for 15 minutes", "10 minute ke liye roko", "15 मिनट के लिए रोको")
    if any(k in low for k in ("pause", "roko", "rok do", "रोको", "रोक दो", "पॉज़")):
        minutes = 15
        m_num = re.search(r"\b(\d{1,3})\b", low)
        if m_num:
            minutes = max(1, min(120, int(m_num.group(1))))
        else:
            for word, val in HINDI_NUM_WORDS.items():
                if word in low.split():
                    minutes = val
                    break
        return {
            "action": "pause_minutes",
            "params": {"minutes": minutes},
            "is_blocked": False,
            "reply_en": f"Paused protection for {minutes} minutes.",
            "reply_hi": f"सुरक्षा को {minutes} मिनट के लिए रोक दिया गया है।",
        }

    # 8. Resume ("resume", "resume protection", "वापस चालू करो", "chalu karo", "start protection")
    if any(
        p in low
        for p in (
            "resume", "unpause", "turn on protection", "start protection",
            "wapas chalu karo", "chalu karo", "shuru karo", "वापस चालू करो", "चालू करो", "शुरू करो",
        )
    ):
        return {
            "action": "resume",
            "params": {},
            "is_blocked": False,
            "reply_en": "Protection is back on.",
            "reply_hi": "सुरक्षा वापस चालू हो गई है।",
        }

    # 9. Open dashboard ("open dashboard", "show dashboard", "dashboard kholo", "डैशबोर्ड खोलो")
    if any(
        p in low
        for p in (
            "open dashboard", "show dashboard", "open trustlens", "dashboard kholo",
            "dashboard dikhao", "डैशबोर्ड खोलो", "डैशबोर्ड दिखाओ",
        )
    ):
        return {
            "action": "open_dashboard",
            "params": {},
            "is_blocked": False,
            "reply_en": "Opening the TrustLens dashboard.",
            "reply_hi": "डैशबोर्ड खोला जा रहा है।",
        }

    # 10. What is wrong with this ("what is wrong with this", "isme kya galat hai", "इसमें क्या गड़बड़ है")
    if any(
        p in low
        for p in (
            "what is wrong with this", "what's wrong with this", "why is this risky",
            "why is this a scam", "isme kya galat hai", "isme kya khatra hai",
            "yeh scam kyu hai", "इसमें क्या गलत है", "इसमें क्या गड़बड़ है", "यह धोखा क्यों है",
        )
    ):
        return {
            "action": "what_is_wrong",
            "params": {},
            "is_blocked": False,
            "reply_en": "Explaining the latest alert.",
            "reply_hi": "आखिरी अलर्ट के बारे में बता रहा हूँ।",
        }

    # 11. Everything else falls through safely as a question to the chatbot
    return {
        "action": "ask_chatbot",
        "params": {"query": raw},
        "is_blocked": False,
        "reply_en": "",
        "reply_hi": "",
    }


# --------------------------------------------------------------------------- #
# PART 3: Push-to-Talk Hold-to-Record & Local faster-whisper Transcriber
# --------------------------------------------------------------------------- #
VK_MAP: dict[str, int] = {
    "ctrl": 0x11,
    "control": 0x11,
    "alt": 0x12,
    "menu": 0x12,
    "shift": 0x10,
    "esc": 0x1B,
    "escape": 0x1B,
    "space": 0x20,
}


def _parse_hotkey_vks(hotkey_str: str) -> list[int]:
    parts = [p.strip().lower() for p in (hotkey_str or "ctrl+alt+t").split("+") if p.strip()]
    vks: list[int] = []
    for p in parts:
        if p in VK_MAP:
            vks.append(VK_MAP[p])
        elif len(p) == 1 and "a" <= p <= "z":
            vks.append(ord(p.upper()))
        elif len(p) == 1 and "0" <= p <= "9":
            vks.append(ord(p))
    return vks or [0x11, 0x12, ord("T")]


def _is_vk_pressed(vk: int) -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000)
    except Exception:
        return False


class PushToTalkController:
    """
    Hold-to-talk voice recorder & local faster-whisper transcriber.
    - Does nothing if Voice is OFF or the app is Paused.
    - Opens microphone ONLY while the configured hotkey (default Ctrl+Alt+T) is held down.
    - Caps recording at 8 seconds, closes microphone immediately on release, keeps audio in RAM only.
    - Pressing Esc while speaking cuts off speech immediately.
    """

    def __init__(
        self,
        is_voice_allowed_fn: Callable[[], bool],
        get_hotkey_fn: Callable[[], str],
        on_listening_change: Callable[[bool, str], None],
        on_transcript_ready: Callable[[str], None],
        on_escape_pressed: Callable[[], None],
    ) -> None:
        self.is_voice_allowed_fn = is_voice_allowed_fn
        self.get_hotkey_fn = get_hotkey_fn
        self.on_listening_change = on_listening_change
        self.on_transcript_ready = on_transcript_ready
        self.on_escape_pressed = on_escape_pressed

        self._stop_event = threading.Event()
        self._whisper_model: Any = None
        self._model_lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._hotkey_poll_loop, name="TrustLensPTT", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _ensure_whisper_model(self) -> Any:
        if not FASTER_WHISPER_AVAILABLE or WhisperModel is None:
            return None
        with self._model_lock:
            if self._whisper_model is None:
                self.on_listening_change(False, "Downloading local voice model (first time only)...")
                self._whisper_model = WhisperModel("base", device="cpu", compute_type="int8")
                self.on_listening_change(False, "")
            return self._whisper_model

    def _hotkey_poll_loop(self) -> None:
        if sys.platform != "win32":
            return
        while not self._stop_event.is_set():
            # Esc key cuts off ongoing speech immediately
            if _is_vk_pressed(VK_MAP["esc"]):
                try:
                    self.on_escape_pressed()
                except Exception:
                    pass
                time.sleep(0.25)

            if not self.is_voice_allowed_fn():
                self._stop_event.wait(0.25)
                continue

            vks = _parse_hotkey_vks(self.get_hotkey_fn())
            if all(_is_vk_pressed(vk) for vk in vks):
                self._record_while_held(vks)
                # Wait until keys are released before allowing another trigger
                while all(_is_vk_pressed(vk) for vk in vks) and not self._stop_event.is_set():
                    time.sleep(0.08)

            self._stop_event.wait(0.06)

    def _record_while_held(self, vks: list[int]) -> None:
        if not self.is_voice_allowed_fn():
            return
        if not VOICE_STACK_AVAILABLE or sd is None or np is None:
            self.on_listening_change(False, get_voice_availability_message("en"))
            return

        frames: list[Any] = []
        _play_beep(880, 90)
        self.on_listening_change(True, "🎤 Listening... (Hold Ctrl+Alt+T)")

        def _audio_cb(indata: Any, frame_count: int, time_info: Any, status: Any) -> None:
            frames.append(indata.copy())

        start_ts = time.monotonic()
        try:
            with sd.InputStream(samplerate=SAMPLE_RATE, channels=1, dtype="float32", callback=_audio_cb):
                while (
                    not self._stop_event.is_set()
                    and self.is_voice_allowed_fn()
                    and all(_is_vk_pressed(vk) for vk in vks)
                    and (time.monotonic() - start_ts) < MAX_HOLD_SECONDS
                ):
                    time.sleep(0.04)
        except Exception as e:
            log.warning("Microphone capture error: %s", e)
            self.on_listening_change(False, "Microphone is unavailable. Check audio settings.")
            frames.clear()
            return

        _play_beep(520, 90)
        duration = time.monotonic() - start_ts
        if not frames or duration < 0.25:
            frames.clear()
            self.on_listening_change(False, "")
            return

        self.on_listening_change(False, "⏳ Understanding voice locally...")
        try:
            audio_np = np.concatenate(frames, axis=0).flatten()
        finally:
            frames.clear()

        try:
            model = self._ensure_whisper_model()
            if model is None:
                self.on_listening_change(False, get_voice_availability_message("en"))
                return
            segments, _ = model.transcribe(audio_np, beam_size=1, vad_filter=True)
            transcript = " ".join(seg.text.strip() for seg in segments if seg.text).strip()
        except Exception as e:
            log.warning("Local faster-whisper transcription error: %s", e)
            self.on_listening_change(False, "Could not transcribe audio locally.")
            return
        finally:
            # Explicitly discard in-memory audio buffer immediately after transcription
            del audio_np

        self.on_listening_change(False, "")
        if transcript:
            self.on_transcript_ready(transcript)
