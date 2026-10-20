# 🛡️ TrustLens AI

**A quiet guardian for Windows and your browser that spots scams and explains them in plain words.**

TrustLens watches what you copy, the notifications you get, the screenshots you take and the web pages you open. It stays hidden until something looks fake. Then it shows a small shield and a short, calm explanation in English or Hindi.

> ⚠️ **This is a hackathon prototype.** It can make mistakes. Do not treat it as your only protection.

---

## The problem

Scams today work on people, not on computers. They use:

- **Fake website names**, like `arnazon.com` instead of `amazon.com`.
- **UPI "refund" traps**, where a request that says "refund" actually takes money out.
- **Fake bots and support pages** that ask for your OTP, PIN or password.
- **Vague bait**, like "5 million credited, click here", made to cause panic or curiosity.
- **Tricky web pages**, with fake login forms, hidden buttons, fake countdowns and fake virus warnings.

Most security tools use fixed keyword lists. They miss new tricks and wrongly flag real bank messages. They also wait for you to copy and paste something in, and they explain the problem in technical words. Most people have to decide in seconds, under pressure, with no help.

## What TrustLens does

| Where | What it checks |
|---|---|
| **Clipboard** | Anything you copy (links, messages) |
| **Notifications** | Windows toast notifications |
| **Screenshots** | Screenshots from the clipboard or the Screenshots folder |
| **Web pages** | Every page you open, through the browser extension (Chrome and Edge) |

When something looks suspicious you get:

- A short **verdict** ("🛑 This is a scam").
- Three short lines: what it is, what it pretends to be, what could happen to you.
- **At most 3 steps** to take.
- A pie chart showing **why** it was flagged. The slices are the real findings, not guesses.
- A **More details** section with the technical evidence.
- **English and Hindi**.

It also has an **Ask TrustLens** chatbot, **read-aloud**, and optional **push-to-talk** voice (hold a key, speak, release).

Real bank OTP messages and payment receipts are meant to stay silent, so there are no false alarms.

## How it works

```
Clipboard / Notifications / Screenshots / Web pages
                    │
                    ▼
        Local rules check first (fast, no internet)
                    │
          unsure? ──┴── sure
             │            │
             ▼            │
   Gemini second opinion  │
   (private details       │
    removed first)        │
             └─────┬──────┘
                   ▼
      Safe merge (hard rules always win)
                   ▼
   Hidden shield ➜ calm explanation card
```

- **Local rules go first.** They catch lookalike names, OTP requests, refund traps and page tricks without any internet.
- **Gemini is the second opinion**, used only when the local result is unsure.
- **If the AI is down**, local checks still work. If those can't decide either, TrustLens says "unable to verify" instead of making up a score.

## Privacy

- Phone numbers, card numbers, emails, Aadhaar-style numbers and OTPs are **removed on your PC before anything goes to the cloud**.
- The browser extension **never reads what you type**. It sends only the page structure and a short, redacted text sample.
- The extension talks **only to your own PC** (`127.0.0.1`), never to a third-party server.
- Every source (notifications, clipboard, screenshots, voice) has its own **on/off switch**, and there is a **Pause** button.
- Voice audio stays in memory, is never saved and never leaves your PC. It is **off by default**.
- The local API is protected by a **secret token**, so websites cannot call it.

## Requirements

- **Windows 10 or 11** (the notification and screenshot watchers are Windows-only)
- **Python 3.12** from [python.org](https://www.python.org/downloads/) (tick "Add python.exe to PATH")
- **Chrome or Edge** for the extension
- A **free Gemini API key** from [aistudio.google.com](https://aistudio.google.com) (click "Get API key")
- Git (only if you want to clone the repo)

## Quick start

Open **Command Prompt** and run these one at a time. Use a simple folder like `C:\TrustLens`, **not** inside OneDrive.

```
cd C:\
git clone https://github.com/Sujal-cyber11/trustlens-ai.git TrustLens
cd C:\TrustLens
py -3.12 -m venv venv
venv\Scripts\python.exe -m pip install --upgrade pip
venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
notepad .env
```

In Notepad, put your key after `GEMINI_API_KEY=` (no quotes, no spaces) and save.

Start the app:

```
venv\Scripts\python.exe trustlens_app.py
```

A consent screen opens. Choose which sources TrustLens may watch, then click **Enable**. A shield icon appears near the clock (it may be under the `^` arrow).

**Tip:** use `pythonw.exe` in place of `python.exe` to run with no console window. If nothing appears, read the log (see Troubleshooting).

## Install the browser extension

1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select the `extension` folder.
4. Copy the extension's **ID** shown on its card.
5. Open `.env` and add this line (use your real ID, no trailing slash):
```
   TRUSTLENS_EXTENSION_ORIGINS=chrome-extension://PASTE_ID_HERE
```
6. Quit TrustLens from the tray and start it again.
7. Right-click the tray icon, choose **Copy extension token**.
8. Open the extension's **Options** page, paste the token and save.

The extension's icon is green for a clean page, amber or red for a suspicious page, and grey if the TrustLens app is not running.

## Try it

| Do this | You should see |
|---|---|
| Copy `arnazon.com` | A High-risk alert |
| Copy `https://chatgpt.com` | Nothing (it is safe) |
| Copy `5M credited to your account, click here` | A Medium or High alert |
| Copy `482910 is your OTP for SBI netbanking. Do NOT share this OTP.` | Nothing (a genuine bank message) |
| Open Wikipedia with the extension on | Green icon |
| Open the demo page (see below) | An amber or red warning |
| Click **Ask TrustLens** on an alert | A short, simple answer |

**Demo pages.** Browser extensions skip `file://` pages on purpose, so don't double-click the files in the `demo` folder. With TrustLens running, open `http://127.0.0.1:8000/demo/dark-patterns`. If you get "Not Found", serve the folder yourself:

```
cd demo
..\venv\Scripts\python.exe -m http.server 8080
```

Then open `http://localhost:8080/` and pick the page. The demo pages are safe test pages with deliberately planted tricks. They collect nothing.

Dashboard: `http://127.0.0.1:8000`

## Voice (optional)

1. Turn **Voice** on from the consent screen or the tray menu.
2. **Hold Ctrl+Alt+T**, speak, then **release**. "Listening..." shows only while the key is held.
3. The first use downloads a speech model of a few hundred MB, so use good Wi-Fi.

Nothing is spoken aloud unless you press **Read aloud** or ask by voice.

## Run the tests

```
venv\Scripts\python.exe -m pytest tests -q
```

The tests use no network and no microphone.

## Troubleshooting

| Problem | Try this |
|---|---|
| `python` opens the wrong Python | Always use `py -3.12`, and call `venv\Scripts\python.exe` directly |
| `pip install` fails on a package | Use Python 3.12 (3.14 is too new for some packages). Voice packages are optional, so the rest works without them |
| Nothing appears after starting | Read the log: `notepad %LOCALAPPDATA%\TrustLens\logs\trustlens.log` |
| "Cloud AI is offline" | Your Gemini key is missing, wrong or out of free quota. Check `.env`, or wait and try again |
| Extension icon is grey | The app is not running, the token is wrong, or the extension ID is not in `TRUSTLENS_EXTENSION_ORIGINS` |
| Extension gets `403` | Copy the token again from the tray and paste it on the Options page |
| A second copy won't start | That's the single-instance lock. Quit the first copy from the tray |
| Chat says "basic checks only" | Gemini can't be reached. Local checks still work |

## Known limitations

- **Windows only.**
- **Notification capture is the most fragile part.** It relies on Windows internals that can change, and some apps (such as browser notifications) may not be captured.
- **It can be wrong.** Expect some false alarms and some missed scams. Use the feedback buttons carefully, and don't press "scam" on test items.
- **It judges the content of a message, not who sent it.** It cannot detect cloned voices or fake caller IDs.
- **Hindi and Hinglish wording and speech recognition are good but not perfect.**
- **Gemini's free tier has limits.** Heavy use can hit the quota.
- **Page checks are heuristics.** Some dark patterns depend on intent and can be missed.
- **The browser extension runs in developer mode,** so Chrome may show a warning on each restart.

## Future work

- Call Guard: warning during spoken scam calls
- A fully local AI model option
- Packaged `.exe` installer
- A fixed extension ID, so setup needs no origin step
- More languages

## Safety note

If you think you have been scammed, call the National Cyber Crime Helpline **1930** and report at **[cybercrime.gov.in](https://cybercrime.gov.in)**. Never share your OTP, PIN or password with anyone, including this app's chatbot.

## License

MIT. See `LICENSE`.

## Credits

Built for a cybersecurity hackathon.
