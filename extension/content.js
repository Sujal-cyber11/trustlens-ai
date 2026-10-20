/**
 * TrustLens AI — Content Script Signal Collector (content.js)
 *
 * PRIVACY GUARANTEES:
 * - NEVER reads .value of any input, textarea, select, or contenteditable element.
 * - NEVER sends full page HTML or script source code.
 * - Strips query strings and fragments from URLs before sending.
 * - Redacts phones, emails, card numbers, PANs, and OTPs in the 500-char text sample locally.
 * - Scans at document_idle, up to 2 debounced MutationObserver rescans, and before form submit
 *   on pages with password fields.
 */
(function () {
  if (window.__trustlensContentScriptActive) {
    return;
  }
  window.__trustlensContentScriptActive = true;

  const proto = window.location.protocol;
  if (proto !== "http:" && proto !== "https:") {
    return;
  }

  const MAX_MUTATION_RESCANS = 2;
  let mutationRescanCount = 0;
  let mutationTimer = null;
  let typingInPassword = false;
  const hookSignalsMap = new Map();

  // Inject page_hooks.js to wrap permission APIs & programmatic download clicks in main world
  try {
    const scriptEl = document.createElement("script");
    scriptEl.src = chrome.runtime.getURL("page_hooks.js");
    scriptEl.onload = () => scriptEl.remove();
    (document.head || document.documentElement).appendChild(scriptEl);
  } catch (_) {
    // Ignore if blocked by strict CSP
  }

  window.addEventListener("__trustlens_hook_signal", (ev) => {
    if (!ev || !ev.detail || !ev.detail.id) return;
    const id = String(ev.detail.id);
    const evidence = String(ev.detail.evidence || "").slice(0, 110);
    const existing = hookSignalsMap.get(id);
    if (existing) {
      existing.count += 1;
    } else {
      hookSignalsMap.set(id, { id, severity: "High", evidence, count: 1 });
    }
  });

  // Track password focus so we never trigger mutation scans while the user is typing a password
  document.addEventListener("focusin", (e) => {
    if (e.target && e.target.tagName === "INPUT" && e.target.type === "password") {
      typingInPassword = true;
    }
  }, true);

  document.addEventListener("focusout", (e) => {
    if (e.target && e.target.tagName === "INPUT" && e.target.type === "password") {
      typingInPassword = false;
    }
  }, true);

  const MULTI_PART_SUFFIXES = new Set([
    "co.in", "gov.in", "org.in", "ac.in", "net.in",
    "co.uk", "org.uk", "com.au", "co.jp", "com.sg"
  ]);

  function getRegisteredDomain(hostname) {
    const clean = String(hostname || "").toLowerCase().replace(/\.+$/, "");
    if (!clean) return "";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return clean;
    const parts = clean.split(".").filter(Boolean);
    if (parts.length <= 2) return clean;
    const lastTwo = parts.slice(-2).join(".");
    if (MULTI_PART_SUFFIXES.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }

  function redactPii(text) {
    if (!text) return "";
    return String(text)
      .replace(/\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b/g, "[REDACTED_EMAIL]")
      .replace(/\b[A-Z]{5}\d{4}[A-Z]\b/g, "[REDACTED_PAN]")
      .replace(/\b\d{4,8}\b(?=\s*(?:is your|is the|otp|one time password|verification code))/gi, "[REDACTED_OTP]")
      .replace(/\b(otp\s+is|code\s+is|password\s+is|pin\s+is|otp[:\s-]+)\s*\d{4,8}\b/gi, "$1 [REDACTED_OTP]")
      .replace(/(?<!\d)(?:\d[ -]?){11,18}\d(?!\d)/g, "[REDACTED_CARD_OR_ID]")
      .replace(/(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)/g, "[REDACTED_PHONE]");
  }

  function addSignal(map, id, severity, evidence, count = 1) {
    const cleanEv = redactPii(String(evidence || "").replace(/\s+/g, " ").trim()).slice(0, 120);
    const prev = map.get(id);
    if (prev) {
      prev.count += count;
      if (!prev.evidence && cleanEv) prev.evidence = cleanEv;
    } else {
      map.set(id, { id, severity, evidence: cleanEv, count });
    }
  }

  function collectPageSignals(checksConfig) {
    const signals = new Map();
    const pageHost = window.location.hostname.toLowerCase();
    const pageRegDom = getRegisteredDomain(pageHost);
    const isHttpsPage = window.location.protocol === "https:";

    // Include any runtime hook signals captured so far
    for (const [k, v] of hookSignalsMap.entries()) {
      signals.set(k, { ...v });
    }

    // 1. Password / OTP inputs & cross-domain / HTTP form actions (NEVER read .value)
    if (checksConfig.checkForms !== false) {
      const inputs = Array.from(document.querySelectorAll("input"));
      let pwCount = 0;
      let otpCount = 0;

      for (const inp of inputs) {
        const typeAttr = String(inp.getAttribute("type") || "text").toLowerCase();
        const ident = `${inp.getAttribute("name") || ""} ${inp.getAttribute("id") || ""} ${inp.getAttribute("autocomplete") || ""}`.toLowerCase();
        if (typeAttr === "password") {
          pwCount += 1;
        } else if (/\b(otp|totp|mpin|upi[_-]?pin|cvv|passcode)\b/.test(ident)) {
          otpCount += 1;
        }
      }

      if (pwCount > 0 || otpCount > 0) {
        addSignal(
          signals,
          "password_or_otp_input",
          "Medium",
          `Sensitive fields present: password=${pwCount}, otp/pin=${otpCount}`,
          pwCount + otpCount
        );
      }

      const forms = Array.from(document.querySelectorAll("form"));
      for (const form of forms) {
        const hasSensitiveField = Boolean(
          form.querySelector('input[type="password"], input[name*="otp" i], input[name*="pin" i], input[name*="cvv" i]')
        );
        if (!hasSensitiveField && pwCount === 0) continue;

        const rawAction = String(form.getAttribute("action") || "").trim();
        if (!rawAction || rawAction.startsWith("#") || rawAction.toLowerCase().startsWith("javascript:")) {
          continue;
        }
        try {
          const resolved = new URL(rawAction, window.location.href);
          const actionRegDom = getRegisteredDomain(resolved.hostname);
          if (actionRegDom && pageRegDom && actionRegDom !== pageRegDom) {
            addSignal(
              signals,
              "cross_domain_password_form",
              "High",
              `Form on '${pageRegDom}' submits to external domain '${actionRegDom}'`,
              1
            );
          }
          if (resolved.protocol === "http:" && (isHttpsPage || hasSensitiveField)) {
            addSignal(
              signals,
              "insecure_http_form",
              "High",
              `Sensitive form submits over insecure HTTP to '${resolved.hostname}'`,
              1
            );
          }
        } catch (_) {
          // Ignore malformed form action
        }
      }
    }

    // 2. Hidden or cross-origin iframes & full-page transparent clickjacking overlays
    if (checksConfig.checkIframesAndOverlays !== false) {
      const iframes = Array.from(document.querySelectorAll("iframe"));
      let suspiciousIframeCount = 0;
      let iframeEvidence = "";
      for (const fr of iframes) {
        const src = String(fr.getAttribute("src") || "").trim();
        const rect = fr.getBoundingClientRect();
        const style = window.getComputedStyle(fr);
        const isHidden = rect.width <= 2 || rect.height <= 2 || parseFloat(style.opacity || "1") < 0.1 || style.visibility === "hidden";
        let isCrossDomain = false;
        if (src && !src.startsWith("about:") && !src.startsWith("javascript:")) {
          try {
            const u = new URL(src, window.location.href);
            const fDom = getRegisteredDomain(u.hostname);
            if (fDom && pageRegDom && fDom !== pageRegDom) {
              isCrossDomain = true;
            }
          } catch (_) {}
        }
        if (isHidden && isCrossDomain) {
          suspiciousIframeCount += 1;
          if (!iframeEvidence) iframeEvidence = `Hidden cross-origin iframe (${src.slice(0, 60)})`;
        }
      }
      if (suspiciousIframeCount > 0) {
        addSignal(signals, "hidden_or_cross_iframe", "Medium", iframeEvidence, suspiciousIframeCount);
      }

      // Clickjacking check: inspect interactive buttons/links using elementFromPoint at their center
      const buttons = Array.from(document.querySelectorAll("button, a[href], input[type='submit']")).slice(0, 15);
      let overlayHits = 0;
      for (const btn of buttons) {
        const r = btn.getBoundingClientRect();
        if (r.width < 20 || r.height < 12 || r.top < 0 || r.left < 0 || r.bottom > window.innerHeight) continue;
        const cx = r.left + r.width / 2;
        const cy = r.top + r.height / 2;
        const topEl = document.elementFromPoint(cx, cy);
        if (topEl && topEl !== btn && !btn.contains(topEl) && !topEl.contains(btn)) {
          const ts = window.getComputedStyle(topEl);
          const op = parseFloat(ts.opacity || "1");
          const z = parseInt(ts.zIndex || "0", 10);
          if (op < 0.15 || (topEl.tagName === "IFRAME" && op < 0.5) || (z > 999 && op < 0.25)) {
            overlayHits += 1;
          }
        }
      }
      if (overlayHits > 0) {
        addSignal(
          signals,
          "clickjack_overlay",
          "High",
          `Transparent high-z-index overlay intercepts clicks over ${overlayHits} button(s)`,
          overlayHits
        );
      }
    }

    // 3. Deceptive anchor tags whose visible text looks like a domain but href goes elsewhere
    if (checksConfig.checkDeceptiveLinks !== false) {
      const anchors = Array.from(document.querySelectorAll("a[href]")).slice(0, 120);
      const domainLikeRe = /\b(?:https?:\/\/)?((?:[a-z0-9-]+\.)+(?:com|in|org|net|co\.in|gov\.in|sbi|io|ai))\b/i;
      for (const a of anchors) {
        const visText = String(a.innerText || a.textContent || "").trim();
        if (!visText || visText.length > 120) continue;
        const m = visText.match(domainLikeRe);
        if (!m) continue;
        const claimedDom = getRegisteredDomain(m[1]);
        try {
          const hrefUrl = new URL(a.getAttribute("href"), window.location.href);
          if (hrefUrl.protocol !== "http:" && hrefUrl.protocol !== "https:") continue;
          const actualDom = getRegisteredDomain(hrefUrl.hostname);
          if (claimedDom && actualDom && claimedDom !== actualDom) {
            addSignal(
              signals,
              "deceptive_anchor_mismatch",
              "High",
              `Link text claims '${claimedDom}' but points to '${actualDom}'`,
              1
            );
          }
        } catch (_) {}
      }
    }

    // 5. Inline script obfuscation counts, clipboard hooks, disabled contextmenu / beforeunload traps
    if (checksConfig.checkScriptsAndHooks !== false) {
      const scripts = Array.from(document.querySelectorAll("script:not([src])")).slice(0, 40);
      let obfCount = 0;
      let docWriteCount = 0;
      let clipHookCount = 0;

      for (const s of scripts) {
        const code = String(s.textContent || "");
        if (!code) continue;
        const mObf = code.match(/\b(eval|Function|atob|unescape)\s*\(/g);
        if (mObf) obfCount += mObf.length;
        const mDw = code.match(/document\.write\s*\(\s*['"`][^'"`]*<script/gi);
        if (mDw) docWriteCount += mDw.length;
        if (/navigator\.clipboard\.writeText|addEventListener\s*\(\s*['"]copy['"]/i.test(code)) {
          clipHookCount += 1;
        }
      }

      if (obfCount >= 4) {
        addSignal(signals, "suspicious_inline_script", "Medium", `Inline scripts invoke eval/Function/atob ${obfCount} times`, obfCount);
      }
      if (docWriteCount > 0) {
        addSignal(signals, "document_write_script", "Medium", `Inline script injects <script> via document.write (${docWriteCount}x)`, docWriteCount);
      }
      if (clipHookCount > 0 || document.body?.getAttribute("oncopy")) {
        addSignal(signals, "clipboard_hijack_hook", "Medium", "Page registers copy/clipboard-write override hooks", clipHookCount || 1);
      }
      if (document.body?.getAttribute("oncontextmenu")?.includes("false") || document.body?.getAttribute("onbeforeunload")) {
        addSignal(signals, "contextmenu_or_unload_trap", "Medium", "Page blocks right-click contextmenu or traps tab unload", 1);
      }
    }

    const bodyText = String(document.body?.innerText || "").slice(0, 15000);
    const bodyLow = bodyText.toLowerCase();

    // 7. Fake system UI, fake virus alerts, and ClickFix (Win+R + Ctrl+V) patterns
    if (checksConfig.checkFakeSystemAndClickFix !== false) {
      if (
        (bodyLow.includes("win + r") || bodyLow.includes("win+r") || bodyLow.includes("windows + r")) &&
        (bodyLow.includes("ctrl + v") || bodyLow.includes("ctrl+v") || bodyLow.includes("powershell") || bodyLow.includes("cmd") || bodyLow.includes("command"))
      ) {
        addSignal(
          signals,
          "clickfix_command_trap",
          "High",
          "Page instructs user to press Win+R and paste a command into Run/PowerShell (ClickFix)",
          1
        );
      }

      if (
        /(your pc is infected|virus detected|trojan detected|windows defender alert|system damaged)/i.test(bodyText) &&
        /(call|toll-free|helpline|1800-|support desk|immediately)/i.test(bodyText)
      ) {
        addSignal(
          signals,
          "fake_system_dialog",
          "High",
          "Fake virus/system infection alert paired with urgent tech-support phone number",
          1
        );
      }
    }

    // 8-11. Dark Patterns Detection
    if (checksConfig.checkDarkPatterns !== false) {
      // 8a. Countdown timers that reset on reload (verified via sessionStorage)
      const timerCandidate = document.querySelector("[data-countdown], .timer, .countdown, [id*='timer' i], [class*='countdown' i]");
      const timeRegex = /\b([0-5]?\d):([0-5]\d)(?::([0-5]\d))?\b/;
      const timerMatch = (timerCandidate ? timerCandidate.textContent : bodyText).match(timeRegex);
      if (timerMatch) {
        const parts = timerMatch[0].split(":").map(Number);
        const totalSec = parts.length === 3 ? parts[0] * 3600 + parts[1] * 60 + parts[2] : parts[0] * 60 + parts[1];
        if (totalSec > 0 && totalSec <= 3600) {
          const storageKey = `__tl_timer_${window.location.pathname}`;
          try {
            const prevRaw = sessionStorage.getItem(storageKey);
            if (prevRaw) {
              const prev = JSON.parse(prevRaw);
              const elapsedReal = (Date.now() - prev.ts) / 1000;
              // If timer reset back up or stayed nearly identical across a reload
              if (elapsedReal >= 2 && totalSec >= prev.sec - 1) {
                addSignal(
                  signals,
                  "resetting_countdown_timer",
                  "Medium",
                  `Countdown timer (${timerMatch[0]}) resets on page reload`,
                  1
                );
              }
            }
            sessionStorage.setItem(storageKey, JSON.stringify({ sec: totalSec, ts: Date.now() }));
          } catch (_) {}
        }
      }

      // 8b. Fake urgency / scarcity claims
      const scarcityMatch = bodyText.match(/\b(only\s+\d+\s+left\s+in\s+stock|\d+\s+people\s+viewing\s+now|hurry!\s+offer\s+expires\s+in)\b/i);
      if (scarcityMatch) {
        addSignal(signals, "fake_urgency_scarcity", "Medium", `Scarcity/urgency pressure: '${scarcityMatch[0]}'`, 1);
      }

      // 9a. Pre-checked checkboxes for add-ons, insurance, marketing, or continuity
      const checkedBoxes = Array.from(document.querySelectorAll("input[type='checkbox'][checked], input[type='checkbox']:checked"));
      for (const cb of checkedBoxes) {
        const labelText = String(cb.closest("label")?.innerText || cb.parentElement?.innerText || "").trim();
        if (/(insurance|warranty|add-on|protection|newsletter|promotional|marketing|auto-renew|monthly|₹|\$|rs\.?)/i.test(labelText)) {
          addSignal(
            signals,
            "prechecked_addon_box",
            "Medium",
            `Pre-checked checkbox: '${labelText.slice(0, 75)}'`,
            1
          );
        }
      }

      // 9b. Forced continuity & hidden drip-pricing hints
      if (/(auto-renews\s+monthly\s+unless\s+cancelled|charged\s+automatically\s+after\s+trial)/i.test(bodyText)) {
        addSignal(signals, "forced_continuity_wording", "Medium", "Forced continuity auto-renewal terms detected", 1);
      }
      if (/(mandatory\s+.*\s+(processing|convenience|service)\s+fee\s+will\s+be\s+added)/i.test(bodyText)) {
        addSignal(signals, "hidden_drip_pricing", "Medium", "Late-stage mandatory processing/convenience fee disclosure", 1);
      }

      // 10a. Confirm-shaming button/link text
      const clickables = Array.from(document.querySelectorAll("button, a, [role='button'], [data-confirm-shame]")).slice(0, 100);
      for (const el of clickables) {
        const txt = String(el.innerText || el.textContent || "").trim();
        if (txt.length >= 12 && txt.length <= 140) {
          if (/^no\s+thanks?,?\s+i\s+(don't\s+want|prefer\s+paying|hate\s+saving|don't\s+care)/i.test(txt) || el.hasAttribute("data-confirm-shame")) {
            addSignal(signals, "confirm_shaming", "Medium", `Confirm-shaming button: '${txt.slice(0, 75)}'`, 1);
          }
        }
      }

      // 10b. Asymmetric choice UI (Accept button vastly larger/more visible than Reject button)
      const acceptBtns = clickables.filter(el => /\b(accept\s+all|agree\s+&\s+continue|allow\s+all)\b/i.test(el.innerText || ""));
      const rejectBtns = clickables.filter(el => /\b(reject|decline|manage\s*\/\s*reject|refuse)\b/i.test(el.innerText || ""));
      if (acceptBtns.length > 0 && rejectBtns.length > 0) {
        const aRect = acceptBtns[0].getBoundingClientRect();
        const rRect = rejectBtns[0].getBoundingClientRect();
        const aArea = Math.max(1, aRect.width * aRect.height);
        const rArea = Math.max(1, rRect.width * rRect.height);
        const rOpacity = parseFloat(window.getComputedStyle(rejectBtns[0]).opacity || "1");
        if (aArea / rArea >= 3.0 || rOpacity <= 0.5) {
          addSignal(
            signals,
            "asymmetric_choice_ui",
            "Medium",
            `Accept button is ${(aArea / rArea).toFixed(1)}x larger (reject opacity=${rOpacity})`,
            1
          );
        }
      }

      // 10c. Misdirection close ('X') buttons that actually link to an external URL
      const closeLinks = Array.from(document.querySelectorAll("a.close-btn, a[aria-label='Close' i]"));
      for (const cl of closeLinks) {
        const h = String(cl.getAttribute("href") || "");
        if (h.startsWith("http://") || h.startsWith("https://")) {
          addSignal(signals, "misdirection_close_button", "Medium", `Close '✕' button links to '${h.slice(0, 60)}'`, 1);
        }
      }
    }

    const cleanUrl = `${window.location.origin}${window.location.pathname}`;
    const sample = redactPii(bodyText.replace(/\s+/g, " ").trim().slice(0, 500));

    return {
      url: cleanUrl,
      hostname: pageHost,
      title: redactPii(String(document.title || "").trim()).slice(0, 200),
      signals: Array.from(signals.values()),
      text_sample: sample
    };
  }

  function runPageScan(reason) {
    if (typingInPassword && reason === "mutation") {
      return;
    }
    chrome.storage.local.get(
      {
        globalPaused: false,
        pausedHosts: [],
        neverScanHosts: [],
        language: "en",
        checksConfig: {
          checkForms: true,
          checkIframesAndOverlays: true,
          checkDeceptiveLinks: true,
          checkScriptsAndHooks: true,
          checkFakeSystemAndClickFix: true,
          checkDarkPatterns: true
        }
      },
      (cfg) => {
        if (cfg.globalPaused) {
          window.__trustlensBannerController?.remove();
          return;
        }
        const host = window.location.hostname.toLowerCase();
        const isSkipped = [...(cfg.pausedHosts || []), ...(cfg.neverScanHosts || [])].some(
          (d) => host === d.toLowerCase() || host.endsWith("." + d.toLowerCase())
        );
        if (isSkipped) {
          window.__trustlensBannerController?.remove();
          return;
        }

        const payload = collectPageSignals(cfg.checksConfig || {});
        payload.language = cfg.language || "en";

        chrome.runtime.sendMessage(
          { type: "TRUSTLENS_AUDIT_PAGE", payload, force: reason === "form_submit" },
          (response) => {
            if (chrome.runtime.lastError || !response || response.status !== "success") {
              return;
            }
            window.__trustlensBannerController?.show(response.data, payload.language);
          }
        );
      }
    );
  }

  // Initial scan at document_idle
  runPageScan("initial");

  // Debounced MutationObserver (max 2 rescans per page load)
  const observer = new MutationObserver(() => {
    if (mutationRescanCount >= MAX_MUTATION_RESCANS || typingInPassword) {
      return;
    }
    if (mutationTimer) clearTimeout(mutationTimer);
    mutationTimer = setTimeout(() => {
      mutationRescanCount += 1;
      runPageScan("mutation");
    }, 1800);
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // Pre-submit check on forms containing a password field
  document.addEventListener("submit", (e) => {
    const form = e.target;
    if (form && form.querySelector && form.querySelector('input[type="password"]')) {
      runPageScan("form_submit");
    }
  }, true);
})();