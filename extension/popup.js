/**
 * TrustLens AI — Popup Controller (popup.js)
 * Renders current page verdict, scores, top 3 indicators, pause controls, report flow, and EN/HI toggle.
 */
document.addEventListener("DOMContentLoaded", async () => {
  const verdictCard = document.getElementById("verdictCard");
  const verdictTitle = document.getElementById("verdictTitle");
  const subScoreLine = document.getElementById("subScoreLine");
  const calmLine = document.getElementById("calmLine");
  const indContainer = document.getElementById("indicatorsContainer");
  const pauseSiteBtn = document.getElementById("pauseSiteBtn");
  const pauseGlobalBtn = document.getElementById("pauseGlobalBtn");
  const markSafeBtn = document.getElementById("markSafeBtn");
  const reportBtn = document.getElementById("reportBtn");
  const langToggleBtn = document.getElementById("langToggleBtn");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabUrl = tab?.url || "";
  let currentHost = "";
  try {
    currentHost = new URL(tabUrl).hostname.toLowerCase();
  } catch (_) {}

  let cfg = await chrome.storage.local.get({
    globalPaused: false,
    pausedHosts: [],
    language: "en"
  });

  function updatePauseLabels() {
    pauseGlobalBtn.textContent = cfg.globalPaused ? "▶️ Resume Everywhere" : "⏸️ Pause Everywhere";
    const sitePaused = (cfg.pausedHosts || []).includes(currentHost);
    pauseSiteBtn.textContent = sitePaused ? "▶️ Resume on This Site" : "⏸️ Pause on This Site";
    langToggleBtn.textContent = cfg.language === "hi" ? "🌐 हिंदी (HI)" : "🌐 English (EN)";
  }

  updatePauseLabels();

  function renderVerdict(data) {
    if (!data || !data.analysis) {
      verdictTitle.textContent = "No scan data for this tab yet";
      calmLine.textContent = "Reload the tab or ensure the TrustLens desktop app is running.";
      return;
    }
    const a = data.analysis;
    const risk = String(a.overall_risk_score || "Low");
    const score = Number(a.numeric_risk_score || 0);
    const mal = Number(a.malicious_score || 0);
    const dp = Number(a.dark_pattern_score || 0);
    const useHi = cfg.language === "hi";

    verdictCard.style.borderColor = risk === "High" ? "#ef4444" : risk === "Medium" ? "#f59e0b" : "#10b981";
    verdictTitle.textContent = `${risk.toUpperCase()} RISK (${score}/100) — ${a.fraud_category || ""}`;
    subScoreLine.textContent = `Malicious Behaviour: ${mal}/100  |  Dark Patterns: ${dp}/100`;
    calmLine.textContent = useHi ? (a.calm_down_message_hi || a.calm_down_message || "") : (a.calm_down_message || "");

    indContainer.textContent = "";
    const topInds = (a.indicators || []).slice(0, 3);
    if (topInds.length === 0) {
      const cleanEl = document.createElement("div");
      cleanEl.style.color = "#10b981";
      cleanEl.textContent = useHi ? "✓ कोई दुर्भावनापूर्ण या डार्क पैटर्न संकेत नहीं मिला।" : "✓ Zero malicious or dark-pattern indicators triggered.";
      indContainer.appendChild(cleanEl);
    } else {
      for (const ind of topInds) {
        const row = document.createElement("div");
        row.className = "ind-item";
        const b = document.createElement("b");
        b.style.color = ind.severity === "High" ? "#f87171" : "#fbbf24";
        b.textContent = `[${ind.severity}] ${ind.indicator_type}: `;
        const span = document.createElement("span");
        span.textContent = `${ind.target_element} — ${ind.explanation}`;
        row.appendChild(b);
        row.appendChild(span);
        indContainer.appendChild(row);
      }
    }
  }

  chrome.runtime.sendMessage(
    { type: "TRUSTLENS_GET_TAB_VERDICT", tabId: tab?.id, url: tabUrl },
    (res) => {
      if (res && res.status === "success") {
        renderVerdict(res.data);
      } else {
        verdictTitle.textContent = res?.reason || "Page not scanned yet";
        calmLine.textContent = "Open any HTTP/HTTPS webpage while TrustLens is running.";
      }
    }
  );

  langToggleBtn.addEventListener("click", async () => {
    cfg.language = cfg.language === "en" ? "hi" : "en";
    await chrome.storage.local.set({ language: cfg.language });
    updatePauseLabels();
    chrome.runtime.sendMessage({ type: "TRUSTLENS_GET_TAB_VERDICT", tabId: tab?.id, url: tabUrl }, (res) => {
      if (res && res.status === "success") renderVerdict(res.data);
    });
  });

  pauseGlobalBtn.addEventListener("click", async () => {
    cfg.globalPaused = !cfg.globalPaused;
    await chrome.storage.local.set({ globalPaused: cfg.globalPaused });
    updatePauseLabels();
  });

  pauseSiteBtn.addEventListener("click", async () => {
    if (!currentHost) return;
    const set = new Set(cfg.pausedHosts || []);
    if (set.has(currentHost)) set.delete(currentHost);
    else set.add(currentHost);
    cfg.pausedHosts = Array.from(set);
    await chrome.storage.local.set({ pausedHosts: cfg.pausedHosts });
    updatePauseLabels();
  });

  markSafeBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "TRUSTLENS_FEEDBACK",
      feedback_type: "false_positive",
      hostname: currentHost,
      url: tabUrl
    }, () => {
      calmLine.textContent = "✅ Marked safe & added to site pause list.";
    });
  });

  reportBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "TRUSTLENS_FEEDBACK",
      feedback_type: "confirm_scam",
      hostname: currentHost,
      url: tabUrl
    }, () => {
      chrome.tabs.create({ url: "https://cybercrime.gov.in" });
    });
  });

  document.getElementById("openOptionsLink").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  document.getElementById("openDashboardLink").addEventListener("click", () => {
    chrome.tabs.create({ url: "http://127.0.0.1:8000" });
  });
});