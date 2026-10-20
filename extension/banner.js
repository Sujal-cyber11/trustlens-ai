/**
 * TrustLens AI — Closed Shadow DOM In-Page Banner (banner.js)
 * Renders a small, dismissible friendly explanation banner for Medium and High risk verdicts.
 * Uses mode: 'closed' so host page CSS/JS cannot read, spoof, or restyle the warning.
 * Uses only textContent / DOM node construction (zero innerHTML with untrusted strings).
 */
(function () {
  if (window.__trustlensBannerController) {
    return;
  }

  let hostElement = null;
  let closedRoot = null;

  function removeExistingBanner() {
    if (hostElement && hostElement.parentNode) {
      hostElement.parentNode.removeChild(hostElement);
    }
    hostElement = null;
    closedRoot = null;
  }

  function showTrustLensBanner(payload, lang) {
    if (!payload || !payload.analysis) {
      return;
    }
    const analysis = payload.analysis;
    const risk = String(analysis.overall_risk_score || "Low");
    if (risk !== "High" && risk !== "Medium") {
      removeExistingBanner();
      return;
    }

    removeExistingBanner();

    hostElement = document.createElement("div");
    hostElement.setAttribute("data-trustlens-host", "1");
    hostElement.style.all = "initial";
    hostElement.style.position = "fixed";
    hostElement.style.bottom = "18px";
    hostElement.style.right = "18px";
    hostElement.style.zIndex = "2147483647";
    hostElement.style.maxWidth = "440px";
    hostElement.style.width = "calc(100vw - 36px)";

    closedRoot = hostElement.attachShadow({ mode: "closed" });

    const isHigh = risk === "High";
    const accentBg = isHigh ? "#991b1b" : "#b45309";
    const borderCol = isHigh ? "#ef4444" : "#f59e0b";
    const score = Number(analysis.numeric_risk_score || 0);
    const malScore = Number(analysis.malicious_score || 0);
    const dpScore = Number(analysis.dark_pattern_score || 0);
    const useHi = lang === "hi";

    const style = document.createElement("style");
    style.textContent = `
      .tl-card {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #0b1120;
        color: #f8fafc;
        border: 2px solid ${borderCol};
        border-radius: 12px;
        box-shadow: 0 18px 38px rgba(0,0,0,0.65);
        overflow: hidden;
        font-size: 13px;
        line-height: 1.45;
      }
      .tl-header {
        background: ${accentBg};
        padding: 9px 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
      }
      .tl-badge {
        font-weight: 800;
        font-size: 12.5px;
        color: #ffffff;
        letter-spacing: 0.2px;
      }
      .tl-close {
        background: rgba(0,0,0,0.25);
        color: #ffffff;
        border: none;
        border-radius: 6px;
        width: 24px;
        height: 24px;
        cursor: pointer;
        font-weight: bold;
        font-size: 13px;
      }
      .tl-close:hover { background: rgba(0,0,0,0.45); }
      .tl-body {
        padding: 12px 14px;
        display: flex;
        flex-direction: column;
        gap: 8px;
        max-height: 360px;
        overflow-y: auto;
      }
      .tl-calm {
        background: #1e293b;
        color: #38bdf8;
        padding: 8px 10px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 12.5px;
      }
      .tl-subscores {
        display: flex;
        gap: 8px;
        font-size: 11px;
        color: #cbd5e1;
      }
      .tl-pill {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 3px 8px;
      }
      .tl-section {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 7px 10px;
        font-size: 12px;
      }
      .tl-label {
        font-weight: 700;
        display: block;
        margin-bottom: 2px;
      }
      .tl-actions {
        display: flex;
        gap: 6px;
        padding: 8px 14px 12px;
        background: #0b1120;
      }
      .tl-btn {
        flex: 1;
        padding: 6px 10px;
        border-radius: 7px;
        border: 1px solid #334155;
        background: #1e293b;
        color: #e2e8f0;
        font-size: 11.5px;
        font-weight: 700;
        cursor: pointer;
      }
      .tl-btn:hover { background: #334155; }
      .tl-btn-danger {
        background: #dc2626;
        border-color: #ef4444;
        color: #ffffff;
      }
    `;

    const card = document.createElement("div");
    card.className = "tl-card";

    // Header
    const header = document.createElement("div");
    header.className = "tl-header";

    const titleSpan = document.createElement("span");
    titleSpan.className = "tl-badge";
    titleSpan.textContent = `🛡️ TrustLens AI: ${risk.toUpperCase()} RISK (${score}/100)`;

    const closeBtn = document.createElement("button");
    closeBtn.className = "tl-close";
    closeBtn.type = "button";
    closeBtn.title = "Dismiss";
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", removeExistingBanner);

    header.appendChild(titleSpan);
    header.appendChild(closeBtn);
    card.appendChild(header);

    // Body
    const body = document.createElement("div");
    body.className = "tl-body";

    const calmDiv = document.createElement("div");
    calmDiv.className = "tl-calm";
    calmDiv.textContent = useHi
      ? (analysis.calm_down_message_hi || analysis.calm_down_message || "")
      : (analysis.calm_down_message || "");
    body.appendChild(calmDiv);

    const subRow = document.createElement("div");
    subRow.className = "tl-subscores";
    const malPill = document.createElement("span");
    malPill.className = "tl-pill";
    malPill.textContent = `Malicious Score: ${malScore}/100`;
    const dpPill = document.createElement("span");
    dpPill.className = "tl-pill";
    dpPill.textContent = `Dark Patterns: ${dpScore}/100`;
    subRow.appendChild(malPill);
    subRow.appendChild(dpPill);
    body.appendChild(subRow);

    function addPillar(labelText, labelColor, bodyText) {
      if (!bodyText) return;
      const sec = document.createElement("div");
      sec.className = "tl-section";
      const lbl = document.createElement("span");
      lbl.className = "tl-label";
      lbl.style.color = labelColor;
      lbl.textContent = labelText;
      const txt = document.createElement("div");
      txt.textContent = bodyText;
      sec.appendChild(lbl);
      sec.appendChild(txt);
      body.appendChild(sec);
    }

    addPillar(
      useHi ? "📌 यह किस बारे में है:" : "📌 What this is about:",
      "#38bdf8",
      useHi ? (analysis.what_input_is_about_hi || analysis.what_input_is_about) : analysis.what_input_is_about
    );
    addPillar(
      useHi ? "🎭 यह क्या होने का दिखावा करता है:" : "🎭 What it seems to be:",
      "#fbbf24",
      useHi ? (analysis.what_it_seems_to_be_hi || analysis.what_it_seems_to_be) : analysis.what_it_seems_to_be
    );
    addPillar(
      useHi ? "💥 यह आपको कैसे प्रभावित करता है:" : "💥 How it affects you:",
      "#f87171",
      useHi ? (analysis.how_it_affects_user_hi || analysis.how_it_affects_user) : analysis.how_it_affects_user
    );

    const acts = useHi
      ? (analysis.recommended_actions_hi && analysis.recommended_actions_hi.length ? analysis.recommended_actions_hi : analysis.recommended_actions)
      : analysis.recommended_actions;
    if (Array.isArray(acts) && acts.length > 0) {
      addPillar(
        useHi ? "✅ सुरक्षित कदम:" : "✅ Recommended Actions:",
        "#34d399",
        acts.map(a => `• ${a}`).join("\n")
      );
    }

    card.appendChild(body);

    // Footer buttons
    const footer = document.createElement("div");
    footer.className = "tl-actions";

    const safeBtn = document.createElement("button");
    safeBtn.className = "tl-btn";
    safeBtn.type = "button";
    safeBtn.textContent = useHi ? "✅ यह पेज सुरक्षित है" : "✅ Mark Safe (Pause Site)";
    safeBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({
        type: "TRUSTLENS_FEEDBACK",
        feedback_type: "false_positive",
        hostname: window.location.hostname,
        url: window.location.origin + window.location.pathname
      });
      removeExistingBanner();
    });

    const dismissBtn = document.createElement("button");
    dismissBtn.className = "tl-btn tl-btn-danger";
    dismissBtn.type = "button";
    dismissBtn.textContent = useHi ? "समझ गया (बंद करें)" : "Got It (Dismiss)";
    dismissBtn.addEventListener("click", removeExistingBanner);

    footer.appendChild(safeBtn);
    footer.appendChild(dismissBtn);
    card.appendChild(footer);

    closedRoot.appendChild(style);
    closedRoot.appendChild(card);

    (document.body || document.documentElement).appendChild(hostElement);
  }

  window.__trustlensBannerController = {
    show: showTrustLensBanner,
    remove: removeExistingBanner
  };
})();