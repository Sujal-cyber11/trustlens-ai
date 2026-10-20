/**
 * TrustLens AI — Closed Shadow DOM In-Page Banner with Inline SVG Pie Chart (banner.js)
 *
 * - Draws the per-alert 'Why is this risky?' pie chart using pure inline SVG (`createElementNS`)
 *   and `textContent` from `analysis.score_breakdown`.
 * - Includes 'Show as list' table fallback for screen readers and switches labels on EN/HI toggle.
 * - Zero remote code, zero CDN, zero innerHTML.
 */
(function () {
  if (window.__trustlensBannerController) {
    return;
  }

  let hostElement = null;
  let closedRoot = null;
  let currentLang = "en";

  const PALETTE = ["#EF4444", "#F97316", "#EAB308", "#A855F7", "#38BDF8", "#10B981"];

  function removeExistingBanner() {
    if ("speechSynthesis" in window) {
      window.speechSynthesis.cancel();
    }
    if (hostElement && hostElement.parentNode) {
      hostElement.parentNode.removeChild(hostElement);
    }
    hostElement = null;
    closedRoot = null;
  }

  function fallbackVerdict(risk, lang) {
    const r = String(risk || "Low").toLowerCase();
    if (lang === "hi") {
      if (r.startsWith("high")) return "🛑 यह एक धोखा है";
      if (r.startsWith("med")) return "⚠️ सावधान रहें";
      return "✅ यह सुरक्षित लगता है";
    }
    if (r.startsWith("high")) return "🛑 This is a scam";
    if (r.startsWith("med")) return "⚠️ Be careful";
    return "✅ This looks safe";
  }

  function createSvgPie(breakdown, totalScore) {
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", "0 0 120 120");
    svg.setAttribute("width", "110");
    svg.setAttribute("height", "110");

    const cx = 60;
    const cy = 60;
    const r = 48;
    const sumPts = breakdown.reduce((acc, s) => acc + Math.max(0, Number(s.points || 0)), 0);

    if (sumPts <= 0 || breakdown.length === 1) {
      const circle = document.createElementNS(svgNS, "circle");
      circle.setAttribute("cx", String(cx));
      circle.setAttribute("cy", String(cy));
      circle.setAttribute("r", String(r));
      const col = breakdown[0]?.key === "nothing_suspicious" ? "#10B981" : PALETTE[0];
      circle.setAttribute("fill", col);
      svg.appendChild(circle);
    } else {
      let startAngle = -Math.PI / 2;
      breakdown.forEach((s, idx) => {
        const pts = Math.max(0, Number(s.points || 0));
        if (pts <= 0) return;
        const angle = (pts / sumPts) * Math.PI * 2;
        const endAngle = startAngle + angle;
        const x1 = cx + r * Math.cos(startAngle);
        const y1 = cy + r * Math.sin(startAngle);
        const x2 = cx + r * Math.cos(endAngle);
        const y2 = cy + r * Math.sin(endAngle);
        const largeArc = angle > Math.PI ? 1 : 0;

        const path = document.createElementNS(svgNS, "path");
        const d = `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2} Z`;
        path.setAttribute("d", d);
        path.setAttribute("fill", PALETTE[idx % (PALETTE.length - 1)]);
        path.setAttribute("stroke", "#0b1120");
        path.setAttribute("stroke-width", "2");
        svg.appendChild(path);
        startAngle = endAngle;
      });
    }

    const inner = document.createElementNS(svgNS, "circle");
    inner.setAttribute("cx", String(cx));
    inner.setAttribute("cy", String(cy));
    inner.setAttribute("r", "26");
    inner.setAttribute("fill", "#0b1120");
    svg.appendChild(inner);

    const text = document.createElementNS(svgNS, "text");
    text.setAttribute("x", String(cx));
    text.setAttribute("y", String(cy + 4));
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("fill", "#f8fafc");
    text.setAttribute("font-size", "12");
    text.setAttribute("font-weight", "bold");
    text.textContent = `${totalScore}/100`;
    svg.appendChild(text);

    return svg;
  }

  function showTrustLensBanner(payload, lang) {
    if (!payload || !payload.analysis) {
      return;
    }
    currentLang = lang === "hi" ? "hi" : "en";
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
    hostElement.style.maxWidth = "460px";
    hostElement.style.width = "calc(100vw - 36px)";

    closedRoot = hostElement.attachShadow({ mode: "closed" });

    const isHigh = risk === "High";
    const accentBg = isHigh ? "#991b1b" : "#b45309";
    const borderCol = isHigh ? "#ef4444" : "#f59e0b";

    const style = document.createElement("style");
    style.textContent = `
      .tl-card {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: #0b1120;
        color: #f8fafc;
        border: 3px solid ${borderCol};
        border-radius: 14px;
        box-shadow: 0 20px 42px rgba(0,0,0,0.75);
        overflow: hidden;
        font-size: 15px;
        line-height: 1.5;
      }
      .tl-header {
        background: ${accentBg};
        padding: 12px 14px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
      }
      .tl-verdict { font-weight: 800; font-size: 18px; color: #ffffff; }
      .tl-top-btns { display: flex; gap: 6px; align-items: center; }
      .tl-small-btn {
        background: rgba(0,0,0,0.35);
        color: #ffffff;
        border: 1px solid rgba(255,255,255,0.3);
        border-radius: 7px;
        padding: 4px 8px;
        cursor: pointer;
        font-weight: 700;
        font-size: 12px;
      }
      .tl-body {
        padding: 14px;
        display: flex;
        flex-direction: column;
        gap: 10px;
        max-height: 440px;
        overflow-y: auto;
      }
      .tl-calm {
        background: #1e293b;
        color: #7dd3fc;
        padding: 10px 12px;
        border-radius: 10px;
        font-weight: 700;
        font-size: 15px;
      }
      .tl-lines {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 10px 12px;
        display: flex;
        flex-direction: column;
        gap: 6px;
        font-size: 15px;
      }
      .tl-pie-box {
        background: #111827;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 10px 12px;
      }
      .tl-pie-row {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .tl-legend {
        display: flex;
        flex-direction: column;
        gap: 5px;
        font-size: 13.5px;
      }
      .tl-legend-item {
        display: flex;
        align-items: center;
        gap: 6px;
        font-weight: 600;
      }
      .tl-swatch {
        width: 12px;
        height: 12px;
        border-radius: 3px;
        display: inline-block;
        flex-shrink: 0;
      }
      .tl-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 13px;
      }
      .tl-table td, .tl-table th {
        border: 1px solid #334155;
        padding: 4px 8px;
        text-align: left;
      }
      .tl-steps {
        background: #064e3b;
        border: 1px solid #059669;
        border-radius: 10px;
        padding: 10px 12px;
        font-size: 15px;
        font-weight: 700;
        color: #ffffff;
      }
      .tl-more-btn {
        background: #1e293b;
        color: #cbd5e1;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 7px 10px;
        font-size: 13px;
        font-weight: 700;
        text-align: left;
        cursor: pointer;
      }
      .tl-details {
        display: none;
        background: #080d1a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 10px;
        font-family: monospace;
        font-size: 12px;
        color: #94a3b8;
        white-space: pre-wrap;
      }
      .tl-actions {
        display: flex;
        gap: 8px;
        padding: 10px 14px 14px;
        background: #0b1120;
      }
      .tl-btn {
        flex: 1;
        padding: 9px 10px;
        border-radius: 8px;
        border: 1px solid #334155;
        background: #1e293b;
        color: #f8fafc;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
      }
      .tl-btn-danger {
        background: #dc2626;
        border-color: #ef4444;
        color: #ffffff;
      }
    `;

    const card = document.createElement("div");
    card.className = "tl-card";

    const header = document.createElement("div");
    header.className = "tl-header";

    const verdictEl = document.createElement("span");
    verdictEl.className = "tl-verdict";

    const topBtns = document.createElement("div");
    topBtns.className = "tl-top-btns";

    const speakBtn = document.createElement("button");
    speakBtn.className = "tl-small-btn";
    speakBtn.type = "button";
    speakBtn.textContent = "🔊";

    const langBtn = document.createElement("button");
    langBtn.className = "tl-small-btn";
    langBtn.type = "button";

    const closeBtn = document.createElement("button");
    closeBtn.className = "tl-small-btn";
    closeBtn.type = "button";
    closeBtn.textContent = "✕";
    closeBtn.addEventListener("click", removeExistingBanner);

    topBtns.appendChild(speakBtn);
    topBtns.appendChild(langBtn);
    topBtns.appendChild(closeBtn);
    header.appendChild(verdictEl);
    header.appendChild(topBtns);
    card.appendChild(header);

    const body = document.createElement("div");
    body.className = "tl-body";

    const calmEl = document.createElement("div");
    calmEl.className = "tl-calm";
    body.appendChild(calmEl);

    const linesBox = document.createElement("div");
    linesBox.className = "tl-lines";
    const aboutEl = document.createElement("div");
    const seemsEl = document.createElement("div");
    seemsEl.style.color = "#fde68a";
    const affectsEl = document.createElement("div");
    affectsEl.style.color = "#fca5a5";
    affectsEl.style.fontWeight = "700";
    linesBox.appendChild(aboutEl);
    linesBox.appendChild(seemsEl);
    linesBox.appendChild(affectsEl);
    body.appendChild(linesBox);

    const pieContainer = document.createElement("div");
    body.appendChild(pieContainer);

    const stepsBox = document.createElement("div");
    stepsBox.className = "tl-steps";
    body.appendChild(stepsBox);

    const moreBtn = document.createElement("button");
    moreBtn.className = "tl-more-btn";
    moreBtn.type = "button";
    body.appendChild(moreBtn);

    const detailsBox = document.createElement("div");
    detailsBox.className = "tl-details";
    body.appendChild(detailsBox);

    let detailsOpen = false;
    moreBtn.addEventListener("click", () => {
      detailsOpen = !detailsOpen;
      detailsBox.style.display = detailsOpen ? "block" : "none";
      moreBtn.textContent = detailsOpen
        ? (currentLang === "hi" ? "▲ जानकारी छुपाएं" : "▲ Hide details")
        : (currentLang === "hi" ? "▼ और जानकारी देखें" : "▼ More details");
    });

    card.appendChild(body);

    const footer = document.createElement("div");
    footer.className = "tl-actions";

    const safeBtn = document.createElement("button");
    safeBtn.className = "tl-btn";
    safeBtn.type = "button";
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
    dismissBtn.addEventListener("click", removeExistingBanner);

    footer.appendChild(safeBtn);
    footer.appendChild(dismissBtn);
    card.appendChild(footer);

    let listOpen = false;

    function renderLanguageContent() {
      const useHi = currentLang === "hi";
      langBtn.textContent = useHi ? "EN" : "हिं";
      const score = Number(analysis.numeric_risk_score || 0);

      verdictEl.textContent = (useHi ? analysis.verdict_line_hi : analysis.verdict_line) || fallbackVerdict(risk, currentLang);
      calmEl.textContent = (useHi ? analysis.calm_down_message_hi : analysis.calm_down_message) || analysis.calm_down_message || "";
      aboutEl.textContent = (useHi ? analysis.what_input_is_about_hi : analysis.what_input_is_about) || analysis.what_input_is_about || "";
      seemsEl.textContent = (useHi ? analysis.what_it_seems_to_be_hi : analysis.what_it_seems_to_be) || analysis.what_it_seems_to_be || "";
      affectsEl.textContent = (useHi ? analysis.how_it_affects_user_hi : analysis.how_it_affects_user) || analysis.how_it_affects_user || "";

      // Render inline SVG pie chart from score_breakdown
      pieContainer.textContent = "";
      const breakdown = Array.isArray(analysis.score_breakdown) ? analysis.score_breakdown : [];
      if (breakdown.length > 0) {
        const pieBox = document.createElement("div");
        pieBox.className = "tl-pie-box";

        const topRow = document.createElement("div");
        topRow.style.display = "flex";
        topRow.style.justifyContent = "space-between";
        topRow.style.alignItems = "center";
        topRow.style.marginBottom = "6px";

        const pTitle = document.createElement("strong");
        pTitle.textContent = useHi ? "🥧 इसमें क्या जोखिम है?" : "🥧 Why is this risky?";

        const listToggle = document.createElement("button");
        listToggle.className = "tl-small-btn";
        listToggle.type = "button";
        listToggle.textContent = useHi ? "लिस्ट में देखें" : "Show as list";

        topRow.appendChild(pTitle);
        topRow.appendChild(listToggle);
        pieBox.appendChild(topRow);

        const pieRow = document.createElement("div");
        pieRow.className = "tl-pie-row";
        pieRow.appendChild(createSvgPie(breakdown, score));

        const legend = document.createElement("div");
        legend.className = "tl-legend";

        const tbl = document.createElement("table");
        tbl.className = "tl-table";
        tbl.style.display = listOpen ? "table" : "none";

        const ptsWord = useHi ? "अंक" : "pts";
        breakdown.forEach((s, idx) => {
          const sLbl = useHi ? (s.label_hi || s.label_en) : s.label_en;
          const pts = Number(s.points || 0);
          const col = s.key === "nothing_suspicious" ? "#10B981" : PALETTE[idx % (PALETTE.length - 1)];

          const row = document.createElement("div");
          row.className = "tl-legend-item";
          const sw = document.createElement("span");
          sw.className = "tl-swatch";
          sw.style.background = col;
          const sp = document.createElement("span");
          sp.textContent = `${sLbl}: ${pts} ${ptsWord}`;
          row.appendChild(sw);
          row.appendChild(sp);
          legend.appendChild(row);

          const tr = document.createElement("tr");
          const td1 = document.createElement("td");
          td1.textContent = sLbl;
          const td2 = document.createElement("td");
          td2.textContent = `${pts} ${ptsWord}`;
          tr.appendChild(td1);
          tr.appendChild(td2);
          tbl.appendChild(tr);
        });

        listToggle.addEventListener("click", () => {
          listOpen = !listOpen;
          tbl.style.display = listOpen ? "table" : "none";
        });

        pieRow.appendChild(legend);
        pieBox.appendChild(pieRow);
        pieBox.appendChild(tbl);
        pieContainer.appendChild(pieBox);
      }

      const acts = ((useHi && analysis.recommended_actions_hi?.length ? analysis.recommended_actions_hi : analysis.recommended_actions) || []).slice(0, 3);
      stepsBox.textContent = "";
      const stepsTitle = document.createElement("div");
      stepsTitle.style.color = "#a7f3d0";
      stepsTitle.style.marginBottom = "4px";
      stepsTitle.textContent = useHi ? "✅ अब क्या करें:" : "✅ What to do now:";
      stepsBox.appendChild(stepsTitle);

      acts.forEach((step, idx) => {
        const line = document.createElement("div");
        line.textContent = `${idx + 1}. ${step}`;
        stepsBox.appendChild(line);
      });

      moreBtn.textContent = detailsOpen
        ? (useHi ? "▲ जानकारी छुपाएं" : "▲ Hide details")
        : (useHi ? "▼ और जानकारी देखें" : "▼ More details");

      const inds = (analysis.indicators || []).map(
        i => `• [${i.severity}] ${i.indicator_type}: ${i.target_element} — ${i.explanation}`
      );
      detailsBox.textContent = [
        `Score: ${score}/100 (${risk})`,
        analysis.confidence_score_explanation || "",
        ...inds
      ].filter(Boolean).join("\n");

      safeBtn.textContent = useHi ? "✅ यह सुरक्षित है" : "✅ This is safe";
      dismissBtn.textContent = useHi ? "बंद करें" : "Close warning";
    }

    langBtn.addEventListener("click", () => {
      currentLang = currentLang === "en" ? "hi" : "en";
      renderLanguageContent();
    });

    speakBtn.addEventListener("click", () => {
      if (!("speechSynthesis" in window)) return;
      const useHi = currentLang === "hi";
      const parts = [
        verdictEl.textContent,
        calmEl.textContent,
        aboutEl.textContent,
        seemsEl.textContent,
        affectsEl.textContent
      ];
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(parts.join(". "));
      u.lang = useHi ? "hi-IN" : "en-IN";
      window.speechSynthesis.speak(u);
    });

    renderLanguageContent();

    closedRoot.appendChild(style);
    closedRoot.appendChild(card);
    (document.body || document.documentElement).appendChild(hostElement);
  }

  window.__trustlensBannerController = {
    show: showTrustLensBanner,
    remove: removeExistingBanner
  };
})();