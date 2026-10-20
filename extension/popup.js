/**
 * TrustLens AI — Popup Controller with Inline SVG Pie Chart (popup.js)
 */
document.addEventListener("DOMContentLoaded", async () => {
  const PALETTE = ["#EF4444", "#F97316", "#EAB308", "#A855F7", "#38BDF8", "#10B981"];

  const verdictCard = document.getElementById("verdictCard");
  const verdictTitle = document.getElementById("verdictTitle");
  const calmLine = document.getElementById("calmLine");
  const threeLinesBox = document.getElementById("threeLinesBox");
  const pieSection = document.getElementById("pieSection");
  const pieHeading = document.getElementById("pieHeading");
  const showListBtn = document.getElementById("showListBtn");
  const svgMount = document.getElementById("svgMount");
  const legendMount = document.getElementById("legendMount");
  const listTable = document.getElementById("listTable");

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

  let listVisible = false;
  showListBtn.addEventListener("click", () => {
    listVisible = !listVisible;
    listTable.style.display = listVisible ? "table" : "none";
  });

  function buildSvgPie(breakdown, totalScore) {
    const svgNS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", "0 0 100 100");
    svg.setAttribute("width", "92");
    svg.setAttribute("height", "92");

    const cx = 50;
    const cy = 50;
    const r = 42;
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
        path.setAttribute("d", `M ${cx} ${cy} L ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2} Z`);
        path.setAttribute("fill", PALETTE[idx % (PALETTE.length - 1)]);
        path.setAttribute("stroke", "#111827");
        path.setAttribute("stroke-width", "1.5");
        svg.appendChild(path);
        startAngle = endAngle;
      });
    }

    const inner = document.createElementNS(svgNS, "circle");
    inner.setAttribute("cx", String(cx));
    inner.setAttribute("cy", String(cy));
    inner.setAttribute("r", "22");
    inner.setAttribute("fill", "#111827");
    svg.appendChild(inner);

    const text = document.createElementNS(svgNS, "text");
    text.setAttribute("x", String(cx));
    text.setAttribute("y", String(cy + 4));
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("fill", "#f8fafc");
    text.setAttribute("font-size", "11");
    text.setAttribute("font-weight", "bold");
    text.textContent = `${totalScore}/100`;
    svg.appendChild(text);

    return svg;
  }

  function updatePauseLabels() {
    const useHi = cfg.language === "hi";
    pauseGlobalBtn.textContent = cfg.globalPaused
      ? (useHi ? "▶️ सब चालू करें" : "▶️ Resume Everywhere")
      : (useHi ? "⏸️ सब रोकें" : "⏸️ Pause Everywhere");
    const sitePaused = (cfg.pausedHosts || []).includes(currentHost);
    pauseSiteBtn.textContent = sitePaused
      ? (useHi ? "▶️ इस साइट पर चालू करें" : "▶️ Resume Site")
      : (useHi ? "⏸️ इस साइट पर रोकें" : "⏸️ Pause Site");
    langToggleBtn.textContent = useHi ? "🌐 हिंदी (HI)" : "🌐 English (EN)";
    pieHeading.textContent = useHi ? "🥧 इसमें क्या जोखिम है?" : "🥧 Why is this risky?";
    showListBtn.textContent = useHi ? "लिस्ट में देखें" : "Show as list";
  }

  updatePauseLabels();

  function renderVerdict(data) {
    if (!data || !data.analysis) {
      verdictTitle.textContent = "No scan data for this tab yet";
      calmLine.textContent = "Reload the tab while TrustLens is running.";
      return;
    }
    const a = data.analysis;
    const risk = String(a.overall_risk_score || "Low");
    const score = Number(a.numeric_risk_score || 0);
    const useHi = cfg.language === "hi";

    verdictCard.style.borderColor = risk === "High" ? "#ef4444" : risk === "Medium" ? "#f59e0b" : "#10b981";
    verdictTitle.textContent = (useHi ? a.verdict_line_hi : a.verdict_line) || (risk === "High" ? "🛑 This is a scam" : risk === "Medium" ? "⚠️ Be careful" : "✅ This looks safe");
    calmLine.textContent = (useHi ? a.calm_down_message_hi : a.calm_down_message) || a.calm_down_message || "";

    threeLinesBox.textContent = "";
    const l1 = document.createElement("div");
    l1.textContent = (useHi ? a.what_input_is_about_hi : a.what_input_is_about) || a.what_input_is_about || "";
    const l2 = document.createElement("div");
    l2.style.color = "#fde68a";
    l2.textContent = (useHi ? a.what_it_seems_to_be_hi : a.what_it_seems_to_be) || a.what_it_seems_to_be || "";
    const l3 = document.createElement("div");
    l3.style.color = "#fca5a5";
    l3.style.fontWeight = "700";
    l3.textContent = (useHi ? a.how_it_affects_user_hi : a.how_it_affects_user) || a.how_it_affects_user || "";
    threeLinesBox.appendChild(l1);
    threeLinesBox.appendChild(l2);
    threeLinesBox.appendChild(l3);

    const breakdown = Array.isArray(a.score_breakdown) ? a.score_breakdown : [];
    svgMount.textContent = "";
    legendMount.textContent = "";
    listTable.textContent = "";

    if (breakdown.length > 0) {
      pieSection.style.display = "block";
      svgMount.appendChild(buildSvgPie(breakdown, score));
      const ptsWord = useHi ? "अंक" : "pts";

      breakdown.forEach((s, idx) => {
        const sLbl = useHi ? (s.label_hi || s.label_en) : s.label_en;
        const pts = Number(s.points || 0);
        const col = s.key === "nothing_suspicious" ? "#10B981" : PALETTE[idx % (PALETTE.length - 1)];

        const item = document.createElement("div");
        item.className = "legend-item";
        const sw = document.createElement("span");
        sw.className = "swatch";
        sw.style.background = col;
        const sp = document.createElement("span");
        sp.textContent = `${sLbl}: ${pts} ${ptsWord}`;
        item.appendChild(sw);
        item.appendChild(sp);
        legendMount.appendChild(item);

        const tr = document.createElement("tr");
        const td1 = document.createElement("td");
        td1.textContent = sLbl;
        const td2 = document.createElement("td");
        td2.textContent = `${pts} ${ptsWord}`;
        tr.appendChild(td1);
        tr.appendChild(td2);
        listTable.appendChild(tr);
      });
    } else {
      pieSection.style.display = "none";
    }
  }

  chrome.runtime.sendMessage({ type: "TRUSTLENS_GET_TAB_VERDICT", tabId: tab?.id, url: tabUrl }, (res) => {
    if (res && res.status === "success") {
      renderVerdict(res.data);
    } else {
      verdictTitle.textContent = res?.reason || "Page not checked yet";
      calmLine.textContent = "Open any webpage while TrustLens is running.";
    }
  });

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
      calmLine.textContent = "✅ Marked safe.";
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