/**
 * TrustLens AI — Manifest V3 Background Service Worker (background.js)
 *
 * - Stateless across sleep cycles: stores 10-minute verdict caches and backend backoff state
 *   in chrome.storage.session (with chrome.storage.local fallback).
 * - Skips chrome://, edge://, extension pages, file://, and incognito tabs.
 * - Updates toolbar icon color (green / amber / red / grey) and tooltip per tab.
 */

const API_BASE = "http://127.0.0.1:8000";
const CACHE_TTL_MS = 10 * 60 * 1000;

const DEFAULT_ALLOWLIST = [
  "google.com",
  "github.com",
  "microsoft.com",
  "wikipedia.org",
  "chatgpt.com",
  "sbi.co.in",
  "hdfcbank.com",
  "icicibank.com"
];

function getIconPaths(color) {
  const valid = ["green", "amber", "red", "grey"].includes(color) ? color : "green";
  return {
    "16": `icons/icon_${valid}_16.png`,
    "48": `icons/icon_${valid}_48.png`,
    "128": `icons/icon_${valid}_128.png`
  };
}

async function setTabVisuals(tabId, color, titleText, badgeText = "") {
  if (!tabId) return;
  try {
    await chrome.action.setIcon({ tabId, path: getIconPaths(color) });
    await chrome.action.setTitle({ tabId, title: titleText });
    await chrome.action.setBadgeText({ tabId, text: badgeText });
    if (badgeText) {
      const bg = color === "red" ? "#DC2626" : color === "amber" ? "#D97706" : "#475569";
      await chrome.action.setBadgeBackgroundColor({ tabId, color: bg });
    }
  } catch (_) {
    // Tab may have closed
  }
}

function hashString(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}

async function getSessionData(key) {
  const store = chrome.storage.session || chrome.storage.local;
  const res = await store.get(key);
  return res[key];
}

async function setSessionData(key, val) {
  const store = chrome.storage.session || chrome.storage.local;
  await store.set({ [key]: val });
}

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get({ initialized: false });
  if (!existing.initialized) {
    await chrome.storage.local.set({
      initialized: true,
      extensionToken: "",
      globalPaused: false,
      language: "en",
      allowlistDomains: DEFAULT_ALLOWLIST,
      pausedHosts: [],
      neverScanHosts: [],
      checksConfig: {
        checkForms: true,
        checkIframesAndOverlays: true,
        checkDeceptiveLinks: true,
        checkScriptsAndHooks: true,
        checkFakeSystemAndClickFix: true,
        checkDarkPatterns: true
      }
    });
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  if (message.type === "TRUSTLENS_AUDIT_PAGE") {
    handlePageAudit(message.payload, Boolean(message.force), sender.tab)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ status: "error", detail: String(err) }));
    return true;
  }

  if (message.type === "TRUSTLENS_GET_TAB_VERDICT") {
    getTabVerdict(message.tabId, message.url)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ status: "error", detail: String(err) }));
    return true;
  }

  if (message.type === "TRUSTLENS_FEEDBACK") {
    handleExtensionFeedback(message)
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ status: "error", detail: String(err) }));
    return true;
  }

  return false;
});

async function getTabVerdict(tabId, rawUrl) {
  if (!rawUrl || !rawUrl.startsWith("http")) {
    return { status: "skipped", reason: "Non-HTTP page" };
  }
  const u = new URL(rawUrl);
  const cacheKey = `verdict_${u.origin}${u.pathname}`;
  const cached = await getSessionData(cacheKey);
  if (cached && cached.data) {
    return { status: "success", data: cached.data };
  }
  return { status: "empty" };
}

async function handleExtensionFeedback(msg) {
  const cfg = await chrome.storage.local.get({ extensionToken: "", pausedHosts: [] });
  if (msg.feedback_type === "false_positive" && msg.hostname) {
    const updated = Array.from(new Set([...(cfg.pausedHosts || []), msg.hostname.toLowerCase()]));
    await chrome.storage.local.set({ pausedHosts: updated });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const headers = { "Content-Type": "application/json" };
    if (cfg.extensionToken) headers["X-TrustLens-Token"] = cfg.extensionToken;
    await fetch(`${API_BASE}/api/feedback`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        item_id: "",
        input_snippet: msg.url || msg.hostname || "",
        domain: msg.hostname || null,
        feedback_type: msg.feedback_type || "confirm_scam",
        lesson_note: `Browser extension feedback (${msg.feedback_type}) on ${msg.hostname}`
      }),
      signal: controller.signal
    });
    return { status: "success" };
  } finally {
    clearTimeout(timer);
  }
}

async function handlePageAudit(payload, force, tab) {
  const tabId = tab?.id;
  if (tab?.incognito) {
    return { status: "skipped", reason: "Incognito tab skipped by default" };
  }

  const cfg = await chrome.storage.local.get({
    extensionToken: "",
    globalPaused: false,
    allowlistDomains: DEFAULT_ALLOWLIST,
    pausedHosts: [],
    neverScanHosts: []
  });

  if (cfg.globalPaused) {
    await setTabVisuals(tabId, "grey", "TrustLens AI — Protection Paused");
    return { status: "paused" };
  }

  const host = String(payload.hostname || "").toLowerCase();
  const skipList = [...(cfg.pausedHosts || []), ...(cfg.neverScanHosts || [])];
  if (skipList.some((d) => host === d.toLowerCase() || host.endsWith("." + d.toLowerCase()))) {
    await setTabVisuals(tabId, "grey", `TrustLens AI — Paused on ${host}`);
    return { status: "paused_site" };
  }

  const u = new URL(payload.url);
  const sigHash = hashString(JSON.stringify(payload.signals || []));
  const originPathKey = `verdict_${u.origin}${u.pathname}`;

  if (!force) {
    const cached = await getSessionData(originPathKey);
    if (cached && (Date.now() - cached.ts) < CACHE_TTL_MS && cached.sigHash === sigHash) {
      await applyVerdictVisuals(tabId, cached.data);
      return { status: "success", data: cached.data, cached: true };
    }
  }

  // Check exponential backoff if backend was recently unreachable
  const backoffState = (await getSessionData("backend_backoff")) || { until: 0, failures: 0 };
  if (Date.now() < backoffState.until && !force) {
    await setTabVisuals(tabId, "grey", "TrustLens app not running");
    return { status: "offline", detail: "TrustLens app not running (backoff active)" };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  try {
    const headers = { "Content-Type": "application/json" };
    if (cfg.extensionToken) {
      headers["X-TrustLens-Token"] = cfg.extensionToken;
    }

    const res = await fetch(`${API_BASE}/api/audit-page`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal
    });

    if (res.status === 401) {
      await setTabVisuals(tabId, "grey", "TrustLens AI — Token required (Click Copy Extension Token in tray)", "KEY");
      return { status: "unauthorized", detail: "Extension token missing or invalid." };
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    await setSessionData("backend_backoff", { until: 0, failures: 0 });
    await setSessionData(originPathKey, { ts: Date.now(), sigHash, data });
    await applyVerdictVisuals(tabId, data);
    return { status: "success", data };
  } catch (err) {
    const failures = (backoffState.failures || 0) + 1;
    const delayMs = Math.min(60000, 5000 * Math.pow(2, failures - 1));
    await setSessionData("backend_backoff", { until: Date.now() + delayMs, failures });
    await setTabVisuals(tabId, "grey", "TrustLens app not running");
    return { status: "offline", detail: String(err) };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function applyVerdictVisuals(tabId, data) {
  const analysis = data?.analysis || {};
  const risk = String(analysis.overall_risk_score || "Low");
  const score = Number(analysis.numeric_risk_score || 0);
  const cat = String(analysis.fraud_category || "Verified");

  if (risk === "High") {
    await setTabVisuals(tabId, "red", `⚠️ TrustLens: HIGH RISK (${score}/100) — ${cat}`, String(score));
  } else if (risk === "Medium") {
    await setTabVisuals(tabId, "amber", `⚠️ TrustLens: MEDIUM RISK (${score}/100) — ${cat}`, String(score));
  } else {
    await setTabVisuals(tabId, "green", `✅ TrustLens: Safe (${score}/100) — ${cat}`, "");
  }
}