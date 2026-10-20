/**
 * TrustLens AI — Extension Options Controller (options.js)
 */
document.addEventListener("DOMContentLoaded", async () => {
  const tokenInput = document.getElementById("tokenInput");
  const globalKillSwitch = document.getElementById("globalKillSwitch");
  const chkForms = document.getElementById("chkForms");
  const chkIframes = document.getElementById("chkIframes");
  const chkLinks = document.getElementById("chkLinks");
  const chkScripts = document.getElementById("chkScripts");
  const chkClickFix = document.getElementById("chkClickFix");
  const chkDarkPatterns = document.getElementById("chkDarkPatterns");
  const neverScanBox = document.getElementById("neverScanBox");
  const allowlistBox = document.getElementById("allowlistBox");
  const saveStatus = document.getElementById("saveStatus");

  const cfg = await chrome.storage.local.get({
    extensionToken: "",
    globalPaused: false,
    allowlistDomains: ["google.com", "github.com", "microsoft.com", "wikipedia.org", "chatgpt.com"],
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

  tokenInput.value = cfg.extensionToken || "";
  globalKillSwitch.checked = Boolean(cfg.globalPaused);
  chkForms.checked = cfg.checksConfig.checkForms !== false;
  chkIframes.checked = cfg.checksConfig.checkIframesAndOverlays !== false;
  chkLinks.checked = cfg.checksConfig.checkDeceptiveLinks !== false;
  chkScripts.checked = cfg.checksConfig.checkScriptsAndHooks !== false;
  chkClickFix.checked = cfg.checksConfig.checkFakeSystemAndClickFix !== false;
  chkDarkPatterns.checked = cfg.checksConfig.checkDarkPatterns !== false;
  neverScanBox.value = (cfg.neverScanHosts || []).join("\n");
  allowlistBox.value = (cfg.allowlistDomains || []).join("\n");

  document.getElementById("saveBtn").addEventListener("click", async () => {
    const neverList = neverScanBox.value.split("\n").map(s => s.trim().toLowerCase()).filter(Boolean);
    const allowList = allowlistBox.value.split("\n").map(s => s.trim().toLowerCase()).filter(Boolean);

    await chrome.storage.local.set({
      extensionToken: tokenInput.value.trim(),
      globalPaused: globalKillSwitch.checked,
      neverScanHosts: neverList,
      allowlistDomains: allowList,
      checksConfig: {
        checkForms: chkForms.checked,
        checkIframesAndOverlays: chkIframes.checked,
        checkDeceptiveLinks: chkLinks.checked,
        checkScriptsAndHooks: chkScripts.checked,
        checkFakeSystemAndClickFix: chkClickFix.checked,
        checkDarkPatterns: chkDarkPatterns.checked
      }
    });

    saveStatus.textContent = "✅ Settings saved!";
    setTimeout(() => { saveStatus.textContent = ""; }, 2500);
  });
});