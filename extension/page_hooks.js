/**
 * TrustLens AI — Page-Context API Monitor (page_hooks.js)
 * Safely wraps Notification.requestPermission, navigator.geolocation, and mediaDevices.getUserMedia
 * in the main world to detect permission prompts fired WITHOUT a user gesture, plus programmatic
 * <a download> clicks. Emits structure-only custom events; never reads any input value or secret.
 */
(function () {
  if (window.__trustlensPageHooksInstalled) {
    return;
  }
  window.__trustlensPageHooksInstalled = true;

  let lastUserGestureTs = 0;
  const markGesture = () => {
    lastUserGestureTs = Date.now();
  };

  window.addEventListener("pointerdown", markGesture, true);
  window.addEventListener("keydown", markGesture, true);

  function hasRecentUserGesture() {
    const ua = navigator.userActivation;
    if (ua && typeof ua.isActive === "boolean") {
      return ua.isActive || (Date.now() - lastUserGestureTs) < 1500;
    }
    return (Date.now() - lastUserGestureTs) < 1500;
  }

  function emitHookSignal(id, evidence) {
    try {
      window.dispatchEvent(
        new CustomEvent("__trustlens_hook_signal", {
          detail: {
            id: String(id || ""),
            evidence: String(evidence || "").slice(0, 110)
          }
        })
      );
    } catch (_) {
      // Ignore dispatch errors on restricted documents
    }
  }

  // 1. Wrap Notification.requestPermission
  if (typeof window.Notification !== "undefined" && typeof window.Notification.requestPermission === "function") {
    const origReqPerm = window.Notification.requestPermission.bind(window.Notification);
    window.Notification.requestPermission = function (...args) {
      if (!hasRecentUserGesture()) {
        emitHookSignal("unprompted_permission_request", "Notification.requestPermission called without user gesture");
      }
      return origReqPerm(...args);
    };
  }

  // 2. Wrap navigator.geolocation
  if (navigator.geolocation) {
    if (typeof navigator.geolocation.getCurrentPosition === "function") {
      const origGeo = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
      navigator.geolocation.getCurrentPosition = function (...args) {
        if (!hasRecentUserGesture()) {
          emitHookSignal("unprompted_permission_request", "geolocation.getCurrentPosition called without user gesture");
        }
        return origGeo(...args);
      };
    }
    if (typeof navigator.geolocation.watchPosition === "function") {
      const origWatch = navigator.geolocation.watchPosition.bind(navigator.geolocation);
      navigator.geolocation.watchPosition = function (...args) {
        if (!hasRecentUserGesture()) {
          emitHookSignal("unprompted_permission_request", "geolocation.watchPosition called without user gesture");
        }
        return origWatch(...args);
      };
    }
  }

  // 3. Wrap navigator.mediaDevices.getUserMedia
  if (navigator.mediaDevices && typeof navigator.mediaDevices.getUserMedia === "function") {
    const origMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
    navigator.mediaDevices.getUserMedia = function (constraints, ...rest) {
      if (!hasRecentUserGesture()) {
        emitHookSignal("unprompted_permission_request", "mediaDevices.getUserMedia called without user gesture");
      }
      return origMedia(constraints, ...rest);
    };
  }

  // 4. Detect programmatic automatic downloads without user gesture
  const origClick = HTMLElement.prototype.click;
  HTMLElement.prototype.click = function (...args) {
    try {
      if (this && this.tagName === "A") {
        const href = String(this.getAttribute("href") || "");
        if ((this.hasAttribute("download") || href.startsWith("blob:") || href.startsWith("data:")) && !hasRecentUserGesture()) {
          emitHookSignal("auto_download_trigger", "Programmatic <a download> or blob click without user gesture");
        }
      }
    } catch (_) {
      // Ignore inspection errors
    }
    return origClick.apply(this, args);
  };
})();