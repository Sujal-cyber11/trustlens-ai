/**
 * TrustLens Offline Local Chart Renderer (static/vendor/chart.umd.js)
 * Self-contained offline doughnut/pie chart implementation exposing `window.Chart`.
 * - Sizes the canvas strictly from its fixed-height parent container (`parentElement.clientWidth`
 *   and `parentElement.clientHeight`) so `canvas.width` / `canvas.height` never feed back into layout growth.
 * - Supports `.update()` in place without recreating instances and `.destroy()` to release resources.
 */
(function (global) {
  if (global.Chart && global.Chart.__trustlensOfflineReady) {
    return;
  }

  class OfflineChart {
    constructor(ctxOrCanvas, config) {
      this.canvas = ctxOrCanvas && ctxOrCanvas.canvas ? ctxOrCanvas.canvas : ctxOrCanvas;
      this.ctx = this.canvas ? this.canvas.getContext("2d") : null;
      this.config = config || {};
      this.data = this.config.data || { labels: [], datasets: [] };
      this.options = this.config.options || { responsive: true, maintainAspectRatio: false };
      this._destroyed = false;
      this.render();
    }

    update() {
      if (this._destroyed) return;
      this.data = this.config.data || this.data;
      this.render();
    }

    destroy() {
      this._destroyed = true;
      if (this.ctx && this.canvas) {
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
      }
    }

    render() {
      if (this._destroyed || !this.ctx || !this.canvas) return;
      const parent = this.canvas.parentElement;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);

      // Measure strictly from the fixed-size parent wrapper to prevent resize feedback loops
      const cssW = Math.max(140, Math.min(220, (parent && parent.clientWidth) ? parent.clientWidth : 200));
      const cssH = Math.max(140, Math.min(220, (parent && parent.clientHeight) ? parent.clientHeight : 220));

      const targetW = Math.round(cssW * dpr);
      const targetH = Math.round(cssH * dpr);
      if (this.canvas.width !== targetW || this.canvas.height !== targetH) {
        this.canvas.width = targetW;
        this.canvas.height = targetH;
        this.canvas.style.width = cssW + "px";
        this.canvas.style.height = cssH + "px";
      }

      const ctx = this.ctx;
      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, cssW, cssH);

      const ds = (this.data && this.data.datasets && this.data.datasets[0]) || {};
      const values = Array.isArray(ds.data) ? ds.data.map(v => Math.max(0, Number(v) || 0)) : [];
      const colors = Array.isArray(ds.backgroundColor)
        ? ds.backgroundColor
        : ["#EF4444", "#F97316", "#EAB308", "#A855F7", "#38BDF8", "#10B981"];

      const cx = cssW / 2;
      const cy = cssH / 2;
      const radius = Math.max(36, Math.min(cx, cy) - 16);
      const innerRadius = this.config.type === "pie" ? 0 : radius * 0.56;

      const total = values.reduce((acc, v) => acc + v, 0);
      const centerLabel =
        (this.options && this.options.plugins && this.options.plugins.centerText) ||
        this.config.centerText ||
        String(total);

      if (total <= 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, radius, 0, Math.PI * 2);
        ctx.fillStyle = colors[0] || "#10B981";
        ctx.fill();
        if (innerRadius > 0) {
          ctx.beginPath();
          ctx.arc(cx, cy, innerRadius, 0, Math.PI * 2);
          ctx.fillStyle = "#0F172A";
          ctx.fill();
        }
        ctx.fillStyle = "#F8FAFC";
        ctx.font = "bold 14px Segoe UI, sans-serif";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(centerLabel, cx, cy);
        ctx.restore();
        return;
      }

      let startAngle = -Math.PI / 2;
      for (let i = 0; i < values.length; i++) {
        const val = values[i];
        if (val <= 0) continue;
        const sliceAngle = (val / total) * (Math.PI * 2);
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = colors[i % colors.length];
        ctx.fill();
        ctx.lineWidth = 2;
        ctx.strokeStyle = "#0F172A";
        ctx.stroke();
        startAngle += sliceAngle;
      }

      if (innerRadius > 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, innerRadius, 0, Math.PI * 2);
        ctx.fillStyle = "#0F172A";
        ctx.fill();
        ctx.fillStyle = "#F8FAFC";
        ctx.font = "bold 14px Segoe UI, sans-serif";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(centerLabel, cx, cy);
      }

      ctx.restore();
    }
  }

  OfflineChart.__trustlensOfflineReady = true;
  global.Chart = OfflineChart;
})(window);