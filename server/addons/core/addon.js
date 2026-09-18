// core addon
//
// Ships with OpenCTF and can't be disabled (see "can_disable": false in
// addon.json / admin_toggle_addon in server/app.py). It isn't special to
// the platform in any technical sense - it's a normal addon built on the
// same window.OpenCTF API any other addon gets - it's just marked
// non-disableable so a lab operator can't accidentally turn off the small
// conveniences every player benefits from: a toast on solve, a heads-up
// when an admin pushes a live theme/addon change, and a "live updates"
// status row. Copy this folder (minus "can_disable": false and with your
// own "core" version requirement) if you want your own always-visible
// addon as a starting point.
(function () {
  const FALLBACK = { solve_toasts: true, connection_indicator: true };
  let CONFIG = { ...FALLBACK };

  function ensureToastHost() {
    let host = document.getElementById("core-toast-host");
    if (!host) {
      host = document.createElement("div");
      host.id = "core-toast-host";
      host.style.cssText = [
        "position: fixed", "bottom: 16px", "right: 16px", "z-index: 9999",
        "display: flex", "flex-direction: column", "gap: 8px", "align-items: flex-end",
        "pointer-events: none",
      ].join(";");
      document.body.appendChild(host);
    }
    return host;
  }

  function toast(message, tone = "ok") {
    const host = ensureToastHost();
    const color = tone === "err" ? "var(--err, #d9645b)" : tone === "info" ? "var(--accent, #e8a33d)" : "var(--ok, #4fae7a)";
    const el = document.createElement("div");
    el.textContent = message;
    el.style.cssText = [
      "background: var(--bg-raised, #121722)",
      `border-left: 3px solid ${color}`,
      "color: var(--text, #e7ebf3)",
      "font-family: 'IBM Plex Sans', system-ui, sans-serif",
      "font-size: 12px",
      "padding: 10px 14px",
      "border-radius: var(--radius, 6px)",
      "box-shadow: 0 4px 16px rgba(0,0,0,0.35)",
      "opacity: 0",
      "transform: translateY(6px)",
      "transition: opacity 0.15s ease, transform 0.15s ease",
      "max-width: 280px",
    ].join(";");
    host.appendChild(el);
    requestAnimationFrame(() => {
      el.style.opacity = "1";
      el.style.transform = "translateY(0)";
    });
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transform = "translateY(6px)";
      setTimeout(() => el.remove(), 200);
    }, 4000);
  }

  // Renders into the sidebar's own #sidebar-status-slot (see index.html)
  // instead of floating a fixed-position dot over the rest of the UI -
  // that used to land right on top of the "Sign out" row at some window
  // sizes. The slot only exists once the player's logged in (it's inside
  // the main app's sidebar), so this is a no-op until then; it's called
  // again on every relevant event, so it catches up as soon as the slot
  // shows up.
  function renderLiveStatus(connected) {
    const slot = document.getElementById("sidebar-status-slot");
    if (!slot) return;
    if (!CONFIG.connection_indicator) {
      slot.innerHTML = "";
      return;
    }
    slot.innerHTML = `
      <div class="sidebar-live-row" title="${connected ? "Live updates connected" : "Live updates disconnected - reconnecting..."}">
        <span class="sidebar-live-dot ${connected ? "connected" : "disconnected"}"></span>
        <span>${connected ? "Live updates" : "Reconnecting..."}</span>
      </div>
    `;
  }

  async function loadConfig() {
    try {
      CONFIG = { ...FALLBACK, ...(await window.OpenCTF.getAddonConfig("core")) };
    } catch {
      CONFIG = { ...FALLBACK };
    }
  }

  window.OpenCTF.on("ready", async () => {
    await loadConfig();
    renderLiveStatus(window.OpenCTF.isLive());
  });

  // Re-render on login too: the sidebar (and #sidebar-status-slot inside
  // it) doesn't exist in the DOM until the login screen is replaced by the
  // main app, so "ready" alone can't be relied on to find it.
  window.OpenCTF.on("auth:login", () => renderLiveStatus(window.OpenCTF.isLive()));

  window.OpenCTF.on("challenge:solved", (challenge) => {
    if (!CONFIG.solve_toasts) return;
    toast(`Solved "${challenge.title}" for ${challenge.points} pts!`, "ok");
  });

  // "live:connected"/"live:disconnected" replay their current state to a
  // late subscriber (see OpenCTF.on() in renderer.js), so these fire
  // correctly here even if the SSE connection opened before this script
  // finished loading.
  window.OpenCTF.on("live:connected", () => renderLiveStatus(true));
  window.OpenCTF.on("live:disconnected", () => renderLiveStatus(false));

  window.OpenCTF.on("site:theme_changed", () => {
    toast("The site theme was just updated by an admin.", "info");
  });

  window.OpenCTF.on("addon:enabled", ({ name }) => {
    toast(`Addon enabled: ${name}`, "info");
  });
  window.OpenCTF.on("addon:disabled", ({ name }) => {
    toast(`Addon disabled: ${name}`, "info");
  });

  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id !== "core") return;
    CONFIG = { ...FALLBACK, ...config };
    renderLiveStatus(window.OpenCTF.isLive());
  });
})();
