// CTF Countdown - a small example addon.
//
// Demonstrates, in one place: a sidebar tab via registerView() (using
// labelKey so the tab's own text stays correctly translated across a
// language switch, not just frozen in whatever language was active when
// this script first loaded - see docs/LOCALIZATION.md), a gear-button
// config screen (config.js), and an addon owning its own translated
// strings via a lang/ folder instead of the central catalog (also
// docs/LOCALIZATION.md). Read server/addons/certifications/addon.js for
// a fuller example if you're building something more involved than this.
(function () {
  const ADDON_ID = "ctf-countdown";
  const t = window.OpenCTF.t;

  let intervalId = null;
  let currentContainer = null;
  let currentConfig = null;

  // This addon is installed as a standalone upload, so it can't rely on
  // anything in the host app's own styles.css - it has to bring
  // whatever CSS it needs itself. Injected once, on load.
  const style = document.createElement("style");
  style.textContent = `
    .countdown-status { color: var(--text-dim); margin: 4px 0 18px; }
    .countdown-digits { display: flex; gap: 16px; flex-wrap: wrap; }
    .countdown-unit {
      display: flex;
      flex-direction: column;
      align-items: center;
      background: var(--bg-card, #17181c);
      border: 1px solid var(--border, #2a2b30);
      border-radius: var(--radius, 8px);
      padding: 16px 22px;
      min-width: 84px;
    }
    .countdown-value { font-size: 32px; font-weight: 700; color: var(--accent, #e8a33d); font-variant-numeric: tabular-nums; }
    .countdown-label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
  `;
  document.head.appendChild(style);

  function renderCountdown(container, config) {
    currentContainer = container;
    currentConfig = config;
    const endTime = config.end_time ? new Date(config.end_time) : null;
    const title = config.title || t("addon.ctf-countdown.default_title", "CTF Countdown");

    container.innerHTML = `
      <h2>${title}</h2>
      <p class="countdown-status" id="countdown-status"></p>
      <div class="countdown-digits" id="countdown-digits"></div>
    `;

    const statusEl = container.querySelector("#countdown-status");
    const digitsEl = container.querySelector("#countdown-digits");

    function tick() {
      const now = new Date();

      if (!endTime || Number.isNaN(endTime.getTime())) {
        statusEl.textContent = t("addon.ctf-countdown.no_end_time", "No end time has been set yet - ask an admin to configure one from the gear button.");
        digitsEl.innerHTML = "";
        return;
      }

      const diffMs = endTime.getTime() - now.getTime();
      const ended = diffMs <= 0;
      statusEl.textContent = ended
        ? t("addon.ctf-countdown.ended", "The event has ended.")
        : t("addon.ctf-countdown.remaining", "Time remaining:");

      const totalSeconds = Math.max(0, Math.floor(Math.abs(diffMs) / 1000));
      const days = Math.floor(totalSeconds / 86400);
      const hours = Math.floor((totalSeconds % 86400) / 3600);
      const minutes = Math.floor((totalSeconds % 3600) / 60);
      const seconds = totalSeconds % 60;

      digitsEl.innerHTML = ended
        ? ""
        : [
            [days, "addon.ctf-countdown.unit_days", "days"],
            [hours, "addon.ctf-countdown.unit_hours", "hours"],
            [minutes, "addon.ctf-countdown.unit_minutes", "min"],
            [seconds, "addon.ctf-countdown.unit_seconds", "sec"],
          ]
            .map(([value, key, fallback]) => `<div class="countdown-unit"><span class="countdown-value">${value}</span><span class="countdown-label">${t(key, fallback)}</span></div>`)
            .join("");
    }

    tick();
    if (intervalId) clearInterval(intervalId);
    intervalId = setInterval(tick, 1000);
  }

  window.OpenCTF.registerView({
    id: ADDON_ID,
    label: "Countdown",
    labelKey: "addon.ctf-countdown.nav_label",
    async render(container) {
      container.innerHTML = `<p class="field-note">${t("common.loading_config", "Loading current config...")}</p>`;
      try {
        const config = await window.OpenCTF.getAddonConfig(ADDON_ID);
        currentContainer = container;
        currentConfig = config;
        renderCountdown(container, config);
      } catch (err) {
        container.innerHTML = `<p class="form-error">${err.message}</p>`;
      }
    },
  });

  window.OpenCTF.on("language:changed", () => {
    if (currentContainer && currentConfig && !currentContainer.classList.contains("hidden")) {
      renderCountdown(currentContainer, currentConfig);
    }
  });

  // Stop the ticking interval once this addon is disabled, so it isn't
  // still running (and erroring against a now-removed view) in the
  // background - registerView()'s own auto-hide only hides the tab.
  window.OpenCTF.on("addon:disabled", (detail) => {
    if (detail && detail.id === ADDON_ID && intervalId) {
      clearInterval(intervalId);
      intervalId = null;
    }
  });
})();
