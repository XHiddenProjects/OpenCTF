// Labels go through window.OpenCTF.t() with a matching data-i18n
// attribute - see docs/LOCALIZATION.md. Note that the *values* an admin
// types in here (the title text, specifically) are content, not UI
// chrome, so they're shown to players exactly as typed - the same way a
// motd-banner message isn't machine-translated either.
(function () {
  const t = window.OpenCTF.t;
  window.OpenCTFAdmin.mount(async (container) => {
    container.innerHTML = `<p class="field-note" data-i18n="common.loading_config">${t("common.loading_config", "Loading current config...")}</p>`;
    let config;
    try {
      config = await window.OpenCTFAdmin.get();
    } catch (err) {
      container.innerHTML = `<p class="form-error">${err.message}</p>`;
      return;
    }

    container.innerHTML = `
      <label>
        <span data-i18n="addon.ctf-countdown.config.title_label">${t("addon.ctf-countdown.config.title_label", "Title (optional)")}</span>
        <input type="text" id="countdown-cfg-title" placeholder="${t("addon.ctf-countdown.default_title", "CTF Countdown")}" />
      </label>
      <label>
        <span data-i18n="addon.ctf-countdown.config.end_time_label">${t("addon.ctf-countdown.config.end_time_label", "End date & time")}</span>
        <input type="datetime-local" id="countdown-cfg-end-time" />
      </label>
      <p class="field-note" data-i18n="addon.ctf-countdown.config.end_time_help">${t("addon.ctf-countdown.config.end_time_help", "Shown in each player's own local time zone. Leave empty to hide the countdown until you set one.")}</p>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="countdown-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="countdown-cfg-result"></span>
      </div>
    `;

    container.querySelector("#countdown-cfg-title").value = config.title || "";
    if (config.end_time) {
      // <input type="datetime-local"> wants "YYYY-MM-DDTHH:MM" in local
      // time, not the ISO string (with a Z/offset) we store - trim it.
      const d = new Date(config.end_time);
      if (!Number.isNaN(d.getTime())) {
        const pad = (n) => String(n).padStart(2, "0");
        container.querySelector("#countdown-cfg-end-time").value =
          `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
      }
    }

    container.querySelector("#countdown-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#countdown-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      try {
        const rawEndTime = container.querySelector("#countdown-cfg-end-time").value;
        await window.OpenCTFAdmin.save({
          title: container.querySelector("#countdown-cfg-title").value.trim(),
          end_time: rawEndTime ? new Date(rawEndTime).toISOString() : "",
        });
        result.textContent = t("common.saved_live", "Saved - live on every open client.");
        result.className = "form-result ok";
      } catch (err) {
        result.textContent = err.message;
        result.className = "form-result err";
      }
    });
  });
})();
