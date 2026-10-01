// core addon config GUI - see motd-banner/config.js for a more heavily
// commented example of the window.OpenCTFAdmin contract this relies on.
// Labels use window.OpenCTF.t() so the config screen matches whatever
// language is currently active, plus a matching data-i18n attribute so
// it keeps up live if the admin switches language while this modal is
// still open (see docs/LOCALIZATION.md).
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
      <label class="toggle-row">
        <span class="toggle-switch">
          <input type="checkbox" id="core-cfg-toasts" />
          <span class="toggle-track"></span>
        </span>
        <span data-i18n="addon.core.config.toasts_label">${t("addon.core.config.toasts_label", "Toast notification on solve")}</span>
      </label>
      <label class="toggle-row">
        <span class="toggle-switch">
          <input type="checkbox" id="core-cfg-dot" />
          <span class="toggle-track"></span>
        </span>
        <span data-i18n="addon.core.config.dot_label">${t("addon.core.config.dot_label", "Live-updates connection dot")}</span>
      </label>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="core-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="core-cfg-result"></span>
      </div>
    `;

    container.querySelector("#core-cfg-toasts").checked = config.solve_toasts !== false;
    container.querySelector("#core-cfg-dot").checked = config.connection_indicator !== false;

    container.querySelector("#core-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#core-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      try {
        await window.OpenCTFAdmin.save({
          solve_toasts: container.querySelector("#core-cfg-toasts").checked,
          connection_indicator: container.querySelector("#core-cfg-dot").checked,
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
