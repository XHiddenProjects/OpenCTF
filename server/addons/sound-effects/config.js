// Just the volume - whether this addon runs at all is controlled by its
// own toggle in Admin -> Addons & Themes, not a second setting in here.
// Labels go through window.OpenCTF.t() with a matching data-i18n
// attribute - see docs/LOCALIZATION.md.
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
        <span data-i18n="addon.sound-effects.config.volume_label">${t("addon.sound-effects.config.volume_label", "Volume")}</span>
        <input type="range" id="sfx-cfg-volume" min="0" max="1" step="0.05" />
      </label>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="sfx-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="sfx-cfg-result"></span>
      </div>
    `;

    container.querySelector("#sfx-cfg-volume").value = config.volume ?? 0.2;

    container.querySelector("#sfx-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#sfx-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      try {
        await window.OpenCTFAdmin.save({
          volume: Number(container.querySelector("#sfx-cfg-volume").value),
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
