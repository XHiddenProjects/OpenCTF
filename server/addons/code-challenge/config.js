// Code Challenge Editor addon - config GUI. Only the two knobs this addon
// actually reads (server/addons/code-challenge/addon.js's CONFIG) live
// here - whether the addon runs at all stays the toggle in Admin ->
// Addons & Themes, not a setting in here (see
// docs/ADDON_DEVELOPMENT.md's "Addon configuration" section).
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
        <span data-i18n="addon.code-challenge.config.font_size_label">${t("addon.code-challenge.config.font_size_label", "Editor font size (px)")}</span>
        <input type="number" id="cc-cfg-font-size" min="10" max="20" step="1" />
      </label>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="cc-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="cc-cfg-result"></span>
      </div>
    `;

    container.querySelector("#cc-cfg-font-size").value = Number(config.editor_font_size) || 13;

    container.querySelector("#cc-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#cc-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      const fontSize = Math.min(20, Math.max(10, Number(container.querySelector("#cc-cfg-font-size").value) || 13));
      try {
        await window.OpenCTFAdmin.save({ editor_font_size: fontSize });
        result.textContent = t("common.saved_live", "Saved - live on every open client.");
        result.className = "form-result ok";
      } catch (err) {
        result.textContent = err.message;
        result.className = "form-result err";
      }
    });
  });
})();
