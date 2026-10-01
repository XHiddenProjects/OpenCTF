// motd-banner config GUI
//
// Loaded only when an admin clicks the gear button on this addon's card in
// Admin -> Addons & Themes. window.OpenCTFAdmin is already set up by the
// time this script runs - see docs/ADDON_DEVELOPMENT.md for the full
// contract (get/save/mount). Labels go through window.OpenCTF.t() with a
// matching data-i18n attribute, the same pattern used by this addon's own
// runtime banner - see docs/LOCALIZATION.md.
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
        <span data-i18n="addon.motd-banner.config.message_label">${t("addon.motd-banner.config.message_label", "Banner message")}</span>
        <textarea id="motd-cfg-message" rows="3"></textarea>
      </label>
      <label>
        <span data-i18n="addon.motd-banner.config.color_label">${t("addon.motd-banner.config.color_label", "Banner color")}</span>
        <input type="color" id="motd-cfg-color" />
      </label>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="motd-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="motd-cfg-result"></span>
      </div>
    `;

    container.querySelector("#motd-cfg-message").value = config.message || "";
    container.querySelector("#motd-cfg-color").value = config.color || "#e8a33d";

    container.querySelector("#motd-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#motd-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      try {
        await window.OpenCTFAdmin.save({
          message: container.querySelector("#motd-cfg-message").value,
          color: container.querySelector("#motd-cfg-color").value,
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
