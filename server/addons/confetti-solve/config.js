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
        <span data-i18n="addon.confetti-solve.config.count_label">${t("addon.confetti-solve.config.count_label", "Particle count")}</span>
        <input type="number" id="confetti-cfg-count" min="10" max="500" step="10" />
      </label>
      <label>
        <span data-i18n="addon.confetti-solve.config.colors_label">${t("addon.confetti-solve.config.colors_label", "Colors (comma-separated hex)")}</span>
        <input type="text" id="confetti-cfg-colors" />
      </label>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="confetti-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <button type="button" class="btn-ghost" id="confetti-cfg-preview" data-i18n="addon.confetti-solve.config.preview_btn">${t("addon.confetti-solve.config.preview_btn", "Preview")}</button>
        <span class="form-result" id="confetti-cfg-result"></span>
      </div>
    `;

    container.querySelector("#confetti-cfg-count").value = config.particle_count || 120;
    container.querySelector("#confetti-cfg-colors").value = config.colors || "#e8a33d,#4fae7a,#b98af5,#5fb4e8";

    container.querySelector("#confetti-cfg-preview").addEventListener("click", () => {
      window.OpenCTF.emitLocal?.("challenge:solved", { id: 0, title: "Preview", category: "preview", points: 0 });
    });

    container.querySelector("#confetti-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#confetti-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      try {
        await window.OpenCTFAdmin.save({
          particle_count: Number(container.querySelector("#confetti-cfg-count").value) || 120,
          colors: container.querySelector("#confetti-cfg-colors").value,
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
