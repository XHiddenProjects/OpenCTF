// Code Challenge Editor addon - config GUI. The editor font size is the one
// knob this addon reads (server/addons/code-challenge/addon.js's CONFIG);
// below it is a read-only status panel for the code runner (which backend,
// how isolated, which languages are installed) so admins can check the
// offline setup. Settings live here - whether the addon runs at all stays the toggle in Admin ->
// Addons & Themes, not a setting in here (see
// docs/ADDON_DEVELOPMENT.md's "Addon configuration" section).
(function () {
  const t = window.OpenCTF.t;
  const esc = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function renderRunnerStatus(el) {
    try {
      const info = await window.OpenCTF.api("/api/admin/code-runner");
      const langs = Object.entries(info.languages)
        .map(([name, d]) => `<li class="${d.available ? "ok" : "off"}">${d.available ? "&#10003;" : "&#10007;"} ${esc(name)}${d.available ? "" : ` <em>(${esc(t("addon.code-challenge.config.runner_not_installed", "not installed"))})</em>`}</li>`)
        .join("");
      el.innerHTML = `
        <h4>${esc(t("addon.code-challenge.config.runner_title", "Code runner"))}</h4>
        <p class="field-note"><strong>${esc(t("addon.code-challenge.config.runner_backend", "Backend"))}:</strong> ${esc(info.backend)}${info.offline ? " (offline)" : ""}
          &middot; <strong>${esc(t("addon.code-challenge.config.runner_sandbox", "Isolation"))}:</strong> ${esc(info.sandbox)} - ${esc(info.sandbox_detail)}</p>
        ${info.warnings.map((w) => `<p class="form-error">${esc(w)}</p>`).join("")}
        <p class="field-note">${esc(t("addon.code-challenge.config.runner_languages", "Languages on this server"))}:</p>
        <ul class="cc-runner-langs">${langs}</ul>`;
    } catch (err) {
      el.innerHTML = `<p class="form-error">${esc(t("addon.code-challenge.config.runner_unavailable", "Couldn't read runner status: {error}", { error: err.message }))}</p>`;
    }
  }

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
      <div class="cc-runner-status" id="cc-runner-status"></div>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="cc-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="cc-cfg-result"></span>
      </div>
    `;

    container.querySelector("#cc-cfg-font-size").value = Number(config.editor_font_size) || 13;
    renderRunnerStatus(container.querySelector("#cc-runner-status"));

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
