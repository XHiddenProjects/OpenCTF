// Certifications addon config GUI - branding shown on every certificate.
// A "Issued & verifiable via OpenCTF" line is always printed on the
// certificate itself (see certificateHTML() in addon.js) regardless of
// what's set here - it's not a setting, deliberately, so a certificate
// can always be traced back to this platform no matter how it's branded.
// To actually preview a certificate with this branding applied, use the
// Preview button on the Certifications tab's own Manage sub-tab - it
// already builds the real certificate render, so it isn't duplicated here.
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
        <span data-i18n="addon.certifications.config.org_name_label">${t("addon.certifications.config.org_name_label", "Organization name")}</span>
        <input type="text" id="cert-cfg-org-name" placeholder="OpenCTF" />
      </label>
      <label>
        <span data-i18n="addon.certifications.config.org_logo_label">${t("addon.certifications.config.org_logo_label", "Organization logo URL (optional)")}</span>
        <input type="text" id="cert-cfg-org-logo" placeholder="https://example.com/logo.png" />
      </label>
      <label>
        <span data-i18n="addon.certifications.config.signer_name_label">${t("addon.certifications.config.signer_name_label", "Signer name (optional)")}</span>
        <input type="text" id="cert-cfg-signer-name" placeholder="e.g. Jane Doe" />
      </label>
      <label>
        <span data-i18n="addon.certifications.config.signer_title_label">${t("addon.certifications.config.signer_title_label", "Signer title (optional)")}</span>
        <input type="text" id="cert-cfg-signer-title" placeholder="e.g. Program Director" />
      </label>
      <label>
        <span data-i18n="addon.certifications.config.accent_color_label">${t("addon.certifications.config.accent_color_label", "Accent color")}</span>
        <input type="color" id="cert-cfg-accent" />
      </label>
      <p class="field-note" data-i18n="addon.certifications.config.always_shown_note">${t("addon.certifications.config.always_shown_note", 'Every certificate also always shows an "Issued & verifiable via OpenCTF" line, regardless of the branding above.')}</p>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="cert-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="cert-cfg-result"></span>
      </div>
    `;

    container.querySelector("#cert-cfg-org-name").value = config.org_name || "";
    container.querySelector("#cert-cfg-org-logo").value = config.org_logo_url || "";
    container.querySelector("#cert-cfg-signer-name").value = config.signer_name || "";
    container.querySelector("#cert-cfg-signer-title").value = config.signer_title || "";
    container.querySelector("#cert-cfg-accent").value = config.accent_color || "#e8a33d";

    container.querySelector("#cert-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#cert-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      try {
        await window.OpenCTFAdmin.save({
          org_name: container.querySelector("#cert-cfg-org-name").value.trim() || "OpenCTF",
          org_logo_url: container.querySelector("#cert-cfg-org-logo").value.trim(),
          signer_name: container.querySelector("#cert-cfg-signer-name").value.trim(),
          signer_title: container.querySelector("#cert-cfg-signer-title").value.trim(),
          accent_color: container.querySelector("#cert-cfg-accent").value,
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
