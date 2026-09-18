// Certifications addon config GUI - branding shown on every certificate.
// A "Issued & verifiable via OpenCTF" line is always printed on the
// certificate itself (see certificateHTML() in addon.js) regardless of
// what's set here - it's not a setting, deliberately, so a certificate
// can always be traced back to this platform no matter how it's branded.
// To actually preview a certificate with this branding applied, use the
// Preview button on the Certifications tab's own Manage sub-tab - it
// already builds the real certificate render, so it isn't duplicated here.
(function () {
  window.OpenCTFAdmin.mount(async (container) => {
    container.innerHTML = '<p class="field-note">Loading current config...</p>';
    let config;
    try {
      config = await window.OpenCTFAdmin.get();
    } catch (err) {
      container.innerHTML = `<p class="form-error">${err.message}</p>`;
      return;
    }

    container.innerHTML = `
      <label>
        Organization name
        <input type="text" id="cert-cfg-org-name" placeholder="OpenCTF" />
      </label>
      <label>
        Organization logo URL (optional)
        <input type="text" id="cert-cfg-org-logo" placeholder="https://example.com/logo.png" />
      </label>
      <label>
        Signer name (optional)
        <input type="text" id="cert-cfg-signer-name" placeholder="e.g. Jane Doe" />
      </label>
      <label>
        Signer title (optional)
        <input type="text" id="cert-cfg-signer-title" placeholder="e.g. Program Director" />
      </label>
      <label>
        Accent color
        <input type="color" id="cert-cfg-accent" />
      </label>
      <p class="field-note">Every certificate also always shows an "Issued &amp; verifiable via OpenCTF" line, regardless of the branding above.</p>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="cert-cfg-save">Save</button>
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
        result.textContent = "Saved - live on every open client.";
        result.className = "form-result ok";
      } catch (err) {
        result.textContent = err.message;
        result.className = "form-result err";
      }
    });
  });
})();
