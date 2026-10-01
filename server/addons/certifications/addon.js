// Certifications addon
//
// Adds a full "Certifications" tab (its own sidebar entry and view, via
// window.OpenCTF.registerView() - see docs/ADDON_DEVELOPMENT.md) rather
// than a modal or a banner. The certificates themselves are stored and
// issued by the platform's own backend (Certification model and
// /api/certifications/* + /api/admin/certifications/* routes in
// server/app.py) - this addon is the UI and branding layer on top of
// that, same division of responsibility described in
// docs/ADDON_DEVELOPMENT.md's "Folder layout" section.
(function () {
  const ADDON_ID = "certifications";
  const t = window.OpenCTF.t;

  // document.currentScript is only valid during this script's own
  // synchronous top-level execution (which is exactly where this runs) -
  // it's how an addon can find its own folder to load a sibling asset
  // (style.css here) without the host app needing to hand it a base URL.
  const SCRIPT_URL = document.currentScript ? document.currentScript.src : "";
  const ADDON_BASE_URL = SCRIPT_URL.replace(/\/addon\.js(\?.*)?$/, "");
  const SERVER_BASE_URL = SCRIPT_URL.replace(/\/api\/addons\/.*/, "");

  const FALLBACK_BRANDING = {
    org_name: "OpenCTF",
    org_logo_url: "",
    signer_name: "",
    signer_title: "",
    accent_color: "#e8a33d",
  };
  let BRANDING = { ...FALLBACK_BRANDING };

  const STYLE_OPTIONS = [
    { value: "classic", key: "style_classic", label: "Classic" },
    { value: "modern", key: "style_modern", label: "Modern" },
    { value: "gold", key: "style_gold", label: "Gold" },
    { value: "minimal", key: "style_minimal", label: "Minimal" },
    { value: "royal", key: "style_royal", label: "Royal" },
    { value: "cyber", key: "style_cyber", label: "Cyber" },
    { value: "emerald", key: "style_emerald", label: "Emerald" },
    { value: "sunburst", key: "style_sunburst", label: "Sunburst" },
  ];

  let activeSubtab = "mine";
  let previewCertificate = null;
  let previewOptions = null;

  function injectStylesheet() {
    if (document.getElementById("cert-addon-styles") || !ADDON_BASE_URL) return;
    const link = document.createElement("link");
    link.id = "cert-addon-styles";
    link.rel = "stylesheet";
    link.href = `${ADDON_BASE_URL}/style.css`;
    document.head.appendChild(link);
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
  }

  function formatDate(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(window.OpenCTF.getLanguage(), { year: "numeric", month: "long", day: "numeric" });
  }

  async function loadBranding() {
    try {
      BRANDING = { ...FALLBACK_BRANDING, ...(await window.OpenCTF.getAddonConfig(ADDON_ID)) };
    } catch {
      BRANDING = { ...FALLBACK_BRANDING };
    }
  }

  // --- The certificate itself -----------------------------------------

  function certificateHTML(cert, { preview } = {}) {
    const style = STYLE_OPTIONS.some((s) => s.value === cert.style) ? cert.style : "classic";
    const expiresLine = cert.expires_at
      ? `${t("addon.certifications.ui.expires", "Expires")}: ${formatDate(cert.expires_at)}${cert.expired ? ` <span class="cert-expired-tag">${t("addon.certifications.ui.expired", "EXPIRED")}</span>` : ""}`
      : t("addon.certifications.ui.does_not_expire", "Does not expire");
    return `
      <div class="cert-card cert-style-${style}" style="--cert-accent: ${escapeHtml(BRANDING.accent_color || FALLBACK_BRANDING.accent_color)}">
        <div class="cert-card-header">
          ${BRANDING.org_logo_url ? `<img class="cert-logo" src="${escapeHtml(BRANDING.org_logo_url)}" alt="" />` : ""}
          <div class="cert-org-name">${escapeHtml(BRANDING.org_name || FALLBACK_BRANDING.org_name)}</div>
        </div>
        <div class="cert-body">
          <div class="cert-kicker">${t("addon.certifications.ui.certificate_of_completion", "Certificate of Completion")}</div>
          <h1 class="cert-title">${escapeHtml(cert.title)}</h1>
          <div class="cert-presented-to">${t("addon.certifications.ui.this_certifies", "This certifies that")}</div>
          <div class="cert-recipient">${escapeHtml(cert.recipient_name)}</div>
          ${cert.description ? `<p class="cert-desc">${escapeHtml(cert.description)}</p>` : ""}
        </div>
        <div class="cert-footer">
          <div class="cert-dates">
            <div>${t("addon.certifications.ui.issued", "Issued")}: ${formatDate(cert.issued_at)}</div>
            <div>${expiresLine}</div>
          </div>
          ${(BRANDING.signer_name || BRANDING.signer_title) ? `
          <div class="cert-signature">
            ${BRANDING.signer_name ? `<div class="cert-signer-name">${escapeHtml(BRANDING.signer_name)}</div>` : ""}
            ${BRANDING.signer_title ? `<div class="cert-signer-title">${escapeHtml(BRANDING.signer_title)}</div>` : ""}
          </div>` : ""}
        </div>
        <div class="cert-authenticity">
          ${t("addon.certifications.ui.issued_verifiable", "Issued & verifiable via OpenCTF")} &middot; ${t("addon.certifications.ui.id", "ID")}: <code>${preview ? t("addon.certifications.ui.preview_not_saved", "PREVIEW - NOT SAVED") : escapeHtml(cert.cert_uid || "")}</code>
        </div>
      </div>
    `;
  }

  // --- Preview / print overlay -----------------------------------------

  function ensureOverlay() {
    let overlay = document.getElementById("cert-preview-overlay");
    if (overlay) return overlay;
    overlay = document.createElement("div");
    overlay.id = "cert-preview-overlay";
    overlay.className = "cert-preview-overlay hidden";
    overlay.innerHTML = `
      <div class="cert-preview-chrome">
        <button type="button" class="btn-primary small" id="cert-preview-print">${t("addon.certifications.ui.print", "Print")}</button>
        <button type="button" class="btn-ghost" id="cert-preview-close">${t("addon.certifications.ui.close", "Close")}</button>
      </div>
      <div class="cert-preview-scroll"><div class="cert-print-area" id="cert-print-area"></div></div>
    `;
    document.body.appendChild(overlay);
    overlay.querySelector("#cert-preview-close").addEventListener("click", closeCertPreview);
    overlay.querySelector("#cert-preview-print").addEventListener("click", () => window.print());
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeCertPreview();
    });
    return overlay;
  }

  function openCertPreview(cert, opts) {
    previewCertificate = cert;
    previewOptions = opts;
    const overlay = ensureOverlay();
    overlay.querySelector("#cert-print-area").innerHTML = certificateHTML(cert, opts);
    overlay.classList.remove("hidden");
  }

  function closeCertPreview() {
    const overlay = document.getElementById("cert-preview-overlay");
    if (overlay) overlay.classList.add("hidden");
    previewCertificate = null;
    previewOptions = null;
  }

  // --- "My Certificates" tab -------------------------------------------

  async function renderMineTab(root) {
    root.innerHTML = `<p class="field-note">${t("addon.certifications.ui.loading_mine", "Loading your certificates...")}</p>`;
    let certs;
    try {
      certs = await window.OpenCTF.api("/api/certifications/mine");
    } catch (err) {
      root.innerHTML = `<p class="form-error">${escapeHtml(err.message)}</p>`;
      return;
    }
    if (certs.length === 0) {
      root.innerHTML = `<p class="cert-empty">${t("addon.certifications.ui.none_mine", "No certificates issued to you yet.")}</p>`;
      return;
    }
    root.innerHTML = `<div class="cert-list">${certs.map((c) => `
      <div class="cert-row">
        <div class="cert-row-info">
          <div class="cert-row-title">
            ${escapeHtml(c.title)}
            <span class="cert-tag ${c.expired ? "expired" : "valid"}">${c.expired ? t("addon.certifications.ui.expired", "Expired") : t("addon.certifications.ui.valid", "Valid")}</span>
          </div>
          <div class="cert-row-meta">${t("addon.certifications.ui.issued", "Issued")} ${formatDate(c.issued_at)} &middot; ${t("addon.certifications.ui.id", "ID")}: <code>${escapeHtml(c.cert_uid)}</code></div>
        </div>
        <div class="cert-row-actions">
          <button type="button" class="btn-primary small" data-cert-view="${c.id}">${t("addon.certifications.ui.view_print", "View / Print")}</button>
        </div>
      </div>`).join("")}</div>`;

    const byId = new Map(certs.map((c) => [String(c.id), c]));
    root.querySelectorAll("[data-cert-view]").forEach((btn) => {
      btn.addEventListener("click", () => openCertPreview(byId.get(btn.dataset.certView)));
    });
  }

  // --- "Verify a Certificate" tab ---------------------------------------

  function renderVerifyTab(root) {
    root.innerHTML = `
      <p class="field-note">${t("addon.certifications.ui.verify_intro", "Anyone can verify a certificate's ID here - no account needed. Ask the holder for the ID printed on it.")}</p>
      <form id="cert-verify-form" class="cert-verify-form">
        <input type="text" id="cert-verify-input" placeholder="e.g. 485F-7DFA-461D-BD54" autocomplete="off" aria-label="${t("addon.certifications.ui.certificate_id", "Certificate ID")}" />
        <button type="submit" class="btn-primary">${t("addon.certifications.ui.verify", "Verify")}</button>
      </form>
      <div id="cert-verify-result" class="cert-verify-result"></div>
    `;
    root.querySelector("#cert-verify-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = root.querySelector("#cert-verify-input");
      const resultEl = root.querySelector("#cert-verify-result");
      const code = input.value.trim();
      if (!code) return;
      resultEl.className = "cert-verify-result";
      resultEl.textContent = t("common.checking", "Checking...");
      try {
        const res = await fetch(`${SERVER_BASE_URL}/api/certifications/verify/${encodeURIComponent(code)}`);
        const body = await res.json();
        if (!res.ok || !body.found) {
          resultEl.className = "cert-verify-result not-found";
          resultEl.textContent = t("addon.certifications.ui.not_found", "No certificate found with that ID.");
          return;
        }
        resultEl.className = "cert-verify-result";
        resultEl.innerHTML = certificateHTML(body);
      } catch (err) {
        resultEl.className = "cert-verify-result not-found";
        resultEl.textContent = err.message;
      }
    });
  }

  // --- "Manage" tab (admin only) ----------------------------------------

  async function renderManageTab(root) {
    root.innerHTML = `<p class="field-note">${t("common.loading", "Loading...")}</p>`;
    let users = [];
    try {
      users = await window.OpenCTF.api("/api/admin/users");
    } catch {
      users = [];
    }

    root.innerHTML = `
      <h3 class="cert-section-heading">${t("addon.certifications.ui.issue_heading", "Issue a new certificate")}</h3>
      <form id="cert-create-form" class="cert-manage-form">
        <label>${t("challenge.title", "Title")}
          <input type="text" id="cert-f-title" placeholder="e.g. Web Exploitation Fundamentals" required />
        </label>
        <label>${t("addon.certifications.ui.style", "Style")}
          <select id="cert-f-style">
            ${STYLE_OPTIONS.map((s) => `<option value="${s.value}">${t(`addon.certifications.ui.${s.key}`, s.label)}</option>`).join("")}
          </select>
        </label>
        <label class="span-2">${t("addon.certifications.ui.description_optional", "Description (optional)")}
          <textarea id="cert-f-desc" rows="2" placeholder="${t("addon.certifications.ui.description_placeholder", "What this certifies, shown on the certificate itself")}"></textarea>
        </label>
        <label>${t("addon.certifications.ui.recipient_existing", "Recipient (existing user)")}
          <select id="cert-f-user">
            <option value="">&mdash; ${t("addon.certifications.ui.no_account_type_name", "No account (type a name)")} &mdash;</option>
            ${users.map((u) => `<option value="${escapeHtml(u.username)}">${escapeHtml(u.display_name)} (${escapeHtml(u.username)})</option>`).join("")}
          </select>
        </label>
        <label>${t("addon.certifications.ui.recipient_name", "Recipient name (printed on certificate)")}
          <input type="text" id="cert-f-name" placeholder="${t("addon.certifications.ui.full_name_placeholder", "Full name as it should appear")}" required />
        </label>
        <label>${t("addon.certifications.ui.expiration", "Expiration")}
          <select id="cert-f-expiry-mode">
            <option value="never">${t("addon.certifications.ui.never_expires", "Never expires")}</option>
            <option value="days">${t("addon.certifications.ui.expires_days", "Expires N days from now")}</option>
            <option value="date">${t("addon.certifications.ui.expires_date", "Expires on a specific date")}</option>
          </select>
        </label>
        <label id="cert-f-expiry-days-wrap" class="hidden">${t("addon.certifications.ui.days_from_now", "Days from now")}
          <input type="number" id="cert-f-expiry-days" min="1" value="365" />
        </label>
        <label id="cert-f-expiry-date-wrap" class="hidden">${t("addon.certifications.ui.expiration_date", "Expiration date")}
          <input type="date" id="cert-f-expiry-date" />
        </label>
        <div class="cert-manage-form-actions">
          <button type="button" class="btn-ghost" id="cert-f-preview">${t("addon.certifications.ui.preview", "Preview")}</button>
          <button type="submit" class="btn-primary">${t("addon.certifications.ui.issue", "Issue certificate")}</button>
          <span class="form-result" id="cert-f-result"></span>
        </div>
      </form>

      <h3 class="cert-section-heading">${t("addon.certifications.ui.all_issued", "All issued certificates")}</h3>
      <div id="cert-all-list"><p class="field-note">${t("common.loading", "Loading...")}</p></div>
    `;

    const userSelect = root.querySelector("#cert-f-user");
    const nameInput = root.querySelector("#cert-f-name");
    userSelect.addEventListener("change", () => {
      const chosen = users.find((u) => u.username === userSelect.value);
      if (chosen) nameInput.value = chosen.display_name || chosen.username;
    });

    const expiryMode = root.querySelector("#cert-f-expiry-mode");
    const expiryDaysWrap = root.querySelector("#cert-f-expiry-days-wrap");
    const expiryDateWrap = root.querySelector("#cert-f-expiry-date-wrap");
    expiryMode.addEventListener("change", () => {
      expiryDaysWrap.classList.toggle("hidden", expiryMode.value !== "days");
      expiryDateWrap.classList.toggle("hidden", expiryMode.value !== "date");
    });

    function currentFormCert() {
      const expires_at =
        expiryMode.value === "date" && root.querySelector("#cert-f-expiry-date").value
          ? new Date(root.querySelector("#cert-f-expiry-date").value).toISOString()
          : expiryMode.value === "days"
          ? new Date(Date.now() + Number(root.querySelector("#cert-f-expiry-days").value || 0) * 86400000).toISOString()
          : null;
      return {
        title: root.querySelector("#cert-f-title").value.trim() || t("addon.certifications.ui.untitled", "Untitled Certificate"),
        description: root.querySelector("#cert-f-desc").value.trim(),
        style: root.querySelector("#cert-f-style").value,
        recipient_name: nameInput.value.trim() || t("addon.certifications.ui.recipient_name_fallback", "Recipient Name"),
        issued_at: new Date().toISOString(),
        expires_at,
        expired: false,
        cert_uid: null,
      };
    }

    root.querySelector("#cert-f-preview").addEventListener("click", () => {
      openCertPreview(currentFormCert(), { preview: true });
    });

    root.querySelector("#cert-create-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const result = root.querySelector("#cert-f-result");
      result.textContent = "";
      result.className = "form-result";
      const title = root.querySelector("#cert-f-title").value.trim();
      const recipient_name = nameInput.value.trim();
      if (!title || !recipient_name) {
        result.textContent = t("addon.certifications.ui.required_fields", "Title and recipient name are required.");
        result.className = "form-result err";
        return;
      }
      const payload = {
        title,
        description: root.querySelector("#cert-f-desc").value.trim(),
        style: root.querySelector("#cert-f-style").value,
        recipient_username: userSelect.value || undefined,
        recipient_name,
      };
      if (expiryMode.value === "days") payload.expires_in_days = Number(root.querySelector("#cert-f-expiry-days").value || 0);
      if (expiryMode.value === "date") payload.expires_at = root.querySelector("#cert-f-expiry-date").value || undefined;

      try {
        await window.OpenCTF.api("/api/admin/certifications", { method: "POST", body: JSON.stringify(payload) });
        result.textContent = t("addon.certifications.ui.issued_success", "Certificate issued.");
        result.className = "form-result ok";
        root.querySelector("#cert-create-form").reset();
        expiryDaysWrap.classList.add("hidden");
        expiryDateWrap.classList.add("hidden");
        await renderAllCertsList(root.querySelector("#cert-all-list"));
      } catch (err) {
        result.textContent = err.message;
        result.className = "form-result err";
      }
    });

    await renderAllCertsList(root.querySelector("#cert-all-list"));
  }

  async function renderAllCertsList(el) {
    let certs;
    try {
      certs = await window.OpenCTF.api("/api/admin/certifications");
    } catch (err) {
      el.innerHTML = `<p class="form-error">${escapeHtml(err.message)}</p>`;
      return;
    }
    if (certs.length === 0) {
      el.innerHTML = `<p class="cert-empty">${t("addon.certifications.ui.none_issued", "No certificates issued yet.")}</p>`;
      return;
    }
    el.innerHTML = `<div class="cert-list">${certs.map((c) => `
      <div class="cert-row">
        <div class="cert-row-info">
          <div class="cert-row-title">
            ${escapeHtml(c.title)}
            <span class="cert-tag ${c.expired ? "expired" : "valid"}">${c.expired ? t("addon.certifications.ui.expired", "Expired") : t("addon.certifications.ui.valid", "Valid")}</span>
          </div>
          <div class="cert-row-meta">
            ${escapeHtml(c.recipient_name)}${c.recipient_username ? ` (${escapeHtml(c.recipient_username)})` : ` &middot; ${t("addon.certifications.ui.no_account", "no account")}`}
            &middot; ${t("addon.certifications.ui.issued", "Issued")} ${formatDate(c.issued_at)} &middot; <code>${escapeHtml(c.cert_uid)}</code>
          </div>
        </div>
        <div class="cert-row-actions">
          <button type="button" class="btn-ghost" data-cert-view="${c.id}">${t("addon.certifications.ui.view", "View")}</button>
          <button type="button" class="btn-ghost" data-cert-delete="${c.id}">${t("common.delete", "Delete")}</button>
        </div>
      </div>`).join("")}</div>`;

    const byId = new Map(certs.map((c) => [String(c.id), c]));
    el.querySelectorAll("[data-cert-view]").forEach((btn) => {
      btn.addEventListener("click", () => openCertPreview(byId.get(btn.dataset.certView)));
    });
    el.querySelectorAll("[data-cert-delete]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        if (!confirm(t("addon.certifications.ui.confirm_delete", "Delete this certificate? This can't be undone."))) return;
        try {
          await window.OpenCTF.api(`/api/admin/certifications/${btn.dataset.certDelete}`, { method: "DELETE" });
          await renderAllCertsList(el);
        } catch (err) {
          alert(err.message);
        }
      });
    });
  }

  // --- Top-level view -----------------------------------------------------

  function render(container) {
    injectStylesheet();
    const user = window.OpenCTF.getUser();
    const isAdmin = !!(user && user.is_admin);

    container.innerHTML = `
      <header class="view-header"><h2>${t("addon.certifications.nav_label", "Certifications")}</h2></header>
      <div class="cert-subtabs">
        <button type="button" class="cert-subtab-btn" data-cert-subtab="mine">${t("addon.certifications.ui.my_certificates", "My Certificates")}</button>
        <button type="button" class="cert-subtab-btn" data-cert-subtab="verify">${t("addon.certifications.ui.verify_tab", "Verify a Certificate")}</button>
        ${isAdmin ? `<button type="button" class="cert-subtab-btn" data-cert-subtab="manage">${t("addon.certifications.ui.manage", "Manage")}</button>` : ""}
      </div>
      <div id="cert-tab-mine" class="cert-subtab"></div>
      <div id="cert-tab-verify" class="cert-subtab hidden"></div>
      ${isAdmin ? '<div id="cert-tab-manage" class="cert-subtab hidden"></div>' : ""}
    `;

    if (!isAdmin && activeSubtab === "manage") activeSubtab = "mine";

    function showSubtab(name) {
      activeSubtab = name;
      container.querySelectorAll("[data-cert-subtab]").forEach((b) => b.classList.toggle("active", b.dataset.certSubtab === name));
      container.querySelectorAll(".cert-subtab").forEach((s) => s.classList.add("hidden"));
      const pane = container.querySelector(`#cert-tab-${name}`);
      if (pane) pane.classList.remove("hidden");
      if (name === "mine") return renderMineTab(container.querySelector("#cert-tab-mine"));
      if (name === "verify") return renderVerifyTab(container.querySelector("#cert-tab-verify"));
      if (name === "manage" && isAdmin) return renderManageTab(container.querySelector("#cert-tab-manage"));
    }

    container.querySelectorAll("[data-cert-subtab]").forEach((btn) => {
      btn.addEventListener("click", () => showSubtab(btn.dataset.certSubtab));
    });

    return showSubtab(activeSubtab);
  }

  window.OpenCTF.on("ready", loadBranding);
  window.OpenCTF.on("language:changed", () => {
    const container = document.getElementById(`view-${ADDON_ID}`);
    if (container && !container.classList.contains("hidden")) {
      const values = [...container.querySelectorAll("input, textarea, select")].map((field) => [
        field.id,
        field.type === "checkbox" ? field.checked : field.value,
      ]);
      Promise.resolve(render(container)).then(() => {
        values.forEach(([id, value]) => {
          const field = id && container.querySelector(`#${id}`);
          if (!field) return;
          if (field.type === "checkbox") field.checked = value;
          else field.value = value;
        });
      });
    }
    const overlay = document.getElementById("cert-preview-overlay");
    if (previewCertificate && overlay && !overlay.classList.contains("hidden")) {
      openCertPreview(previewCertificate, previewOptions);
    }
  });
  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id === ADDON_ID) BRANDING = { ...FALLBACK_BRANDING, ...config };
  });
  // Pushed by the server's own /api/admin/certifications routes via
  // broadcast_event() - see handleLiveEvent()'s default case in
  // renderer.js, which forwards any unrecognized server event as
  // "server:<type>" rather than the host app needing to know about this
  // addon's business ahead of time.
  window.OpenCTF.on("server:certification_issued", () => {
    if (activeSubtab === "manage") {
      const list = document.getElementById("cert-all-list");
      if (list) renderAllCertsList(list);
    }
  });
  window.OpenCTF.on("server:certification_revoked", () => {
    const list = document.getElementById("cert-all-list");
    if (list) renderAllCertsList(list);
    const mine = document.getElementById("cert-tab-mine");
    if (mine && activeSubtab === "mine") renderMineTab(mine);
  });

  window.OpenCTF.registerView({
    id: ADDON_ID,
    label: "Certifications",
    labelKey: "addon.certifications.nav_label",
    render,
  });
})();
