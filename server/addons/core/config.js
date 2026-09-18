// core addon config GUI - see motd-banner/config.js for a more heavily
// commented example of the window.OpenCTFAdmin contract this relies on.
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
      <label class="toggle-row">
        <span class="toggle-switch">
          <input type="checkbox" id="core-cfg-toasts" />
          <span class="toggle-track"></span>
        </span>
        Toast notification on solve
      </label>
      <label class="toggle-row">
        <span class="toggle-switch">
          <input type="checkbox" id="core-cfg-dot" />
          <span class="toggle-track"></span>
        </span>
        Live-updates connection dot
      </label>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="core-cfg-save">Save</button>
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
        result.textContent = "Saved - live on every open client.";
        result.className = "form-result ok";
      } catch (err) {
        result.textContent = err.message;
        result.className = "form-result err";
      }
    });
  });
})();
