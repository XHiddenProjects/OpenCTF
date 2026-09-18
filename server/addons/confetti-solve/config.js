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
        Particle count
        <input type="number" id="confetti-cfg-count" min="10" max="500" step="10" />
      </label>
      <label>
        Colors (comma-separated hex)
        <input type="text" id="confetti-cfg-colors" />
      </label>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="confetti-cfg-save">Save</button>
        <button type="button" class="btn-ghost" id="confetti-cfg-preview">Preview</button>
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
        result.textContent = "Saved - live on every open client.";
        result.className = "form-result ok";
      } catch (err) {
        result.textContent = err.message;
        result.className = "form-result err";
      }
    });
  });
})();
