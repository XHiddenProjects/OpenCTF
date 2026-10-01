// Stats addon config GUI - see server/addons/motd-banner/config.js for a
// more heavily commented example of the window.OpenCTFAdmin contract this
// relies on. Only the default metric and how many teams get plotted are
// configurable here - whether the addon runs at all is always the toggle
// in the addon list, never a duplicate setting in here (see
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
        <span data-i18n="addon.stats.config.metric_label">${t("addon.stats.config.metric_label", "Default metric")}</span>
        <select id="stats-cfg-metric">
          <option value="score">${t("addon.stats.metric_score", "Score")}</option>
          <option value="solves">${t("addon.stats.metric_solves", "Solves")}</option>
        </select>
      </label>
      <label>
        <span data-i18n="addon.stats.config.chart_type_label">${t("addon.stats.config.chart_type_label", "Default chart type")}</span>
        <select id="stats-cfg-chart-type">
          <option value="bar">${t("addon.stats.chart_bar", "Bar")}</option>
          <option value="line">${t("addon.stats.chart_line", "Line")}</option>
          <option value="area">${t("addon.stats.chart_area", "Area")}</option>
        </select>
      </label>
      <label>
        <span data-i18n="addon.stats.config.max_teams_label">${t("addon.stats.config.max_teams_label", "Teams to plot")}</span>
        <input type="number" id="stats-cfg-max-teams" min="1" max="100" step="1" />
      </label>
      <p class="field-note" data-i18n="addon.stats.config.max_teams_note">${t("addon.stats.config.max_teams_note", "Only the top teams by the selected metric are drawn, so the chart stays readable on a large scoreboard.")}</p>
      <div class="form-actions">
        <button type="button" class="btn-primary small" id="stats-cfg-save" data-i18n="common.save">${t("common.save", "Save")}</button>
        <span class="form-result" id="stats-cfg-result"></span>
      </div>
    `;

    container.querySelector("#stats-cfg-metric").value = config.metric === "solves" ? "solves" : "score";
    container.querySelector("#stats-cfg-chart-type").value = ["bar", "line", "area"].includes(config.chart_type) ? config.chart_type : "bar";
    container.querySelector("#stats-cfg-max-teams").value = Number(config.max_teams) || 15;

    container.querySelector("#stats-cfg-save").addEventListener("click", async () => {
      const result = container.querySelector("#stats-cfg-result");
      result.textContent = "";
      result.className = "form-result";
      const maxTeams = Math.min(100, Math.max(1, Number(container.querySelector("#stats-cfg-max-teams").value) || 15));
      try {
        const chartType = container.querySelector("#stats-cfg-chart-type").value;
        await window.OpenCTFAdmin.save({
          metric: container.querySelector("#stats-cfg-metric").value === "solves" ? "solves" : "score",
          chart_type: ["bar", "line", "area"].includes(chartType) ? chartType : "bar",
          max_teams: maxTeams,
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
