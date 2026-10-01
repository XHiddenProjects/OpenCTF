// Stats addon
//
// Adds a "Stats" tab (its own sidebar entry and view, via
// window.OpenCTF.registerView() - see docs/ADDON_DEVELOPMENT.md) that
// renders the same data GET /api/scoreboard already provides, but as a
// chart (plain inline SVG, styled with the host app's own CSS custom
// properties from client/src/styles.css) instead of a table. The player
// can switch both the metric (score vs. solve count) and the chart type
// (bar / line / area) from the toolbar; a gear-button config screen
// (config.js) lets an admin pick the defaults for both, plus how many
// teams get plotted.
//
// Responsiveness: the SVG itself always scales fluidly (viewBox + CSS
// width: 100%), but a ResizeObserver on the chart's own wrapper also
// switches the whole chart into a "compact" layout (shorter labels,
// smaller font, less padding) once the wrapper gets narrower than
// COMPACT_BREAKPOINT - rebuilding on every measured width would be
// wasteful, so this is a single layout flip, debounced against resize
// thrashing, not a continuous recompute.
(function () {
  const ADDON_ID = "stats";

  // document.currentScript is only valid during this script's own
  // synchronous top-level execution - capture it now, not inside a
  // Promise/event handler, so we can still find our own folder later.
  const SCRIPT_URL = document.currentScript ? document.currentScript.src : "";
  const ADDON_BASE_URL = SCRIPT_URL.replace(/\/addon\.js(\?.*)?$/, "");

  const t = window.OpenCTF.t;

  const CHART_TYPES = ["bar", "line", "area"];
  const FALLBACK_CONFIG = { metric: "score", chart_type: "bar", max_teams: 15 };
  const COMPACT_BREAKPOINT = 460;

  let CONFIG = { ...FALLBACK_CONFIG };
  let currentMetric = CONFIG.metric;
  let currentChartType = CONFIG.chart_type;
  let currentContainer = null;
  let currentCompact = false;
  let resizeObserver = null;
  let resizeDebounce = null;

  function injectStylesheet() {
    if (document.getElementById("stats-addon-styles") || !ADDON_BASE_URL) return;
    const link = document.createElement("link");
    link.id = "stats-addon-styles";
    link.rel = "stylesheet";
    link.href = `${ADDON_BASE_URL}/style.css`;
    document.head.appendChild(link);
  }

  function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    })[c]);
  }

  function truncate(str, n) {
    return str.length > n ? `${str.slice(0, n - 1)}…` : str;
  }

  async function loadConfig() {
    try {
      CONFIG = { ...FALLBACK_CONFIG, ...(await window.OpenCTF.getAddonConfig(ADDON_ID)) };
    } catch {
      CONFIG = { ...FALLBACK_CONFIG };
    }
    currentMetric = CONFIG.metric === "solves" ? "solves" : "score";
    currentChartType = CHART_TYPES.includes(CONFIG.chart_type) ? CONFIG.chart_type : "bar";
  }

  function rankedRows(board, metric) {
    const maxTeams = Math.max(1, Number(CONFIG.max_teams) || FALLBACK_CONFIG.max_teams);
    return board
      .slice()
      .sort((a, b) => b[metric] - a[metric])
      .slice(0, maxTeams);
  }

  const medalClass = (i) => (i === 0 ? " stats-bar-1" : i === 1 ? " stats-bar-2" : i === 2 ? " stats-bar-3" : "");

  // --- Chart builders ----------------------------------------------------
  // Each builder takes the already-ranked rows, the metric key, and
  // whether to lay out compact, and returns a self-contained inline
  // <svg>. All three read colors from the CSS classes in style.css
  // (which in turn read the host app's own --accent/--ok/etc custom
  // properties), so they follow whatever theme is active instead of
  // hardcoding colors. Every value label uses a CSS paint-order halo
  // (see .stats-chart-value in style.css) instead of a hand-measured
  // background rect, so numbers stay legible over a bar, line, or area
  // fill at any width without per-label width math.

  function buildBarChart(rows, metric, compact) {
    const barHeight = compact ? 24 : 26;
    const gap = compact ? 10 : 12;
    const topPad = 8;
    const width = 640;
    const labelWidth = compact ? 92 : 150;
    const valueGutter = compact ? 46 : 56;
    const barAreaWidth = width - labelWidth - valueGutter;
    const chartHeight = rows.length * (barHeight + gap) + topPad;
    const max = Math.max(1, ...rows.map((r) => r[metric]));
    const labelChars = compact ? 11 : 20;

    let bars = "";
    rows.forEach((row, i) => {
      const y = topPad + i * (barHeight + gap);
      const value = row[metric] || 0;
      const barW = max > 0 ? (value / max) * barAreaWidth : 0;
      const drawnW = Math.max(barW, value > 0 ? 3 : 0);
      bars += `
        <g class="stats-row">
          <text x="${labelWidth - 10}" y="${y + barHeight / 2 + 5}" text-anchor="end" class="stats-chart-label"><title>${escapeHtml(row.team)}</title>${escapeHtml(truncate(row.team, labelChars))}</text>
          <rect x="${labelWidth}" y="${y}" width="${barAreaWidth}" height="${barHeight}" rx="5" class="stats-chart-track"></rect>
          <rect x="${labelWidth}" y="${y}" width="${drawnW}" height="${barHeight}" rx="5" class="stats-chart-bar${medalClass(i)}"></rect>
          <text x="${labelWidth + drawnW + 8}" y="${y + barHeight / 2 + 5}" class="stats-chart-value">${value}</text>
        </g>`;
    });

    return `<svg viewBox="0 0 ${width} ${chartHeight}" class="stats-chart${compact ? " stats-chart-compact" : ""}" role="img"
        aria-label="${escapeHtml(t("addon.stats.chart_aria_bar", "Leaderboard bar chart"))}">${bars}</svg>`;
  }

  // Shared layout for the two point-based charts (line/area): teams walk
  // left-to-right by rank on the x-axis, the metric value on the y-axis.
  function pointLayout(rows, metric, compact) {
    const width = 640;
    const height = compact ? 260 : 320;
    const leftPad = compact ? 34 : 46;
    const rightPad = 16;
    const topPad = compact ? 22 : 16;
    const bottomPad = compact ? 46 : 56;
    const plotW = width - leftPad - rightPad;
    const plotH = height - topPad - bottomPad;
    const max = Math.max(1, ...rows.map((r) => r[metric]));
    const stepX = rows.length > 1 ? plotW / (rows.length - 1) : 0;

    const points = rows.map((row, i) => {
      const value = row[metric] || 0;
      const x = leftPad + (rows.length > 1 ? i * stepX : plotW / 2);
      // Clamp so a leader's value label never gets clipped by the top edge.
      const rawY = topPad + plotH - (value / max) * plotH;
      const y = Math.max(rawY, topPad + 12);
      return { x, y, value, team: row.team };
    });

    return { width, height, leftPad, topPad, plotW, plotH, bottomPad, points };
  }

  function axisAndLabels({ width, height, leftPad, topPad, plotH, bottomPad, points }, compact) {
    const baseline = topPad + plotH;
    const labelChars = compact ? 8 : 12;
    let labels = "";
    points.forEach((p) => {
      labels += `
        <g class="stats-row">
          <line x1="${p.x}" y1="${baseline}" x2="${p.x}" y2="${baseline + 5}" class="stats-chart-tick" vector-effect="non-scaling-stroke"></line>
          <text x="${p.x}" y="${height - bottomPad + 22}" text-anchor="middle" class="stats-chart-label" transform="rotate(-35 ${p.x} ${height - bottomPad + 22})">
            <title>${escapeHtml(p.team)}</title>${escapeHtml(truncate(p.team, labelChars))}
          </text>
          <text x="${p.x}" y="${p.y - 10}" text-anchor="middle" class="stats-chart-value">${p.value}</text>
        </g>`;
    });
    return `
      <line x1="${leftPad}" y1="${topPad}" x2="${leftPad}" y2="${baseline}" class="stats-chart-axis" vector-effect="non-scaling-stroke"></line>
      <line x1="${leftPad}" y1="${baseline}" x2="${width - 16}" y2="${baseline}" class="stats-chart-axis" vector-effect="non-scaling-stroke"></line>
      ${labels}`;
  }

  function buildLineChart(rows, metric, compact) {
    const layout = pointLayout(rows, metric, compact);
    const { width, height, points } = layout;
    const path = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
    const dots = points
      .map((p, i) => `<circle cx="${p.x}" cy="${p.y}" r="4" class="stats-chart-dot${medalClass(i)}"></circle>`)
      .join("");

    return `<svg viewBox="0 0 ${width} ${height}" class="stats-chart${compact ? " stats-chart-compact" : ""}" role="img"
        aria-label="${escapeHtml(t("addon.stats.chart_aria_line", "Leaderboard line chart"))}">
        ${axisAndLabels(layout, compact)}
        <path d="${path}" class="stats-chart-line" vector-effect="non-scaling-stroke"></path>
        ${dots}
      </svg>`;
  }

  function buildAreaChart(rows, metric, compact) {
    const layout = pointLayout(rows, metric, compact);
    const { width, height, points, topPad, plotH } = layout;
    const baseline = topPad + plotH;
    const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
    const areaPath = `${linePath} L${points[points.length - 1].x},${baseline} L${points[0].x},${baseline} Z`;
    const dots = points
      .map((p, i) => `<circle cx="${p.x}" cy="${p.y}" r="4" class="stats-chart-dot${medalClass(i)}"></circle>`)
      .join("");

    return `<svg viewBox="0 0 ${width} ${height}" class="stats-chart${compact ? " stats-chart-compact" : ""}" role="img"
        aria-label="${escapeHtml(t("addon.stats.chart_aria_area", "Leaderboard area chart"))}">
        ${axisAndLabels(layout, compact)}
        <path d="${areaPath}" class="stats-chart-area"></path>
        <path d="${linePath}" class="stats-chart-line" vector-effect="non-scaling-stroke"></path>
        ${dots}
      </svg>`;
  }

  function buildChart(chartType, rows, metric, compact) {
    if (chartType === "line") return buildLineChart(rows, metric, compact);
    if (chartType === "area") return buildAreaChart(rows, metric, compact);
    return buildBarChart(rows, metric, compact);
  }

  function metricLabel(metric) {
    return metric === "solves"
      ? t("addon.stats.metric_solves", "Solves")
      : t("addon.stats.metric_score", "Score");
  }

  // --- Data + render -----------------------------------------------------

  let lastBoard = null;

  function renderChartOnly(container) {
    const wrap = container.querySelector("#stats-chart-wrap");
    if (!wrap || !lastBoard) return;
    if (!lastBoard.length) {
      wrap.innerHTML = `<p class="stats-empty" data-i18n="addon.stats.empty">${t("addon.stats.empty", "No teams on the board yet.")}</p>`;
      return;
    }
    const rows = rankedRows(lastBoard, currentMetric);
    wrap.innerHTML = buildChart(currentChartType, rows, currentMetric, currentCompact);
  }

  async function refresh(container) {
    const wrap = container.querySelector("#stats-chart-wrap");
    if (!wrap) return;
    wrap.innerHTML = `<p class="field-note">${t("common.loading", "Loading...")}</p>`;
    try {
      lastBoard = await window.OpenCTF.api("/api/scoreboard");
    } catch (err) {
      wrap.innerHTML = `<p class="form-error">${escapeHtml(err.message)}</p>`;
      return;
    }
    if (!lastBoard.length) {
      wrap.innerHTML = `<p class="stats-empty" data-i18n="addon.stats.empty">${t("addon.stats.empty", "No teams on the board yet.")}</p>`;
      return;
    }

    const rows = rankedRows(lastBoard, currentMetric);
    wrap.innerHTML = buildChart(currentChartType, rows, currentMetric, currentCompact);

    const summary = container.querySelector("#stats-summary");
    if (summary) {
      const leader = rows[0];
      summary.textContent = t("addon.stats.summary", "{count} teams · leading: {team} ({value} {metric})", {
        count: lastBoard.length,
        team: leader.team,
        value: leader[currentMetric] || 0,
        metric: metricLabel(currentMetric).toLowerCase(),
      });
    }
  }

  function watchResize(container) {
    if (resizeObserver) resizeObserver.disconnect();
    if (typeof ResizeObserver === "undefined") return;
    const wrap = container.querySelector("#stats-chart-wrap");
    if (!wrap) return;
    resizeObserver = new ResizeObserver((entries) => {
      const width = entries[0] && entries[0].contentRect ? entries[0].contentRect.width : wrap.clientWidth;
      const compact = width > 0 && width < COMPACT_BREAKPOINT;
      if (compact === currentCompact) return;
      clearTimeout(resizeDebounce);
      resizeDebounce = setTimeout(() => {
        currentCompact = compact;
        renderChartOnly(container);
      }, 120);
    });
    resizeObserver.observe(wrap);
  }

  function render(container) {
    injectStylesheet();
    currentContainer = container;

    container.innerHTML = `
      <header class="view-header">
        <h2 data-i18n="addon.stats.title">${t("addon.stats.title", "Stats")}</h2>
      </header>
      <div class="stats-toolbar">
        <div class="stats-metric-toggle" role="group" aria-label="${escapeHtml(t("addon.stats.metric_group_label", "Metric"))}">
          <button type="button" class="stats-metric-btn" data-metric="score" data-i18n="addon.stats.metric_score">${t("addon.stats.metric_score", "Score")}</button>
          <button type="button" class="stats-metric-btn" data-metric="solves" data-i18n="addon.stats.metric_solves">${t("addon.stats.metric_solves", "Solves")}</button>
        </div>
        <div class="stats-chart-type-toggle" role="group" aria-label="${escapeHtml(t("addon.stats.chart_type_group_label", "Chart type"))}">
          <button type="button" class="stats-chart-type-btn" data-chart-type="bar" data-i18n="addon.stats.chart_bar">${t("addon.stats.chart_bar", "Bar")}</button>
          <button type="button" class="stats-chart-type-btn" data-chart-type="line" data-i18n="addon.stats.chart_line">${t("addon.stats.chart_line", "Line")}</button>
          <button type="button" class="stats-chart-type-btn" data-chart-type="area" data-i18n="addon.stats.chart_area">${t("addon.stats.chart_area", "Area")}</button>
        </div>
        <span class="field-note" id="stats-summary"></span>
      </div>
      <div id="stats-chart-wrap" class="stats-chart-wrap"></div>
    `;

    function updateActiveButtons() {
      container.querySelectorAll(".stats-metric-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.metric === currentMetric);
      });
      container.querySelectorAll(".stats-chart-type-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.chartType === currentChartType);
      });
    }
    container.querySelectorAll(".stats-metric-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        currentMetric = btn.dataset.metric;
        updateActiveButtons();
        renderChartOnly(container);
        refresh(container);
      });
    });
    container.querySelectorAll(".stats-chart-type-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        currentChartType = btn.dataset.chartType;
        updateActiveButtons();
        renderChartOnly(container);
      });
    });
    updateActiveButtons();

    const wrap = container.querySelector("#stats-chart-wrap");
    currentCompact = wrap.clientWidth > 0 && wrap.clientWidth < COMPACT_BREAKPOINT;
    watchResize(container);

    refresh(container);
  }

  // Best-effort live refresh: fires right after this player's own correct
  // submission (see docs/ADDON_DEVELOPMENT.md's event table) - not a full
  // scoreboard push for every player, but enough to keep the chart from
  // looking stale while someone's actually sitting on this tab.
  window.OpenCTF.on("challenge:solved", () => {
    if (currentContainer && currentContainer.isConnected) refresh(currentContainer);
  });

  window.OpenCTF.on("language:changed", () => {
    if (!currentContainer || !currentContainer.isConnected) return;
    const metricGroup = currentContainer.querySelector(".stats-metric-toggle");
    const chartGroup = currentContainer.querySelector(".stats-chart-type-toggle");
    if (metricGroup) metricGroup.setAttribute("aria-label", t("addon.stats.metric_group_label", "Metric"));
    if (chartGroup) chartGroup.setAttribute("aria-label", t("addon.stats.chart_type_group_label", "Chart type"));
    if (!currentContainer.classList.contains("hidden")) refresh(currentContainer);
  });

  window.OpenCTF.on("ready", loadConfig);
  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id !== ADDON_ID) return;
    CONFIG = { ...FALLBACK_CONFIG, ...config };
    currentMetric = CONFIG.metric === "solves" ? "solves" : "score";
    currentChartType = CHART_TYPES.includes(CONFIG.chart_type) ? CONFIG.chart_type : "bar";
    if (currentContainer && currentContainer.isConnected) refresh(currentContainer);
  });

  window.OpenCTF.registerView({
    id: ADDON_ID,
    label: "Stats",
    labelKey: "addon.stats.nav_label",
    render,
  });
})();
