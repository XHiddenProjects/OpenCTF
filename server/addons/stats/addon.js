// Stats addon
//
// Adds a "Stats" tab (its own sidebar entry and view, via
// window.OpenCTF.registerView() - see docs/ADDON_DEVELOPMENT.md) that shows
// the scoreboard as an interactive chart (plain inline SVG, styled with the
// host app's own CSS custom properties) instead of a table.
//
//   Bar         the current leaderboard (GET /api/scoreboard).
//   Line / Area every team's progress over time (GET /api/scoreboard/timeline):
//               a step line per team that climbs each time it captures a flag.
//
// The toolbar switches the metric (score vs. solve count) and chart type; the
// gear-button config screen (config.js) sets the defaults and how many teams
// are plotted. Every chart has hover / keyboard-focus / touch tooltips with
// the exact numbers, a value axis with gridlines, and (for the time charts) a
// legend that can show or hide individual teams.
//
// Responsiveness: the SVG scales fluidly (viewBox + width: 100%); a
// ResizeObserver also flips the chart into a "compact" layout (fewer ticks,
// shorter labels) once its wrapper is narrower than COMPACT_BREAKPOINT.
(function () {
  const ADDON_ID = "stats";

  // document.currentScript is only valid during this script's own
  // synchronous top-level execution - capture it now.
  const SCRIPT_URL = document.currentScript ? document.currentScript.src : "";
  const ADDON_BASE_URL = SCRIPT_URL.replace(/\/addon\.js(\?.*)?$/, "");

  const t = window.OpenCTF.t;

  const CHART_TYPES = ["bar", "line", "area"];
  const FALLBACK_CONFIG = { metric: "score", chart_type: "bar", max_teams: 15 };
  const COMPACT_BREAKPOINT = 460;
  const PALETTE_SIZE = 10;
  const VIEW_W = 640;

  let CONFIG = { ...FALLBACK_CONFIG };
  let currentMetric = CONFIG.metric;
  let currentChartType = CONFIG.chart_type;
  let currentContainer = null;
  let currentCompact = false;
  let resizeObserver = null;
  let resizeDebounce = null;
  let lastBoard = null;
  let lastTimeline = null;
  let timelineLoadedAt = 0;
  const hiddenTeams = new Set();
  // Time window for line/area charts, in ms (0 = all time).
  const RANGES = { all: 0, "24h": 24 * 3600 * 1000, "6h": 6 * 3600 * 1000, "1h": 3600 * 1000 };
  let currentRange = "all";

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

  const truncate = (str, n) => (str.length > n ? `${str.slice(0, n - 1)}…` : str);
  const fmtNum = (n) => Number(n || 0).toLocaleString();

  async function loadConfig() {
    try {
      CONFIG = { ...FALLBACK_CONFIG, ...(await window.OpenCTF.getAddonConfig(ADDON_ID)) };
    } catch {
      CONFIG = { ...FALLBACK_CONFIG };
    }
    applyConfigDefaults();
  }

  function applyConfigDefaults() {
    currentMetric = CONFIG.metric === "solves" ? "solves" : "score";
    currentChartType = CHART_TYPES.includes(CONFIG.chart_type) ? CONFIG.chart_type : "bar";
  }

  const maxTeams = () => Math.max(1, Number(CONFIG.max_teams) || FALLBACK_CONFIG.max_teams);

  function rankedRows(board, metric) {
    return board
      .slice()
      .sort((a, b) => b[metric] - a[metric])
      .slice(0, maxTeams());
  }

  const medalClass = (i) => (i === 0 ? " stats-bar-1" : i === 1 ? " stats-bar-2" : i === 2 ? " stats-bar-3" : "");

  function metricLabel(metric) {
    return metric === "solves"
      ? t("addon.stats.metric_solves", "Solves")
      : t("addon.stats.metric_score", "Score");
  }

  // --- Scales ---------------------------------------------------------------

  /** "Nice" value axis: round step (1/2/2.5/5 x 10^n), always whole numbers
   *  (points and solve counts are integers), top tick >= max. */
  function niceScale(max, targetTicks) {
    const safeMax = Math.max(1, max);
    const raw = safeMax / Math.max(1, targetTicks);
    const mag = Math.pow(10, Math.floor(Math.log10(raw)));
    const norm = raw / mag;
    const factor = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10;
    const step = Math.max(1, Math.ceil(factor * mag));
    const top = Math.ceil(safeMax / step) * step;
    const ticks = [];
    for (let v = 0; v <= top; v += step) ticks.push(v);
    return { top, ticks };
  }

  const HOUR = 3600 * 1000;
  const DAY = 24 * HOUR;

  // Short on purpose: five of these have to fit side by side.
  function formatTick(ms, spanMs) {
    const d = new Date(ms);
    if (spanMs <= 36 * HOUR) return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    if (spanMs <= 3 * DAY) return d.toLocaleDateString(undefined, { weekday: "short", hour: "numeric" });
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }

  const formatFull = (ms) => new Date(ms).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });

  // --- Tooltip ----------------------------------------------------------------

  function tooltipEl(wrap) {
    return wrap.querySelector(".stats-tooltip");
  }

  /** Show `html` near viewport point (clientX, clientY), kept inside `wrap`. */
  function showTooltip(wrap, html, clientX, clientY) {
    const tip = tooltipEl(wrap);
    if (!tip) return;
    tip.innerHTML = html;
    tip.hidden = false;
    const box = wrap.getBoundingClientRect();
    const tw = tip.offsetWidth;
    const th = tip.offsetHeight;
    let left = clientX - box.left + 14;
    let top = clientY - box.top + 14;
    if (left + tw > wrap.clientWidth - 4) left = clientX - box.left - tw - 14;
    if (top + th > wrap.clientHeight - 4) top = clientY - box.top - th - 14;
    tip.style.left = `${Math.max(4, left)}px`;
    tip.style.top = `${Math.max(4, top)}px`;
  }

  function hideTooltip(wrap) {
    const tip = tooltipEl(wrap);
    if (tip) tip.hidden = true;
  }

  // --- Bar chart (leaderboard) --------------------------------------------------

  function buildBarChart(rows, metric, compact) {
    const barHeight = compact ? 24 : 26;
    const gap = compact ? 10 : 12;
    const topPad = 6;
    const axisH = 24;
    const labelWidth = compact ? 92 : 150;
    const valueGutter = compact ? 46 : 56;
    const barAreaWidth = VIEW_W - labelWidth - valueGutter;
    const rowsH = rows.length * (barHeight + gap);
    const chartHeight = rowsH + topPad + axisH;
    const labelChars = compact ? 11 : 20;
    const scale = niceScale(Math.max(...rows.map((r) => r[metric] || 0)), compact ? 3 : 5);
    const xOf = (v) => labelWidth + (v / scale.top) * barAreaWidth;

    let grid = "";
    scale.ticks.forEach((v) => {
      const x = xOf(v);
      grid += `<line x1="${x}" y1="${topPad}" x2="${x}" y2="${topPad + rowsH - gap / 2}" class="stats-chart-grid"></line>
        <text x="${x}" y="${topPad + rowsH + 12}" text-anchor="middle" class="stats-chart-label stats-axis-label">${fmtNum(v)}</text>`;
    });

    let bars = "";
    rows.forEach((row, i) => {
      const y = topPad + i * (barHeight + gap);
      const value = row[metric] || 0;
      const barW = (value / scale.top) * barAreaWidth;
      const drawnW = Math.max(barW, value > 0 ? 3 : 0);
      bars += `
        <g class="stats-row stats-hover" data-index="${i}" tabindex="0" role="img"
           aria-label="${escapeHtml(`#${i + 1} ${row.team}: ${value} ${metricLabel(metric).toLowerCase()}`)}">
          <rect x="0" y="${y - gap / 2}" width="${VIEW_W}" height="${barHeight + gap}" class="stats-hit"></rect>
          <text x="${labelWidth - 10}" y="${y + barHeight / 2 + 5}" text-anchor="end" class="stats-chart-label">${escapeHtml(truncate(row.team, labelChars))}</text>
          <rect x="${labelWidth}" y="${y}" width="${barAreaWidth}" height="${barHeight}" rx="5" class="stats-chart-track"></rect>
          <rect x="${labelWidth}" y="${y}" width="${drawnW}" height="${barHeight}" rx="5" class="stats-chart-bar${medalClass(i)}"></rect>
          <text x="${labelWidth + drawnW + 8}" y="${y + barHeight / 2 + 5}" class="stats-chart-value">${fmtNum(value)}</text>
        </g>`;
    });

    return `<svg viewBox="0 0 ${VIEW_W} ${chartHeight}" class="stats-chart${compact ? " stats-chart-compact" : ""}" role="group"
        aria-label="${escapeHtml(t("addon.stats.chart_aria_bar", "Leaderboard bar chart"))}">${grid}${bars}</svg>`;
  }

  function barTooltipHtml(row, i, rows, metric) {
    const leader = rows[0][metric] || 0;
    // floor, not round: 3160 vs 3175 is 99%, and must not read as a tie with the leader.
    const pct = leader > 0 ? Math.floor(((row[metric] || 0) / leader) * 100) : 0;
    const last = row.last_solve ? formatFull(Date.parse(row.last_solve + (/[zZ]|[+-]\d\d:?\d\d$/.test(row.last_solve) ? "" : "Z"))) : null;
    return `
      <div class="stats-tip-title">${escapeHtml(t("addon.stats.tooltip_rank", "Rank #{rank}", { rank: i + 1 }))} · ${escapeHtml(row.team)}</div>
      <div class="stats-tip-row"><span>${escapeHtml(t("addon.stats.metric_score", "Score"))}</span><b>${fmtNum(row.score)}</b></div>
      <div class="stats-tip-row"><span>${escapeHtml(t("addon.stats.metric_solves", "Solves"))}</span><b>${fmtNum(row.solves)}</b></div>
      ${i > 0 ? `<div class="stats-tip-note">${escapeHtml(t("addon.stats.tooltip_pct_leader", "{pct}% of the leader", { pct }))}</div>` : ""}
      ${last ? `<div class="stats-tip-note">${escapeHtml(t("addon.stats.tooltip_last_solve", "Last solve: {time}", { time: last }))}</div>` : ""}`;
  }

  function attachBarInteractions(wrap, rows, metric) {
    wrap.querySelectorAll(".stats-row").forEach((g) => {
      const row = rows[Number(g.dataset.index)];
      const i = Number(g.dataset.index);
      const html = barTooltipHtml(row, i, rows, metric);
      g.addEventListener("pointerenter", (e) => showTooltip(wrap, html, e.clientX, e.clientY));
      g.addEventListener("pointermove", (e) => showTooltip(wrap, html, e.clientX, e.clientY));
      g.addEventListener("pointerleave", () => hideTooltip(wrap));
      g.addEventListener("focus", () => {
        const r = g.getBoundingClientRect();
        showTooltip(wrap, html, r.left + Math.min(r.width, 220), r.top + r.height / 2);
      });
      g.addEventListener("blur", () => hideTooltip(wrap));
    });
  }

  // --- Time charts (line / area): score or solves over time ------------------------

  /** Running totals per team: [{team, index, pts:[{t,total,points,challenge}], final}] */
  function buildSeries(timeline, metric) {
    return timeline.series.map((s, index) => {
      let total = 0;
      const pts = s.events.map((e) => {
        total += metric === "solves" ? 1 : e.points;
        return { t: Date.parse(e.t), total, points: e.points, challenge: e.challenge };
      });
      return { team: s.team, index, pts, final: total };
    });
  }

  const valueAt = (series, time) => {
    let v = 0;
    for (const p of series.pts) {
      if (p.t <= time) v = p.total;
      else break;
    }
    return v;
  };

  function buildTimeChart(series, timeline, metric, type, compact) {
    const visible = series.filter((s) => !hiddenTeams.has(s.team));
    const allTimes = series.flatMap((s) => s.pts.map((p) => p.t));
    if (!allTimes.length) return null;

    const nowMs = Date.parse(timeline.now) || Date.now();
    const windowMs = RANGES[currentRange] || 0;
    let t0;
    let last;
    if (windowMs) {
      // A fixed trailing window; totals earned before it carry in as the starting level.
      last = nowMs;
      t0 = nowMs - windowMs;
    } else {
      const first = Math.min(...allTimes);
      last = Math.max(nowMs, ...allTimes);
      t0 = first - Math.max((last - first) * 0.04, 2 * 60 * 1000);
      if (last - t0 < 10 * 60 * 1000) last = t0 + 10 * 60 * 1000;
    }
    const span = last - t0;

    const height = compact ? 270 : 340;
    const leftPad = compact ? 40 : 50;
    const rightPad = 16;
    const topPad = 16;
    const bottomPad = 30;
    const plotW = VIEW_W - leftPad - rightPad;
    const plotH = height - topPad - bottomPad;
    const baseline = topPad + plotH;

    const maxVal = Math.max(1, ...visible.map((s) => s.final));
    const scale = niceScale(maxVal, compact ? 4 : 5);
    const X = (ms) => leftPad + ((ms - t0) / span) * plotW;
    const Y = (v) => baseline - (v / scale.top) * plotH;

    let grid = "";
    scale.ticks.forEach((v) => {
      grid += `<line x1="${leftPad}" y1="${Y(v)}" x2="${VIEW_W - rightPad}" y2="${Y(v)}" class="stats-chart-grid"></line>
        <text x="${leftPad - 8}" y="${Y(v) + 4}" text-anchor="end" class="stats-chart-label stats-axis-label">${fmtNum(v)}</text>`;
    });
    const xTicks = compact ? 3 : 5;
    for (let i = 0; i <= xTicks; i++) {
      const ms = t0 + (span * i) / xTicks;
      const anchor = i === 0 ? "start" : i === xTicks ? "end" : "middle";
      grid += `<line x1="${X(ms)}" y1="${baseline}" x2="${X(ms)}" y2="${baseline + 4}" class="stats-chart-tick"></line>
        <text x="${X(ms)}" y="${baseline + 18}" text-anchor="${anchor}" class="stats-chart-label stats-axis-label">${escapeHtml(formatTick(ms, span))}</text>`;
    }

    // Paint the leader last so it ends up on top.
    let paths = "";
    visible.slice().reverse().forEach((s) => {
      const inWindow = s.pts.filter((p) => p.t > t0 && p.t <= last);
      let d = `M${X(t0)},${Y(valueAt(s, t0))}`;
      inWindow.forEach((p) => { d += ` H${X(p.t)} V${Y(p.total)}`; });
      d += ` H${X(last)}`;
      const cls = `stats-series stats-s${s.index % PALETTE_SIZE}`;
      if (type === "area") paths += `<path d="${d} V${baseline} H${X(t0)} Z" class="${cls} stats-chart-area" data-series="${s.index}"></path>`;
      paths += `<path d="${d}" class="${cls} stats-chart-line" data-series="${s.index}"></path>`;
      inWindow.forEach((p) => {
        paths += `<circle cx="${X(p.t)}" cy="${Y(p.total)}" r="${compact ? 3 : 3.5}" class="${cls} stats-chart-dot" data-series="${s.index}"></circle>`;
      });
    });

    const ariaKey = type === "area" ? "addon.stats.chart_aria_area" : "addon.stats.chart_aria_line";
    const ariaDefault = type === "area" ? "Progress over time, area chart" : "Progress over time, line chart";
    const svg = `<svg viewBox="0 0 ${VIEW_W} ${height}" class="stats-chart stats-time-chart${compact ? " stats-chart-compact" : ""}"
        role="group" tabindex="0" aria-label="${escapeHtml(t(ariaKey, ariaDefault))}">
        ${grid}
        <line x1="${leftPad}" y1="${baseline}" x2="${VIEW_W - rightPad}" y2="${baseline}" class="stats-chart-axis"></line>
        ${paths}
        <line class="stats-guide" x1="0" y1="${topPad}" x2="0" y2="${baseline}" visibility="hidden"></line>
        <g class="stats-markers"></g>
      </svg>`;

    return { svg, ctx: { visible, X, Y, topPad, baseline, leftPad, plotW, rightPad, span, t0, last, metric } };
  }

  function timeTooltipHtml(visible, ms, metric) {
    const lines = visible
      .map((s) => ({ s, v: valueAt(s, ms), ev: s.pts.find((p) => p.t === ms) }))
      .sort((a, b) => b.v - a.v);
    const shown = lines.slice(0, 8);
    const rows = shown.map(({ s, v, ev }) => `
      <div class="stats-tip-row">
        <span><i class="stats-swatch stats-s${s.index % PALETTE_SIZE}"></i>${escapeHtml(truncate(s.team, 22))}</span><b>${fmtNum(v)}</b>
      </div>
      ${ev ? `<div class="stats-tip-note">${escapeHtml(t("addon.stats.tooltip_solved", "+{points} pts · {challenge}", { points: ev.points, challenge: ev.challenge }))}</div>` : ""}`).join("");
    const more = lines.length > shown.length ? `<div class="stats-tip-note">+${lines.length - shown.length}…</div>` : "";
    return `<div class="stats-tip-title">${escapeHtml(formatFull(ms))} <small>(${escapeHtml(metricLabel(metric).toLowerCase())})</small></div>${rows}${more}`;
  }

  function attachTimeInteractions(wrap, ctx) {
    const svg = wrap.querySelector(".stats-time-chart");
    if (!svg) return;
    const { visible, X, Y, metric } = ctx;
    const guide = svg.querySelector(".stats-guide");
    const markers = svg.querySelector(".stats-markers");
    const times = Array.from(new Set(
      visible.flatMap((s) => s.pts.filter((p) => p.t > ctx.t0 && p.t <= ctx.last).map((p) => p.t)),
    )).sort((a, b) => a - b);
    let keyIndex = times.length - 1;

    function showAt(ms, clientX, clientY) {
      guide.setAttribute("x1", X(ms));
      guide.setAttribute("x2", X(ms));
      guide.setAttribute("visibility", "visible");
      markers.innerHTML = visible
        .map((s) => `<circle cx="${X(ms)}" cy="${Y(valueAt(s, ms))}" r="5" class="stats-series stats-s${s.index % PALETTE_SIZE} stats-marker"></circle>`)
        .join("");
      showTooltip(wrap, timeTooltipHtml(visible, ms, metric), clientX, clientY);
    }

    function hide() {
      guide.setAttribute("visibility", "hidden");
      markers.innerHTML = "";
      hideTooltip(wrap);
    }

    function nearestTime(clientX) {
      const rect = svg.getBoundingClientRect();
      const vx = ((clientX - rect.left) / rect.width) * VIEW_W;
      let best = null;
      let bestDist = Infinity;
      for (const ms of times) {
        const dist = Math.abs(X(ms) - vx);
        if (dist < bestDist) { best = ms; bestDist = dist; }
      }
      return best;
    }

    // No solves inside the visible window (e.g. "last hour" on a quiet board):
    // there's nothing to snap to, so report each team's level at the cursor's time.
    const timeAtCursor = (clientX) => {
      const rect = svg.getBoundingClientRect();
      const vx = ((clientX - rect.left) / rect.width) * VIEW_W;
      const fraction = Math.min(1, Math.max(0, (vx - ctx.leftPad) / ctx.plotW));
      return Math.round(ctx.t0 + fraction * ctx.span);
    };

    const onPointer = (e) => {
      const ms = times.length ? nearestTime(e.clientX) : timeAtCursor(e.clientX);
      if (ms === null) return;
      keyIndex = times.indexOf(ms);
      showAt(ms, e.clientX, e.clientY);
    };
    svg.addEventListener("pointerenter", onPointer);
    svg.addEventListener("pointermove", onPointer);
    svg.addEventListener("pointerdown", onPointer);
    svg.addEventListener("pointerleave", hide);
    svg.addEventListener("blur", hide);
    svg.addEventListener("keydown", (e) => {
      if (!times.length) return;
      if (e.key === "ArrowLeft") keyIndex = Math.max(0, keyIndex - 1);
      else if (e.key === "ArrowRight") keyIndex = Math.min(times.length - 1, keyIndex + 1);
      else if (e.key === "Home") keyIndex = 0;
      else if (e.key === "End") keyIndex = times.length - 1;
      else if (e.key === "Escape") { hide(); return; }
      else return;
      e.preventDefault();
      const r = svg.getBoundingClientRect();
      const px = r.left + (X(times[keyIndex]) / VIEW_W) * r.width;
      showAt(times[keyIndex], px, r.top + r.height * 0.25);
    });
  }

  // --- Legend (line / area) ------------------------------------------------------

  function renderLegend(container, series) {
    const el = container.querySelector("#stats-legend");
    if (!el) return;
    if (!series || currentChartType === "bar") {
      el.innerHTML = "";
      el.hidden = true;
      return;
    }
    el.hidden = false;
    el.setAttribute("aria-label", t("addon.stats.legend_label", "Teams (click to show or hide)"));
    el.innerHTML = series.map((s) => `
      <button type="button" class="stats-legend-item${hiddenTeams.has(s.team) ? " off" : ""}" data-team="${escapeHtml(s.team)}" data-series="${s.index}"
        aria-pressed="${hiddenTeams.has(s.team) ? "false" : "true"}" title="${escapeHtml(s.team)}">
        <i class="stats-swatch stats-s${s.index % PALETTE_SIZE}"></i>${escapeHtml(truncate(s.team, 18))}
      </button>`).join("");
    el.querySelectorAll(".stats-legend-item").forEach((btn) => {
      btn.addEventListener("click", () => {
        const team = btn.dataset.team;
        if (hiddenTeams.has(team)) hiddenTeams.delete(team);
        else hiddenTeams.add(team);
        renderLegend(container, series);
        renderChartOnly(container);
      });
      // Hover a legend entry to spotlight that team's line.
      btn.addEventListener("pointerenter", () => spotlight(container, btn.dataset.series));
      btn.addEventListener("pointerleave", () => spotlight(container, null));
      btn.addEventListener("focus", () => spotlight(container, btn.dataset.series));
      btn.addEventListener("blur", () => spotlight(container, null));
    });
  }

  function spotlight(container, seriesIndex) {
    const svg = container.querySelector(".stats-time-chart");
    if (!svg) return;
    svg.classList.toggle("stats-dim", seriesIndex !== null);
    svg.querySelectorAll("[data-series]").forEach((node) => {
      node.classList.toggle("stats-spot", seriesIndex !== null && node.dataset.series === String(seriesIndex));
    });
  }

  // --- Render -------------------------------------------------------------------

  function setChart(wrap, html) {
    wrap.querySelector(".stats-chart-host").innerHTML = html;
    hideTooltip(wrap);
  }

  function emptyHtml(key, fallback) {
    return `<p class="stats-empty" data-i18n="${key}">${escapeHtml(t(key, fallback))}</p>`;
  }

  function renderChartOnly(container) {
    const wrap = container.querySelector("#stats-chart-wrap");
    if (!wrap || !lastBoard) return;
    if (!lastBoard.length) {
      renderLegend(container, null);
      setChart(wrap, emptyHtml("addon.stats.empty", "No teams on the board yet."));
      return;
    }

    if (currentChartType === "bar") {
      renderLegend(container, null);
      const rows = rankedRows(lastBoard, currentMetric);
      setChart(wrap, buildBarChart(rows, currentMetric, currentCompact));
      attachBarInteractions(wrap, rows, currentMetric);
      return;
    }

    if (!lastTimeline) return; // still loading
    const series = buildSeries(lastTimeline, currentMetric);
    renderLegend(container, series);
    const built = buildTimeChart(series, lastTimeline, currentMetric, currentChartType, currentCompact);
    if (!built) {
      setChart(wrap, emptyHtml("addon.stats.empty_timeline", "No solves yet - the chart appears after the first flag is captured."));
      return;
    }
    setChart(wrap, built.svg);
    attachTimeInteractions(wrap, built.ctx);
  }

  async function loadTimeline(force) {
    if (!force && lastTimeline && Date.now() - timelineLoadedAt < 15000) return;
    lastTimeline = await window.OpenCTF.api(`/api/scoreboard/timeline?limit=${Math.min(25, maxTeams())}`);
    timelineLoadedAt = Date.now();
  }

  async function refresh(container, { forceTimeline = false } = {}) {
    const wrap = container.querySelector("#stats-chart-wrap");
    if (!wrap) return;
    if (!lastBoard) setChart(wrap, `<p class="field-note">${escapeHtml(t("common.loading", "Loading..."))}</p>`);
    try {
      lastBoard = await window.OpenCTF.api("/api/scoreboard");
      if (currentChartType !== "bar") await loadTimeline(forceTimeline);
    } catch (err) {
      setChart(wrap, `<p class="form-error">${escapeHtml(err.message)}</p>`);
      return;
    }
    renderChartOnly(container);

    const summary = container.querySelector("#stats-summary");
    if (summary && lastBoard.length) {
      const leader = rankedRows(lastBoard, currentMetric)[0];
      summary.textContent = t("addon.stats.summary", "{count} teams · leading: {team} ({value} {metric})", {
        count: lastBoard.length,
        team: leader.team,
        value: leader[currentMetric] || 0,
        metric: metricLabel(currentMetric).toLowerCase(),
      });
    } else if (summary) {
      summary.textContent = "";
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
        <div class="stats-range-toggle" id="stats-range" role="group" aria-label="${escapeHtml(t("addon.stats.range_group_label", "Time range"))}" hidden>
          ${Object.keys(RANGES).map((key) => `<button type="button" class="stats-range-btn" data-range="${key}">${escapeHtml(key === "all" ? t("addon.stats.range_all", "All") : key.replace("h", " h"))}</button>`).join("")}
        </div>
        <div class="stats-chart-type-toggle" role="group" aria-label="${escapeHtml(t("addon.stats.chart_type_group_label", "Chart type"))}">
          <button type="button" class="stats-chart-type-btn" data-chart-type="bar" data-i18n="addon.stats.chart_bar">${t("addon.stats.chart_bar", "Bar")}</button>
          <button type="button" class="stats-chart-type-btn" data-chart-type="line" data-i18n="addon.stats.chart_line">${t("addon.stats.chart_line", "Line")}</button>
          <button type="button" class="stats-chart-type-btn" data-chart-type="area" data-i18n="addon.stats.chart_area">${t("addon.stats.chart_area", "Area")}</button>
        </div>
        <span class="field-note" id="stats-summary"></span>
      </div>
      <div class="stats-legend" id="stats-legend" role="group" hidden></div>
      <div id="stats-chart-wrap" class="stats-chart-wrap">
        <div class="stats-chart-host"></div>
        <div class="stats-tooltip" role="tooltip" hidden></div>
      </div>
    `;

    function updateActiveButtons() {
      container.querySelectorAll(".stats-metric-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.metric === currentMetric);
      });
      container.querySelectorAll(".stats-chart-type-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.chartType === currentChartType);
      });
      container.querySelectorAll(".stats-range-btn").forEach((btn) => {
        btn.classList.toggle("active", btn.dataset.range === currentRange);
      });
      container.querySelector("#stats-range").hidden = currentChartType === "bar";
    }
    container.querySelectorAll(".stats-range-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        currentRange = btn.dataset.range;
        updateActiveButtons();
        renderChartOnly(container);
      });
    });
    container.querySelectorAll(".stats-metric-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        currentMetric = btn.dataset.metric;
        updateActiveButtons();
        refresh(container);
      });
    });
    container.querySelectorAll(".stats-chart-type-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        currentChartType = btn.dataset.chartType;
        updateActiveButtons();
        refresh(container);
      });
    });
    updateActiveButtons();

    const wrap = container.querySelector("#stats-chart-wrap");
    currentCompact = wrap.clientWidth > 0 && wrap.clientWidth < COMPACT_BREAKPOINT;
    watchResize(container);

    refresh(container, { forceTimeline: true });
  }

  // Best-effort live refresh: fires right after this player's own correct
  // submission (see docs/ADDON_DEVELOPMENT.md's event table).
  window.OpenCTF.on("challenge:solved", () => {
    if (currentContainer && currentContainer.isConnected) refresh(currentContainer, { forceTimeline: true });
  });

  window.OpenCTF.on("language:changed", () => {
    if (!currentContainer || !currentContainer.isConnected) return;
    const metricGroup = currentContainer.querySelector(".stats-metric-toggle");
    const chartGroup = currentContainer.querySelector(".stats-chart-type-toggle");
    if (metricGroup) metricGroup.setAttribute("aria-label", t("addon.stats.metric_group_label", "Metric"));
    if (chartGroup) chartGroup.setAttribute("aria-label", t("addon.stats.chart_type_group_label", "Chart type"));
    const rangeGroup = currentContainer.querySelector("#stats-range");
    if (rangeGroup) rangeGroup.setAttribute("aria-label", t("addon.stats.range_group_label", "Time range"));
    const allBtn = currentContainer.querySelector('[data-range="all"]');
    if (allBtn) allBtn.textContent = t("addon.stats.range_all", "All");
    if (!currentContainer.classList.contains("hidden")) refresh(currentContainer);
  });

  window.OpenCTF.on("ready", loadConfig);
  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id !== ADDON_ID) return;
    CONFIG = { ...FALLBACK_CONFIG, ...config };
    applyConfigDefaults();
    lastTimeline = null;
    if (currentContainer && currentContainer.isConnected) refresh(currentContainer, { forceTimeline: true });
  });

  window.OpenCTF.registerView({
    id: ADDON_ID,
    label: "Stats",
    labelKey: "addon.stats.nav_label",
    render,
  });
})();
