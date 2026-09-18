let SERVER_URL = "";
let TOKEN = null;
let ME = { username: null, team: null, is_admin: false, display_name: null, bio: "", avatar: "🛡️" };
let CHALLENGES = [];
let CHALLENGE_SEARCH = "";
let ACTIVE_CHALLENGE = null;

// ---- Minimal MD5 (RFC 1321), used only for a live flag preview in the
// admin challenge builder. Matches Python's hashlib.md5(s.encode("utf-8"))
// exactly - the server is still the source of truth for what actually gets
// saved, this is purely so the admin can see the flag before saving.
function md5(input) {
  function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }
  function toHex(bytes) {
    let hex = "";
    for (const b of bytes) hex += b.toString(16).padStart(2, "0");
    return hex;
  }
  const K = new Uint32Array([
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
  ]);
  const S = [
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
  ];
  const msg = new TextEncoder().encode(input);
  const bitLen = msg.length * 8;
  const padLen = ((msg.length % 64) < 56) ? (56 - (msg.length % 64)) : (120 - (msg.length % 64));
  const padded = new Uint8Array(msg.length + padLen + 8);
  padded.set(msg);
  padded[msg.length] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bitLen >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let chunkStart = 0; chunkStart < padded.length; chunkStart += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(chunkStart + i * 4, true);
    let [A, B, C, D] = [a0, b0, c0, d0];
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, S[i])) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, a0, true); outView.setUint32(4, b0, true);
  outView.setUint32(8, c0, true); outView.setUint32(12, d0, true);
  return toHex(out);
}

const FLAG_PREFIX = "OCTF";
function flagPreviewFor(answer) {
  const trimmed = (answer || "").trim();
  if (!trimmed) return "";
  return `${FLAG_PREFIX}{${md5(trimmed)}}`;
}

// terminal state for the currently open terminal challenge
let TERMINAL_CWD = "/";
let TERMINAL_CHALLENGE = null;
let AI_CHALLENGE = null;
let AI_MESSAGES = [];
let AI_RECOGNITION = null;
let TARGET_HISTORY = [];
let TARGET_HISTORY_INDEX = -1;
let TARGET_NAVIGATING = false;

// admin state
let ADMIN_CHALLENGES = [];
let ADMIN_USERS = [];
let ADMIN_TEAMS = [];
let ADMIN_ADDONS = [];
let ADMIN_THEMES = [];
let OLLAMA_MODELS = [];
let OLLAMA_DEFAULT_MODEL = null;
let EDITING_CHALLENGE_ID = null;

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// Every flag-submission form across the four challenge-modal types, so a
// stale flag (correct or not, from whatever was last typed/submitted)
// never lingers into the next time any of these modals is opened.
const FLAG_INPUT_SELECTORS = ["#flag-input", "#ai-flag-input", "#quiz-flag-input", "#terminal-flag-input"];

function clearAllFlagInputs() {
  FLAG_INPUT_SELECTORS.forEach((sel) => {
    const el = $(sel);
    if (el) el.value = "";
  });
}

/** Hide a challenge modal and reset every flag input, not just the one
 * that modal itself owns - belt-and-suspenders so reopening any challenge
 * modal, of any type, never shows a leftover flag from a previous one. */
function closeChallengeModal(modalSelector) {
  $(modalSelector).classList.add("hidden");
  clearAllFlagInputs();
}

/** Views an addon has added via window.OpenCTF.registerView() - see
 * below. Keyed by id, same id used for the nav button's data-view (or
 * admin-tab-btn's data-admin-tab, for an "admin" location) and the view
 * container's id, same convention the built-in views
 * (challenges/scoreboard/profile/admin) already follow. Each entry also
 * tracks what it takes for the entry point (nav button / admin tab
 * button) to actually be visible right now - see updateViewVisibility(). */
const REGISTERED_VIEWS = {};

/** Whether `user` (as OpenCTF.getUser() returns it, or null when logged
 * out) is allowed to see a view/tab registered with this `target`:
 *   - "everyone" (default) or a falsy value - anyone logged in
 *   - "admin" - only admins
 *   - a function (user) => boolean - full custom logic
 *   - an array of usernames - only those specific people
 *   - { usernames: [...] } and/or { teams: [...] } - specific people and/or specific teams
 */
function viewTargetAllows(target, user) {
  if (!target || target === "everyone") return true;
  if (target === "admin") return !!(user && user.is_admin);
  if (typeof target === "function") {
    try {
      return !!target(user);
    } catch (err) {
      console.error("[OpenCTF addon] registerView target function threw:", err);
      return false;
    }
  }
  if (Array.isArray(target)) return !!(user && target.includes(user.username));
  if (typeof target === "object") {
    if (user && Array.isArray(target.usernames) && target.usernames.includes(user.username)) return true;
    if (user && Array.isArray(target.teams) && target.teams.includes(user.team)) return true;
    return false;
  }
  return true;
}

/** Shows/hides a registered view's entry point (nav button, admin tab
 * button, or - for a "header"/"footer" chrome item, which has no button -
 * its container directly) based on both its own target audience and
 * whether the addon that registered it is currently enabled - called on
 * registration, on login (a different user may now be looking at it), and
 * whenever the owning addon is toggled live (see handleLiveEvent's
 * "addon_toggled"). */
function updateViewVisibility(id) {
  const registered = REGISTERED_VIEWS[id];
  const toggleTarget = registered && (registered.button || registered.container);
  if (!toggleTarget) return;
  const allowed = registered.enabled !== false && viewTargetAllows(registered.target, ME);
  toggleTarget.classList.toggle("hidden", !allowed);
  if (!allowed && registered.button && registered.button.classList.contains("active")) {
    // Currently showing the thing we just hid - don't strand the person
    // on a blank/inaccessible pane. Not applicable to "chrome" kind (no
    // button, nothing being "shown" in the tab sense).
    if (registered.kind === "admin-tab") switchAdminTab("challenges");
    else if (registered.kind === "sidebar") switchToView("challenges");
  }
}

/** Re-checks every registered view's visibility - called after login,
 * since a view's `target` is evaluated against whoever's currently logged
 * in, and an addon may have registered its view before that was known. */
function refreshAllViewVisibility() {
  Object.keys(REGISTERED_VIEWS).forEach(updateViewVisibility);
}

function switchToView(view) {
  $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $$(".view").forEach((v) => v.classList.add("hidden"));
  const viewEl = $(`#view-${view}`);
  if (!viewEl) return;
  viewEl.classList.remove("hidden");
  if (view === "scoreboard") loadScoreboard();
  if (view === "profile") loadProfileForm();
  if (view === "admin") loadAdmin();
  const registered = REGISTERED_VIEWS[view];
  if (registered && registered.kind !== "admin-tab") {
    try {
      registered.render(viewEl);
    } catch (err) {
      console.error(`[OpenCTF addon] view "${view}" render threw:`, err);
    }
  }
  octfEmit("view:change", view);
}

function switchAdminTab(tab) {
  $$(".admin-tab-btn").forEach((b) => b.classList.toggle("active", b.dataset.adminTab === tab));
  $$(".admin-tab").forEach((t) => t.classList.add("hidden"));
  const paneEl = $(`#admin-tab-${tab}`);
  if (!paneEl) return;
  paneEl.classList.remove("hidden");
  const registered = REGISTERED_VIEWS[tab];
  if (registered && registered.kind === "admin-tab") {
    try {
      registered.render(paneEl);
    } catch (err) {
      console.error(`[OpenCTF addon] admin tab "${tab}" render threw:`, err);
    }
  }
}

async function api(path, options = {}) {
  const res = await fetch(SERVER_URL + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
      ...(options.headers || {}),
    },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

// ---------------------------------------------------------------------------
// Addon API
//
// The public surface addon scripts (server/addons/*/addon.js) get to work
// with. Kept intentionally small: a way to call the same API the app
// itself uses, a read-only look at the current user, and an event bus for
// the handful of moments an addon is likely to care about. Addon scripts
// are plain <script> tags with full DOM access regardless of what's on
// this object - it's a convenience API, not a sandbox. See
// docs/ADDON_DEVELOPMENT.md for the full reference and event list.
// ---------------------------------------------------------------------------
const OCTF_EVENT_HANDLERS = {};
// Addon ids whose entry script has already been injected into the page -
// used both at startup and by the live-updates handler below, so an
// addon_toggled event for something already loaded doesn't double-inject.
const LOADED_ADDON_IDS = new Set();
let LIVE_CONNECTED = false;

// "ready" and the live-updates connection state are "sticky" - an addon's
// own <script> is fetched asynchronously and can easily finish loading
// (and call OpenCTF.on(...)) *after* the real thing already happened, so a
// plain fire-once emitter would silently strand it. For just these events,
// on() replays the current state to a handler that subscribes late, one
// microtask later (so it behaves like a normal async callback, not a
// synchronous call from inside on() itself).
let OCTF_READY_FIRED = false;
let OCTF_LIVE_STATUS_KNOWN = false;

function octfEmit(event, detail) {
  if (event === "ready") OCTF_READY_FIRED = true;
  if (event === "live:connected" || event === "live:disconnected") OCTF_LIVE_STATUS_KNOWN = true;
  (OCTF_EVENT_HANDLERS[event] || []).forEach((handler) => {
    try {
      handler(detail);
    } catch (err) {
      // An addon's own bug should never be able to break the host app.
      console.error(`[OpenCTF addon] "${event}" handler threw:`, err);
    }
  });
}

window.OpenCTF = {
  /** Same authenticated fetch helper the app itself uses. */
  api,
  /** The logged-in user, or null if nobody's logged in yet. */
  getUser() {
    return ME.username ? { ...ME } : null;
  },
  /**
   * Subscribe to a platform event. Events fired: "ready" (once, after the
   * app has loaded site config and rendered its first screen),
   * "auth:login", "auth:logout", "view:change" (detail: view name),
   * "challenge:solved" (detail: {id, title, category, points}),
   * "challenge:wrong" (detail: {id, title, category}), "live:connected" /
   * "live:disconnected" (the /api/events connection), "site:theme_changed"
   * (detail: {active_theme, theme_entry}), "addon:enabled" / "addon:disabled"
   * (detail: {id, name}), and "addon:config_changed" (detail: {id, config})
   * whenever an admin saves that addon's config, from any client.
   *
   * "ready" and "live:connected"/"live:disconnected" are replayed to a
   * handler registered after they already fired, so an addon doesn't need
   * to race its own script's load time against the app's startup.
   */
  on(event, handler) {
    (OCTF_EVENT_HANDLERS[event] = OCTF_EVENT_HANDLERS[event] || []).push(handler);
    if (event === "ready" && OCTF_READY_FIRED) {
      Promise.resolve().then(() => handler());
    } else if ((event === "live:connected" || event === "live:disconnected") && OCTF_LIVE_STATUS_KNOWN) {
      const isCurrentState = (event === "live:connected") === LIVE_CONNECTED;
      if (isCurrentState) Promise.resolve().then(() => handler());
    }
  },
  off(event, handler) {
    if (!OCTF_EVENT_HANDLERS[event]) return;
    OCTF_EVENT_HANDLERS[event] = OCTF_EVENT_HANDLERS[event].filter((h) => h !== handler);
  },
  /** Whether the live-updates (/api/events) connection is currently up. */
  isLive() {
    return LIVE_CONNECTED;
  },
  /**
   * Read another addon's - or your own - current saved config (whatever an
   * admin set via the gear button, merged over its declared defaults).
   * Unauthenticated, same trust boundary as the addon script itself.
   */
  async getAddonConfig(addonId) {
    const res = await fetch(`${SERVER_URL}/api/addons/${addonId}/config`);
    if (!res.ok) throw new Error(`could not load config for "${addonId}" (${res.status})`);
    return res.json();
  },
  /** Fire a platform event locally without a round trip to the server -
   * handy for an addon's own config screen to preview itself (e.g. a
   * "preview" button that fires a fake "challenge:solved"). */
  emitLocal(event, detail) {
    octfEmit(event, detail);
  },
  /**
   * Add a tab and its own full-page/full-pane view - the same kind of
   * view the built-in Challenges/Scoreboard/Profile/Admin tabs are.
   * `render(container)` is called every time the tab is switched to
   * (matching how the built-in views already reload their own data on
   * every visit) - your addon owns everything inside `container` from
   * there on.
   *
   *   window.OpenCTF.registerView({
   *     id: "certifications",       // used as the button's data-view/data-admin-tab and the view element's id
   *     label: "Certifications",    // button text
   *     render(container) { ... },  // called every time this tab is opened
   *     target: "everyone",         // optional - who can see it; see below
   *     location: "sidebar",        // optional - "sidebar" (default) or "admin"
   *   });
   *
   * `location`: "sidebar" (default) adds a top-level nav button and view,
   * alongside Challenges/Scoreboard/etc. "admin" instead adds a tab
   * inside the existing Admin panel's own tab bar (alongside
   * Challenges/Users/Teams/Addons & Themes there) - use this for
   * admin-only tooling that doesn't need its own top-level place in the
   * main sidebar. An "admin" location is only ever reachable by an admin
   * regardless of `target` (the Admin panel itself is admin-only), but
   * `target` still narrows it further if given.
   *
   * `target`: who can see the entry point at all - "everyone" (default,
   * anyone logged in), "admin", a function `(user) => boolean` for
   * arbitrary logic, an array of usernames, or `{ usernames: [...] }`
   * and/or `{ teams: [...] }` for specific people and/or specific teams.
   * `user` is whatever `OpenCTF.getUser()` returns (or `null`). Re-checked
   * on login, so it's safe to register a view before knowing who's
   * logged in yet.
   *
   * The entry point is also automatically hidden while the addon that
   * registered it is disabled, and shown again once it's re-enabled - no
   * extra wiring needed for that (see `"addon:disabled"` elsewhere in
   * this object if your view also needs to react to that itself, e.g. to
   * stop a poll/timer).
   *
   * Returns { button, container } (both real DOM elements) so you can
   * tweak them further (e.g. add an icon), or null if `id` is already
   * taken or `location` isn't recognized - each id can only be
   * registered once, across every enabled addon.
   */
  registerView({ id, label, render, target = "everyone", location = "sidebar" }) {
    const VALID_LOCATIONS = ["sidebar", "admin", "header", "footer"];
    if (!id || !label || typeof render !== "function") {
      console.error('[OpenCTF] registerView requires "id", "label", and a render(container) function');
      return null;
    }
    if (!VALID_LOCATIONS.includes(location)) {
      console.error(`[OpenCTF] registerView "location" must be one of: ${VALID_LOCATIONS.join(", ")}`);
      return null;
    }
    if (REGISTERED_VIEWS[id] || document.getElementById(`view-${id}`) || document.getElementById(`admin-tab-${id}`)) {
      console.error(`[OpenCTF] a view with id "${id}" is already registered`);
      return null;
    }

    let button = null;
    let container;
    let kind;

    if (location === "admin") {
      kind = "admin-tab";
      const adminTabs = document.querySelector(".admin-tabs");
      button = document.createElement("button");
      button.className = "admin-tab-btn";
      button.dataset.adminTab = id;
      button.textContent = label;
      adminTabs.appendChild(button);

      container = document.createElement("div");
      container.id = `admin-tab-${id}`;
      container.className = "admin-tab hidden";
      document.getElementById("view-admin").appendChild(container);
    } else if (location === "header" || location === "footer") {
      // Not a tab - a persistent slot visible across every view, so there's
      // no button and (see below) render() runs once immediately rather
      // than on a "switch" that will never come. Several addons can each
      // add their own item to the same slot - see .addon-chrome-slot in
      // styles.css for the row layout that makes that work.
      kind = "chrome";
      const slot = document.getElementById(location === "header" ? "addon-header-slot" : "addon-footer-slot");
      container = document.createElement("div");
      container.id = `view-${id}`;
      container.className = "addon-chrome-item";
      slot.appendChild(container);
    } else {
      kind = "sidebar";
      button = document.createElement("button");
      button.className = "nav-btn";
      button.dataset.view = id;
      button.textContent = label;
      const spacer = document.querySelector(".sidebar-spacer");
      spacer.parentNode.insertBefore(button, spacer);

      container = document.createElement("div");
      container.id = `view-${id}`;
      container.className = "view hidden";
      document.querySelector(".content").appendChild(container);
    }

    REGISTERED_VIEWS[id] = { render, button, container, target, kind, enabled: true };
    updateViewVisibility(id);

    if (kind === "chrome") {
      try {
        render(container);
      } catch (err) {
        console.error(`[OpenCTF addon] view "${id}" render threw:`, err);
      }
    }

    return button ? { button, container } : { container };
  },
};

function notifySolve(challenge, body) {
  if (!body || !challenge) return;
  if (body.correct) {
    octfEmit("challenge:solved", {
      id: challenge.id,
      title: challenge.title,
      category: challenge.category,
      points: challenge.points,
    });
  } else {
    octfEmit("challenge:wrong", {
      id: challenge.id,
      title: challenge.title,
      category: challenge.category,
    });
  }
}

// ---------------------------------------------------------------------------
// Site config: active theme + enabled addons
//
// Fetched once at startup (unauthenticated - the theme has to apply to the
// login screen too) and applied before wiring up the rest of the app. From
// then on, connectLiveUpdates() below keeps every open client in sync as an
// admin changes the theme, toggles an addon, or saves an addon's config -
// no refresh needed.
// ---------------------------------------------------------------------------

function applyThemeLink(themeId, themeEntry) {
  const existing = document.getElementById("addon-theme-css");
  if (existing) existing.remove();
  if (!themeId || !themeEntry) return;
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.id = "addon-theme-css";
  // Loaded after the base stylesheet in index.html, so its variable
  // overrides win the cascade without needing !important anywhere.
  link.href = `${SERVER_URL}/api/themes/${themeId}/${themeEntry}`;
  document.head.appendChild(link);
}

function injectAddonScript(addon) {
  if (!addon || !addon.id || !addon.entry || LOADED_ADDON_IDS.has(addon.id)) return;
  LOADED_ADDON_IDS.add(addon.id);
  const script = document.createElement("script");
  script.src = `${SERVER_URL}/api/addons/${addon.id}/${addon.entry}`;
  script.defer = true;
  script.onerror = () => console.error(`[OpenCTF] failed to load addon "${addon.id}"`);
  document.body.appendChild(script);
}

async function applySiteExtensions() {
  let config;
  try {
    const res = await fetch(SERVER_URL + "/api/site-config");
    config = await res.json();
  } catch {
    return; // offline / unreachable server - just run with the default look
  }
  if (!config) return;

  applyThemeLink(config.active_theme, config.theme_entry);
  (config.enabled_addons || []).forEach(injectAddonScript);
}

// ---------------------------------------------------------------------------
// Live updates - Server-Sent Events
//
// One long-lived, unauthenticated connection (theme/addon changes have to
// reach the still-logged-out login screen too) that every client keeps
// open. The admin routes that change a theme, toggle an addon, save an
// addon's config, or install one via upload each push a small event here -
// see broadcast_event() in server/app.py.
// ---------------------------------------------------------------------------
function connectLiveUpdates() {
  if (!window.EventSource) return; // ancient runtime - just skip live updates
  const source = new EventSource(SERVER_URL + "/api/events");
  source.onopen = () => {
    LIVE_CONNECTED = true;
    octfEmit("live:connected");
  };
  source.onerror = () => {
    LIVE_CONNECTED = false;
    octfEmit("live:disconnected");
    // EventSource retries the connection on its own (see "retry:" in the
    // server's stream) - nothing else to do here.
  };
  source.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }
    handleLiveEvent(msg.type, msg.data);
  };
}

function handleLiveEvent(type, data) {
  switch (type) {
    case "theme_changed":
      applyThemeLink(data.active_theme, data.theme_entry);
      octfEmit("site:theme_changed", data);
      if (ME.is_admin) loadAdminThemes();
      break;
    case "addon_toggled":
      if (data.enabled) {
        injectAddonScript(data);
        octfEmit("addon:enabled", data);
      } else {
        // Addon scripts aren't unloaded once fetched - a well-behaved
        // addon listens for this and cleans up its own DOM/state (see
        // server/addons/motd-banner/addon.js for an example).
        octfEmit("addon:disabled", data);
      }
      // A view registered with the same id as its owning addon (the
      // convention every shipped example follows) is shown/hidden
      // automatically here - no per-addon wiring needed for that part.
      if (REGISTERED_VIEWS[data.id]) {
        REGISTERED_VIEWS[data.id].enabled = data.enabled;
        updateViewVisibility(data.id);
      }
      if (ME.is_admin) loadAdminAddons();
      break;
    case "addon_config_changed":
      octfEmit("addon:config_changed", data);
      break;
    case "addon_installed":
      if (ME.is_admin) loadAdminAddons();
      break;
    case "addon_deleted":
      // addon_toggled (enabled: false) - broadcast alongside this - already
      // hides any view it registered and refreshes the admin addon list;
      // this case exists so a client that missed/ignored that one (or
      // just wants to react to deletion specifically) still can.
      octfEmit("addon:deleted", data);
      break;
    case "theme_installed":
      if (ME.is_admin) loadAdminThemes();
      break;
    case "theme_deleted":
      if (ME.is_admin) loadAdminThemes();
      break;
    default:
      // Anything else broadcast_event() was called with server-side (e.g.
      // from an addon's own backend routes - see the Certifications addon
      // and its /api/certifications/* routes in server/app.py) is
      // forwarded as-is, so an addon can define and listen for its own
      // event names without the host app needing to know about them
      // ahead of time.
      octfEmit(`server:${type}`, data);
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init() {
  const config = await window.ctfConfig.get();
  SERVER_URL = config.serverUrl;
  $("#settings-url").value = SERVER_URL;
  wireEvents();
  await applySiteExtensions();
  connectLiveUpdates();
  loadRegistrationTeams();
  octfEmit("ready");
}

function wireEvents() {
  // Auth tabs
  $$(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      $("#form-login").classList.toggle("hidden", tab !== "login");
      $("#form-register").classList.toggle("hidden", tab !== "register");
      if (tab === "register") loadRegistrationTeams();
    });
  });

  $("#form-login").addEventListener("submit", onLogin);
  $("#form-register").addEventListener("submit", onRegister);
  $("#logout").addEventListener("click", onLogout);
  wirePasswordToggles();

  // Nav - delegated (not a per-button loop) so a nav button an addon adds
  // later via window.OpenCTF.registerView() works without extra wiring.
  $(".sidebar").addEventListener("click", (e) => {
    const btn = e.target.closest(".nav-btn");
    if (btn) switchToView(btn.dataset.view);
  });

  $("#refresh-challenges").addEventListener("click", loadChallenges);
  $("#challenge-search").addEventListener("input", (e) => {
    CHALLENGE_SEARCH = e.target.value;
    renderChallenges();
  });
  $("#refresh-scoreboard").addEventListener("click", loadScoreboard);

  // Challenge modal (standard)
  $("#modal-close").addEventListener("click", () => closeChallengeModal("#modal-challenge"));
  $("#form-submit-flag").addEventListener("submit", onSubmitFlag);

  // Terminal challenge modal
  $("#terminal-close").addEventListener("click", () => closeChallengeModal("#modal-terminal"));
  $("#form-terminal-cmd").addEventListener("submit", onTerminalCommand);
  $("#form-submit-flag-terminal").addEventListener("submit", onSubmitFlagTerminal);
  $("#ai-close").addEventListener("click", () => closeChallengeModal("#modal-ai"));
  $("#form-ai-chat").addEventListener("submit", onAiChatSubmit);
  $("#form-submit-flag-ai").addEventListener("submit", onSubmitFlagAi);
  $("#ai-mic").addEventListener("click", startAiSpeechInput);

  // Quiz challenge modal
  $("#quiz-close").addEventListener("click", () => closeChallengeModal("#modal-quiz"));
  $("#form-submit-flag-quiz").addEventListener("submit", onSubmitFlagQuiz);

  // Settings modal
  $("#open-settings").addEventListener("click", () => $("#modal-settings").classList.remove("hidden"));
  $("#open-settings-2").addEventListener("click", () => $("#modal-settings").classList.remove("hidden"));
  $("#settings-close").addEventListener("click", () => $("#modal-settings").classList.add("hidden"));
  $("#settings-save").addEventListener("click", onSaveSettings);

  // Profile view
  $("#form-profile").addEventListener("submit", onSaveProfile);
  $("#form-password").addEventListener("submit", onChangePassword);
  $("#reset-progress").addEventListener("click", onResetProgress);
  $$("[data-web-tab]").forEach((btn) => {
    btn.addEventListener("click", () => switchWebTab(btn.dataset.webTab));
  });
  $("#web-back").addEventListener("click", () => postTargetNavigation("back"));
  $("#web-forward").addEventListener("click", () => postTargetNavigation("forward"));
  $("#web-reload").addEventListener("click", () => postTargetNavigation("reload"));
  $("#form-web-address").addEventListener("submit", onTargetAddressSubmit);
  window.addEventListener("message", onTargetMessage);

  // Admin: tab switching - delegated so a tab an addon adds later via
  // window.OpenCTF.registerView({location: "admin"}) works without extra
  // wiring, same reasoning as the main sidebar nav above.
  $(".admin-tabs").addEventListener("click", (e) => {
    const btn = e.target.closest(".admin-tab-btn");
    if (btn) switchAdminTab(btn.dataset.adminTab);
  });

  // Admin: Addons & Themes
  $("#theme-select").addEventListener("change", updateThemeDeleteButtonState);
  $("#theme-save-btn").addEventListener("click", onSaveTheme);
  $("#theme-delete-btn").addEventListener("click", onDeleteTheme);
  $("#addon-config-close").addEventListener("click", () => $("#modal-addon-config").classList.add("hidden"));
  wireUploadDropzone({
    zoneId: "theme-upload-zone", inputId: "theme-upload-input", filenameId: "theme-upload-filename",
    btnId: "theme-upload-btn", resultId: "theme-upload-result", kind: "themes",
  });
  wireUploadDropzone({
    zoneId: "addon-upload-zone", inputId: "addon-upload-input", filenameId: "addon-upload-filename",
    btnId: "addon-upload-btn", resultId: "addon-upload-result", kind: "addons",
  });

  // Admin: challenge form
  $("#new-challenge-btn").addEventListener("click", () => openChallengeForm(null));
  $("#challenge-form-close").addEventListener("click", () => $("#modal-challenge-form").classList.add("hidden"));
  $("#cf-type").addEventListener("change", (e) => {
    $("#cf-terminal-fs-wrap").classList.toggle("hidden", e.target.value !== "terminal");
    $("#cf-web-wrap").classList.toggle("hidden", e.target.value !== "web");
    $("#cf-ai-wrap").classList.toggle("hidden", e.target.value !== "ai");
    $("#cf-quiz-wrap").classList.toggle("hidden", e.target.value !== "quiz");
  });
  $("#cf-preset").addEventListener("change", (e) => applyChallengePreset(e.target.value));
  $("#cf-difficulty").addEventListener("change", updatePointsForDifficulty);
  $("#cf-flag").addEventListener("input", updateFlagPreview);
  $("#cf-generate-flag").addEventListener("click", onGenerateFlag);
  $("#form-challenge").addEventListener("submit", onSaveChallenge);
  $("#cf-delete").addEventListener("click", onDeleteChallenge);

  // Admin: teams
  $("#form-create-team").addEventListener("submit", onCreateTeam);
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

function wirePasswordToggles() {
  $$("[data-toggle-password]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const input = $(`#${btn.dataset.togglePassword}`);
      const showing = input.type === "text";
      input.type = showing ? "password" : "text";
      btn.textContent = showing ? "👁" : "🙈";
      btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    });
  });
}

function resetAuthForms() {
  $("#form-login").reset();
  $("#form-register").reset();
  $("#login-error").textContent = "";
  $("#register-error").textContent = "";
  // Don't leave a password field toggled to plain-text visible for the
  // next person to see this screen.
  $$("[data-toggle-password]").forEach((btn) => {
    const input = $(`#${btn.dataset.togglePassword}`);
    if (input) input.type = "password";
    btn.textContent = "👁";
    btn.setAttribute("aria-label", "Show password");
  });
}

async function onLogin(e) {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    const body = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: $("#login-username").value,
        password: $("#login-password").value,
      }),
    });
    onAuthed(body);
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
}

async function loadRegistrationTeams() {
  const select = $("#reg-team");
  try {
    const teams = await api("/api/teams");
    const options = ['<option value="">Independent (no team)</option>'];
    teams
      .filter((t) => t.name !== "Independent")
      .forEach((t) => options.push(`<option value="${t.id}">${t.name}</option>`));
    select.innerHTML = options.join("");
  } catch {
    // Leave the default "Independent" option in place - registration still
    // works fine (the server falls back to Independent for a blank team_id).
  }
}

async function onRegister(e) {
  e.preventDefault();
  $("#register-error").textContent = "";
  try {
    const body = await api("/api/register", {
      method: "POST",
      body: JSON.stringify({
        username: $("#reg-username").value,
        team_id: $("#reg-team").value || null,
        password: $("#reg-password").value,
      }),
    });
    onAuthed(body);
  } catch (err) {
    $("#register-error").textContent = err.message;
  }
}

async function onAuthed(body) {
  TOKEN = body.token;
  ME = { username: body.username, team: body.team, is_admin: !!body.is_admin };
  resetAuthForms();
  $("#screen-auth").classList.add("hidden");
  $("#screen-main").classList.remove("hidden");
  $("#nav-admin").classList.toggle("hidden", !ME.is_admin);

  // pull full profile (avatar, display name, bio) now that we have a token
  try {
    const profile = await api("/api/me");
    ME = { ...ME, ...profile };
  } catch {
    /* non-fatal - sidebar just shows defaults */
  }
  $("#who-team").textContent = ME.team || "no team";
  $("#who-user").textContent = ME.display_name || ME.username;
  $("#who-avatar").textContent = ME.avatar || "🛡️";

  loadChallenges();
  refreshAllViewVisibility(); // ME is only fully known now - re-check every registered view's target
  octfEmit("auth:login");
}

function onLogout() {
  TOKEN = null;
  ME = { username: null, team: null, is_admin: false, display_name: null, bio: "", avatar: "🛡️" };
  resetAuthForms();
  $$(".tab-btn").forEach((b) => b.classList.remove("active"));
  $('.tab-btn[data-tab="login"]').classList.add("active");
  $("#form-login").classList.remove("hidden");
  $("#form-register").classList.add("hidden");
  $("#nav-admin").classList.add("hidden");
  $("#screen-main").classList.add("hidden");
  $("#screen-auth").classList.remove("hidden");
  // reset to the challenges tab for next login
  $$(".nav-btn").forEach((b) => b.classList.remove("active"));
  $('.nav-btn[data-view="challenges"]').classList.add("active");
  $$(".view").forEach((v) => v.classList.add("hidden"));
  $("#view-challenges").classList.remove("hidden");
  octfEmit("auth:logout");
}

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

async function loadChallenges() {
  const list = $("#challenge-list");
  list.innerHTML = `<p style="color:var(--text-dim)">Loading…</p>`;
  try {
    CHALLENGES = await api("/api/challenges");
    renderChallenges();
  } catch (err) {
    list.innerHTML = `<p class="form-error">${err.message}</p>`;
  }
}

function renderChallenges() {
  const list = $("#challenge-list");
  list.innerHTML = "";

  if (CHALLENGES.length === 0) {
    list.innerHTML = `<p class="empty-state">No challenges yet.</p>`;
    return;
  }

  const query = CHALLENGE_SEARCH.trim().toLowerCase();
  const filtered = query
    ? CHALLENGES.filter((c) => {
        const haystack = `${c.title} ${c.category} ${c.type} ${c.description || ""}`.toLowerCase();
        return haystack.includes(query);
      })
    : CHALLENGES;

  if (filtered.length === 0) {
    list.innerHTML = `<p class="empty-state">No challenges match "${CHALLENGE_SEARCH.trim()}".</p>`;
    return;
  }

  const sections = new Map();
  filtered.forEach((c) => {
    const key = c.category || "misc";
    if (!sections.has(key)) sections.set(key, []);
    sections.get(key).push(c);
  });

  Array.from(sections.keys())
    .sort((a, b) => a.localeCompare(b))
    .forEach((category) => {
      const items = sections.get(category);
      const solvedCount = items.filter((c) => c.solved).length;

      const section = document.createElement("section");
      section.className = "challenge-section";
      section.innerHTML = `
        <div class="challenge-section-header">
          <h3 class="challenge-section-title">${category}</h3>
          <span class="challenge-section-count">${solvedCount}/${items.length} solved</span>
        </div>
      `;
      const grid = document.createElement("div");
      grid.className = "challenge-grid";
      items.forEach((c) => grid.appendChild(buildChallengeCard(c)));
      section.appendChild(grid);
      list.appendChild(section);
    });
}

function buildChallengeCard(c) {
  const card = document.createElement("div");
  card.className = "challenge-card" + (c.solved ? " solved" : "");
  card.innerHTML = `
    <p class="card-category">${c.category}${c.type === "terminal" ? " · &gt;_ interactive" : c.type === "web" ? " · &lt;/&gt; sandbox" : c.type === "ai" ? " · \u{1F5E3}\uFE0F conversation" : c.type === "quiz" ? " · \u2753 quiz" : ""}</p>
    <p class="card-title">${c.title}</p>
    <p class="card-points">${c.points} pts</p>
    ${c.solved ? `<p class="card-solved-tag">✓ solved</p>` : ""}
  `;
  card.addEventListener("click", () => openChallenge(c));
  return card;
}

function openChallenge(c) {
  if (c.type === "terminal") {
    openTerminalChallenge(c);
    return;
  }
  if (c.type === "web") {
    openWebChallenge(c);
    return;
  }
  if (c.type === "ai") {
    openAiChallenge(c);
    return;
  }
  if (c.type === "quiz") {
    openQuizChallenge(c);
    return;
  }
  $("#web-tabs").classList.add("hidden");
  $("#web-site-pane").classList.add("hidden");
  $("#web-brief-pane").classList.remove("hidden");
  ACTIVE_CHALLENGE = c;
  $("#modal-category").textContent = c.category;
  $("#modal-title").textContent = c.title;
  $("#modal-desc").textContent = c.description;
  $("#modal-meta").textContent = `${c.difficulty || "medium"} difficulty`;
    $("#modal-meta").textContent = `${c.difficulty || "medium"} difficulty`;
  $("#modal-rules-wrap").classList.toggle("hidden", !c.rules);
  $("#modal-rules").textContent = c.rules || "";
  $("#modal-result").textContent = "";
  $("#modal-result").className = "modal-result";
  $("#flag-input").value = "";

  const hintWrap = $("#modal-hint-wrap");
  if (c.hint) {
    hintWrap.classList.remove("hidden");
    $("#modal-hint").textContent = c.hint;
  } else {
    hintWrap.classList.add("hidden");
  }

  $("#modal-challenge").classList.remove("hidden");
}

function openAiChallenge(c) {
  AI_CHALLENGE = c;
  AI_MESSAGES = [];
  $("#ai-category").textContent = c.category;
  $("#ai-title").textContent = c.title;
  $("#ai-points").textContent = `${c.points} points`;
    $("#ai-status").textContent = `${c.difficulty || "medium"} conversation`;
  $("#ai-result").textContent = c.description;
  $("#ai-result").className = "modal-result";
  $("#ai-input").value = "";
  $("#ai-flag-input").value = "";
  $("#form-submit-flag-ai").classList.remove("hidden");
  renderAiTranscript();
  $("#modal-ai").classList.remove("hidden");
  $("#ai-input").focus();
}

function renderAiTranscript() {
  const transcript = $("#ai-transcript");
  transcript.innerHTML = AI_MESSAGES.length
    ? AI_MESSAGES.map((message) => `<div class="ai-message ${message.role}"><span>${message.role === "user" ? "You" : "Persona"}</span><p>${escapeHtml(message.content)}</p></div>`).join("")
    : `<p class="ai-empty">The persona is waiting. Try a convincing request, not just a demand.</p>`;
  transcript.scrollTop = transcript.scrollHeight;
}

function escapeHtml(value) {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[character]));
}

async function onAiChatSubmit(event) {
  event.preventDefault();
  const input = $("#ai-input");
  const content = input.value.trim();
  if (!content || !AI_CHALLENGE) return;
  AI_MESSAGES.push({ role: "user", content });
  input.value = "";
  renderAiTranscript();
  $("#ai-result").textContent = "The persona is thinking...";
  try {
    const body = await api(`/api/challenges/${AI_CHALLENGE.id}/ai`, {
      method: "POST",
      body: JSON.stringify({ messages: AI_MESSAGES }),
    });
    AI_MESSAGES.push({ role: "assistant", content: body.reply });
    renderAiTranscript();
    if (body.speak && "speechSynthesis" in window) {
      window.speechSynthesis.cancel();
      const speech = new SpeechSynthesisUtterance(body.reply);
      const voiceConfig = body.voice || {};
      speech.lang = voiceConfig.language || "en-US";
      const voiceStyles = {
        neutral: { pitch: 1, rate: 1 },
        warm: { pitch: 1.08, rate: 0.96 },
        authoritative: { pitch: 0.88, rate: 0.92 },
        calm: { pitch: 0.96, rate: 0.82 },
      };
      const style = voiceStyles[voiceConfig.style] || voiceStyles.neutral;
      speech.pitch = Math.min(2, Math.max(0.5, (Number(voiceConfig.pitch) || 1) * style.pitch));
      speech.rate = Math.min(2, Math.max(0.5, (Number(voiceConfig.rate) || 1) * style.rate));
      const voices = window.speechSynthesis.getVoices();
      const preferredVoice = voices.find((voice) => voice.lang.toLowerCase().startsWith(speech.lang.toLowerCase()));
      if (preferredVoice) speech.voice = preferredVoice;
      window.speechSynthesis.speak(speech);
    }
      if (body.solved && body.flag) {
        $("#ai-result").textContent = `The persona disclosed your team's flag and encoded ID: ${body.flag}`;
      $("#ai-result").className = "modal-result ok";
        $("#ai-flag-input").value = "";
        $("#form-submit-flag-ai").classList.remove("hidden");
    } else {
      $("#ai-result").textContent = "Keep working the conversation.";
    }
  } catch (err) {
    $("#ai-result").textContent = err.message;
    $("#ai-result").className = "modal-result err";
  }
}

async function onSubmitFlagAi(event) {
  event.preventDefault();
  const result = $("#ai-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: AI_CHALLENGE.id,
        flag: $("#ai-flag-input").value,
      }),
    });
    result.textContent = body.correct ? "Correct! Challenge solved." : "Incorrect flag.";
    result.className = `modal-result ${body.correct ? "ok" : "err"}`;
    if (body.correct) await loadChallenges();
    notifySolve(AI_CHALLENGE, body);
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

function startAiSpeechInput() {
  const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!Recognition) {
    $("#ai-result").textContent = "Speech input is not available here. Type your message instead.";
    $("#ai-result").className = "modal-result err";
    return;
  }
  if (AI_RECOGNITION) AI_RECOGNITION.stop();
  AI_RECOGNITION = new Recognition();
  AI_RECOGNITION.lang = "en-US";
  AI_RECOGNITION.interimResults = false;
  AI_RECOGNITION.onresult = (event) => {
    $("#ai-input").value = event.results[0][0].transcript;
    $("#ai-input").focus();
  };
  AI_RECOGNITION.onerror = () => {
    $("#ai-result").textContent = "Microphone input was unavailable. Type your message instead.";
  };
  AI_RECOGNITION.start();
}

let QUIZ_CHALLENGE = null;

function openQuizChallenge(c) {
  QUIZ_CHALLENGE = c;
  $("#quiz-category").textContent = c.category;
  $("#quiz-title").textContent = c.title;
  $("#quiz-points").textContent = `${c.points} points`;
  $("#quiz-desc").textContent = c.description;
  const hintWrap = $("#quiz-hint-wrap");
  if (c.hint) {
    hintWrap.classList.remove("hidden");
    $("#quiz-hint").textContent = c.hint;
  } else {
    hintWrap.classList.add("hidden");
  }
  $("#quiz-question").textContent = c.quiz_question || "";
  $("#quiz-flag-input").value = "";
  $("#form-submit-flag-quiz").classList.add("hidden");
  $("#quiz-result").textContent = c.solved ? "Already solved by your team." : "";
  $("#quiz-result").className = c.solved ? "modal-result ok" : "modal-result";

  const optionsWrap = $("#quiz-options");
  optionsWrap.innerHTML = "";
  (c.quiz_options || []).forEach((optionText, index) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "quiz-option";
    btn.textContent = optionText;
    btn.disabled = !!c.solved;
    btn.addEventListener("click", () => onQuizOptionPicked(index, optionsWrap));
    optionsWrap.appendChild(btn);
  });

  $("#modal-quiz").classList.remove("hidden");
}

async function onQuizOptionPicked(selectedIndex, optionsWrap) {
  const buttons = Array.from(optionsWrap.children);
  buttons.forEach((btn) => (btn.disabled = true));
  const result = $("#quiz-result");
  result.textContent = "Checking...";
  result.className = "modal-result";
  try {
    const body = await api(`/api/challenges/${QUIZ_CHALLENGE.id}/quiz`, {
      method: "POST",
      body: JSON.stringify({ selected_index: selectedIndex }),
    });
    buttons[selectedIndex].classList.add(body.correct ? "correct" : "incorrect");
    if (body.correct && body.flag) {
      result.textContent = "Correct! Submit the flag below to score it.";
      result.className = "modal-result ok";
      $("#quiz-flag-input").value = body.flag;
      $("#form-submit-flag-quiz").classList.remove("hidden");
    } else {
      result.textContent = "Not quite - take another look and try again.";
      result.className = "modal-result err";
      buttons.forEach((btn) => (btn.disabled = false));
    }
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
    buttons.forEach((btn) => (btn.disabled = false));
  }
}

async function onSubmitFlagQuiz(event) {
  event.preventDefault();
  const result = $("#quiz-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: QUIZ_CHALLENGE.id,
        flag: $("#quiz-flag-input").value,
      }),
    });
    result.textContent = body.correct ? "Correct! Challenge solved." : "Incorrect flag.";
    result.className = `modal-result ${body.correct ? "ok" : "err"}`;
    if (body.correct) await loadChallenges();
    notifySolve(QUIZ_CHALLENGE, body);
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

async function onSubmitFlag(e) {
  e.preventDefault();
  const result = $("#modal-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: ACTIVE_CHALLENGE.id,
        flag: $("#flag-input").value,
      }),
    });
    if (body.correct) {
      result.textContent = "Correct! Challenge solved.";
      result.className = "modal-result ok";
      await loadChallenges();
    } else {
      result.textContent = "Incorrect flag, try again.";
      result.className = "modal-result err";
    }
    notifySolve(ACTIVE_CHALLENGE, body);
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

function switchWebTab(tab) {
  const site = tab === "site";
  $("#web-brief-pane").classList.toggle("hidden", site);
  $("#web-site-pane").classList.toggle("hidden", !site);
  $$("[data-web-tab]").forEach((btn) => btn.classList.toggle("active", btn.dataset.webTab === tab));
}

async function openWebChallenge(c) {
  ACTIVE_CHALLENGE = c;
  $("#modal-category").textContent = c.category;
  $("#modal-title").textContent = c.title;
  $("#modal-desc").textContent = c.description;
  $("#modal-meta").textContent = `${c.difficulty || "medium"} difficulty`;
  $("#modal-points").textContent = `${c.points} points`;
  $("#modal-rules-wrap").classList.toggle("hidden", !c.rules);
  $("#modal-rules").textContent = c.rules || "";
  $("#web-tabs").classList.remove("hidden");
  switchWebTab("brief");
  $("#modal-result").textContent = "";
  $("#modal-result").className = "modal-result";
  $("#flag-input").value = "";
  const hintWrap = $("#modal-hint-wrap");
  hintWrap.classList.toggle("hidden", !c.hint);
  if (c.hint) $("#modal-hint").textContent = c.hint;
  $("#modal-challenge").classList.remove("hidden");
  const targetUrl = c.target_url || `${SERVER_URL.replace(/:\d+$/, ":5001")}/target/${c.id}/`;
  const freshTargetUrl = new URL(targetUrl);
  freshTargetUrl.searchParams.set("_ctf_refresh", Date.now().toString());
  TARGET_HISTORY = [new URL(targetUrl).pathname];
  TARGET_HISTORY_INDEX = 0;
  TARGET_NAVIGATING = true;
  $("#web-address").value = TARGET_HISTORY[0];
  $("#web-target-frame").src = freshTargetUrl.toString();
}

function postTargetNavigation(action) {
  if (action === "reload") {
    $("#web-target-frame").contentWindow?.location.reload();
    return;
  }
  const nextIndex = TARGET_HISTORY_INDEX + (action === "back" ? -1 : 1);
  if (nextIndex < 0 || nextIndex >= TARGET_HISTORY.length) return;
  TARGET_HISTORY_INDEX = nextIndex;
  TARGET_NAVIGATING = true;
  navigateTargetPath(TARGET_HISTORY[TARGET_HISTORY_INDEX]);
}

function onTargetMessage(event) {
  if (!event.data || event.data.type !== "target-location") return;
  const path = event.data.path || "/";
  if (!TARGET_NAVIGATING) {
    TARGET_HISTORY = TARGET_HISTORY.slice(0, TARGET_HISTORY_INDEX + 1);
    TARGET_HISTORY.push(path);
    TARGET_HISTORY_INDEX += 1;
  }
  TARGET_NAVIGATING = false;
  $("#web-address").value = path;
}

function onTargetAddressSubmit(event) {
  event.preventDefault();
  let path = $("#web-address").value.trim();
  if (!path.startsWith("/")) path = `/${path}`;
  if (!ACTIVE_CHALLENGE || !/^\/target\/\d+(\/|$)/.test(path)) {
    path = `/target/${ACTIVE_CHALLENGE.id}/`;
  }
  TARGET_HISTORY = TARGET_HISTORY.slice(0, TARGET_HISTORY_INDEX + 1);
  TARGET_HISTORY.push(path);
  TARGET_HISTORY_INDEX += 1;
  TARGET_NAVIGATING = true;
  navigateTargetPath(path);
}

function navigateTargetPath(path) {
  const targetUrl = new URL($("#web-target-frame").src);
  const requested = new URL(path, targetUrl.origin);
  targetUrl.pathname = requested.pathname;
  targetUrl.search = requested.search;
  $("#web-target-frame").src = targetUrl.toString();
}

// ---------------------------------------------------------------------------
// Scoreboard
// ---------------------------------------------------------------------------

async function loadScoreboard() {
  const body = $("#score-body");
  body.innerHTML = `<tr><td colspan="4" style="color:var(--text-dim)">Loading…</td></tr>`;
  try {
    const rows = await api("/api/scoreboard");
    body.innerHTML = rows
      .map(
        (r, i) => `
      <tr>
        <td>${i + 1}</td>
        <td>${r.team}</td>
        <td>${r.score}</td>
        <td>${r.solves}</td>
      </tr>`
      )
      .join("");
  } catch (err) {
    body.innerHTML = `<tr><td colspan="4" class="form-error">${err.message}</td></tr>`;
  }
}

// ---------------------------------------------------------------------------
// Settings (server URL)
// ---------------------------------------------------------------------------

async function onSaveSettings() {
  const url = $("#settings-url").value.trim().replace(/\/$/, "");
  const status = $("#settings-status");
  if (!url) {
    status.textContent = "Enter a server URL.";
    status.className = "modal-result err";
    return;
  }
  const config = await window.ctfConfig.set({ serverUrl: url });
  SERVER_URL = config.serverUrl;
  status.textContent = "Saved.";
  status.className = "modal-result ok";
}

// ---------------------------------------------------------------------------
// Interactive terminal challenges
// ---------------------------------------------------------------------------

function openTerminalChallenge(c) {
  TERMINAL_CHALLENGE = c;
  TERMINAL_CWD = "/";

  $("#terminal-category").textContent = c.category;
  $("#terminal-title").textContent = c.title;
  $("#terminal-points").textContent = `${c.points} points`;
  $("#terminal-result").textContent = "";
  $("#terminal-result").className = "modal-result";
  $("#terminal-flag-input").value = "";
  $("#terminal-prompt").textContent = "/ $";

  const hintWrap = $("#terminal-hint-wrap");
  if (c.hint) {
    hintWrap.classList.remove("hidden");
    $("#terminal-hint").textContent = c.hint;
  } else {
    hintWrap.classList.add("hidden");
  }

  const out = $("#terminal-output");
  out.innerHTML = "";
  appendTerminalLine(
    `Connected. Type 'help' for a list of commands.\n${c.description}`,
    "info"
  );

  $("#modal-terminal").classList.remove("hidden");
  $("#terminal-cmd-input").value = "";
  $("#terminal-cmd-input").focus();
}

function appendTerminalLine(text, kind) {
  const out = $("#terminal-output");
  const line = document.createElement("div");
  if (kind === "cmd") line.className = "terminal-line-cmd";
  if (kind === "err") line.className = "terminal-line-err";
  line.textContent = text;
  out.appendChild(line);
  out.scrollTop = out.scrollHeight;
}

async function onTerminalCommand(e) {
  e.preventDefault();
  const input = $("#terminal-cmd-input");
  const command = input.value;
  if (!command.trim()) return;

  appendTerminalLine(`${TERMINAL_CWD} $ ${command}`, "cmd");
  input.value = "";

  try {
    const body = await api(`/api/challenges/${TERMINAL_CHALLENGE.id}/terminal`, {
      method: "POST",
      body: JSON.stringify({ cwd: TERMINAL_CWD, command }),
    });
    if (body.output) appendTerminalLine(body.output);
    TERMINAL_CWD = body.cwd;
    $("#terminal-prompt").textContent = `${TERMINAL_CWD} $`;
  } catch (err) {
    appendTerminalLine(err.message, "err");
  }
}

async function onSubmitFlagTerminal(e) {
  e.preventDefault();
  const result = $("#terminal-result");
  try {
    const body = await api("/api/submit", {
      method: "POST",
      body: JSON.stringify({
        challenge_id: TERMINAL_CHALLENGE.id,
        flag: $("#terminal-flag-input").value,
      }),
    });
    if (body.correct) {
      result.textContent = "Correct! Challenge solved.";
      result.className = "modal-result ok";
      await loadChallenges();
    } else {
      result.textContent = "Incorrect flag, try again.";
      result.className = "modal-result err";
    }
    notifySolve(TERMINAL_CHALLENGE, body);
  } catch (err) {
    result.textContent = err.message;
    result.className = "modal-result err";
  }
}

// ---------------------------------------------------------------------------
// Profile / settings view
// ---------------------------------------------------------------------------

async function loadProfileForm() {
  try {
    const profile = await api("/api/me");
    ME = { ...ME, ...profile };
    $("#profile-display-name").value = profile.display_name || "";
    $("#profile-avatar").value = profile.avatar || "🛡️";
    $("#profile-bio").value = profile.bio || "";
  } catch (err) {
    $("#profile-result").textContent = err.message;
    $("#profile-result").className = "form-result err";
  }
}

async function onSaveProfile(e) {
  e.preventDefault();
  const result = $("#profile-result");
  try {
    const profile = await api("/api/me", {
      method: "PUT",
      body: JSON.stringify({
        display_name: $("#profile-display-name").value,
        avatar: $("#profile-avatar").value,
        bio: $("#profile-bio").value,
      }),
    });
    ME = { ...ME, ...profile };
    $("#who-user").textContent = ME.display_name || ME.username;
    $("#who-avatar").textContent = ME.avatar || "🛡️";
    result.textContent = "Saved.";
    result.className = "form-result ok";
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

async function onResetProgress() {
  if (!confirm("Reset your team's solve and attempt history? This cannot be undone.")) return;
  const result = $("#reset-result");
  try {
    await api("/api/me/reset-progress", { method: "POST" });
    result.textContent = "Progress reset.";
    result.className = "form-result ok";
    await loadChallenges();
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

async function onChangePassword(e) {
  e.preventDefault();
  const result = $("#password-result");
  try {
    await api("/api/me/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: $("#pw-current").value,
        new_password: $("#pw-new").value,
      }),
    });
    result.textContent = "Password updated.";
    result.className = "form-result ok";
    $("#pw-current").value = "";
    $("#pw-new").value = "";
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

// ---------------------------------------------------------------------------
// Admin: stats, challenges, users
// ---------------------------------------------------------------------------

async function loadAdmin() {
  await loadAdminTeams();
  await Promise.all([
    loadAdminStats(),
    loadAdminChallenges(),
    loadAdminUsers(),
    loadOllamaStatus(),
    loadAdminThemes(),
    loadAdminAddons(),
  ]);
}

async function loadOllamaStatus() {
  const status = $("#ollama-status");
  try {
    const body = await api("/api/admin/ollama");
    status.textContent = body.available && body.model_available
      ? `Ollama ready · ${body.model}${body.models.length ? ` · ${body.models.length} model(s)` : ""}`
      : body.available
        ? `Ollama online, model missing · run: ollama pull ${body.model}`
      : `Ollama offline · start Ollama at ${body.url} and pull ${body.model}`;
    status.className = `ollama-status ${body.available && body.model_available ? "ok" : "err"}`;
    OLLAMA_MODELS = body.models || [];
    OLLAMA_DEFAULT_MODEL = body.model || null;
    populateAiModelDropdown(body.model);
  } catch (err) {
    status.textContent = err.message;
    status.className = "ollama-status err";
    OLLAMA_MODELS = [];
    OLLAMA_DEFAULT_MODEL = null;
    populateAiModelDropdown(null);
  }
}

function populateAiModelDropdown(serverDefault) {
  const select = $("#cf-ai-model");
  const previousValue = select.value;
  const defaultLabel = serverDefault ? `Use server default (${serverDefault})` : "Use server default";
  const options = [`<option value="">${defaultLabel}</option>`];
  OLLAMA_MODELS.forEach((name) => {
    options.push(`<option value="${name}">${name}</option>`);
  });
  select.innerHTML = options.join("");
  // Keep whatever was selected if it's still a valid option (e.g. a model
  // this specific challenge is already configured to use).
  if ([...select.options].some((o) => o.value === previousValue)) {
    select.value = previousValue;
  }
  const note = $("#cf-ai-model-note");
  if (OLLAMA_MODELS.length === 0) {
    note.textContent = "No models detected - is Ollama running? Falling back to the server default either way.";
  } else {
    note.textContent = `${OLLAMA_MODELS.length} model(s) currently installed on this Ollama instance.`;
  }
}

async function loadAdminStats() {
  const el = $("#admin-stats");
  try {
    const s = await api("/api/admin/stats");
    const cards = [
      ["Users", s.users],
      ["Teams", s.teams],
      ["Challenges", `${s.active_challenges}/${s.challenges}`],
      ["Correct solves", s.correct_submissions],
      ["Total attempts", s.total_submissions],
    ];
    el.innerHTML = cards
      .map(
        ([label, value]) => `
      <div class="stat-card">
        <div class="stat-value">${value}</div>
        <div class="stat-label">${label}</div>
      </div>`
      )
      .join("");
  } catch (err) {
    el.innerHTML = `<p class="form-error">${err.message}</p>`;
  }
}

async function loadAdminChallenges() {
  const body = $("#admin-challenge-body");
  try {
    ADMIN_CHALLENGES = await api("/api/admin/challenges");
    body.innerHTML = ADMIN_CHALLENGES.map(
      (c) => `
      <tr>
        <td>${c.title}</td>
        <td>${c.category}</td>
        <td>${c.type}</td>
        <td>${c.points}</td>
        <td>${c.is_active ? '<span class="tag-active">active</span>' : '<span class="tag-inactive">hidden</span>'}</td>
        <td><button class="row-action-btn" data-edit-id="${c.id}">Edit</button></td>
      </tr>`
    ).join("");
    $$("[data-edit-id]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const c = ADMIN_CHALLENGES.find((x) => x.id === Number(btn.dataset.editId));
        openChallengeForm(c);
      });
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="6" class="form-error">${err.message}</td></tr>`;
  }
}

async function loadAdminUsers() {
  const body = $("#admin-users-body");
  try {
    ADMIN_USERS = await api("/api/admin/users");
    body.innerHTML = ADMIN_USERS.map((u) => {
      const teamOptions = [
        `<option value="__individual__" ${u.team_is_individual ? "selected" : ""}>Independent (solo)</option>`,
        ...ADMIN_TEAMS.map(
          (t) => `<option value="${t.id}" ${!u.team_is_individual && t.name === u.team ? "selected" : ""}>${t.name}</option>`
        ),
      ].join("");
      return `
      <tr>
        <td>${u.username}</td>
        <td>${u.display_name}</td>
        <td><select class="row-select" data-move-user="${u.id}">${teamOptions}</select></td>
        <td>${u.is_admin ? '<span class="tag-active">yes</span>' : '<span class="tag-inactive">no</span>'}</td>
        <td>${
          u.username === ME.username
            ? ""
            : `<button class="row-action-btn" data-toggle-admin="${u.id}">${u.is_admin ? "Revoke admin" : "Make admin"}</button>`
        }</td>
      </tr>`;
    }).join("");
    $$("[data-toggle-admin]").forEach((btn) => {
      btn.addEventListener("click", () => onToggleAdmin(Number(btn.dataset.toggleAdmin)));
    });
    $$("[data-move-user]").forEach((select) => {
      select.addEventListener("change", () => onMoveUserTeam(Number(select.dataset.moveUser), select.value));
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5" class="form-error">${err.message}</td></tr>`;
  }
}

async function onToggleAdmin(userId) {
  try {
    await api(`/api/admin/users/${userId}/toggle-admin`, { method: "POST" });
    await loadAdminUsers();
  } catch (err) {
    alert(err.message);
  }
}

async function onMoveUserTeam(userId, teamValue) {
  try {
    const payload = teamValue === "__individual__" ? { individual: true } : { team_id: Number(teamValue) };
    await api(`/api/admin/users/${userId}/move-team`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
    await loadAdminTeams(); // member counts changed
    await loadAdminUsers(); // team names shown for individuals may have changed
  } catch (err) {
    alert(err.message);
    await loadAdminUsers(); // snap the dropdown back to the real value
  }
}

async function loadAdminTeams() {
  const body = $("#admin-teams-body");
  try {
    ADMIN_TEAMS = await api("/api/admin/teams");
    body.innerHTML = ADMIN_TEAMS.map((t) => {
      let action;
      if (t.is_default) {
        action = '<span class="field-note">default team</span>';
      } else if (t.member_count > 0) {
        action = '<span class="field-note">move members out to delete</span>';
      } else {
        action = `<button class="row-action-btn" data-delete-team="${t.id}">Delete</button>`;
      }
      return `<tr><td>${t.name}</td><td>${t.member_count}</td><td>${action}</td></tr>`;
    }).join("");
    $$("[data-delete-team]").forEach((btn) => {
      btn.addEventListener("click", () => onDeleteTeam(Number(btn.dataset.deleteTeam)));
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="3" class="form-error">${err.message}</td></tr>`;
  }
}

// ---- Theme: a dropdown (Default + every discovered theme) plus an
// explicit Save button, so switching the active theme is a deliberate,
// confirmed action rather than firing on every arrow-key press through the
// list. Saving reaches every open client immediately via live updates.
async function loadAdminThemes() {
  const select = $("#theme-select");
  const meta = $("#theme-meta");
  const result = $("#theme-save-result");
  try {
    ADMIN_THEMES = await api("/api/admin/themes");
    const options = ['<option value="">Default (no theme)</option>'].concat(
      ADMIN_THEMES.map((t) => `<option value="${t.id}">${t.name} (v${t.version})</option>`)
    );
    select.innerHTML = options.join("");
    const active = ADMIN_THEMES.find((t) => t.active);
    select.value = active ? active.id : "";
    renderThemeMeta(active || null);
    updateThemeDeleteButtonState();
    result.textContent = "";
    result.className = "form-result";
  } catch (err) {
    meta.innerHTML = `<p class="form-error">${err.message}</p>`;
  }
}

function renderThemeMeta(theme) {
  const meta = $("#theme-meta");
  if (!theme) {
    meta.innerHTML = '<p class="extension-desc">The built-in OpenCTF look - no theme file loaded.</p>';
    return;
  }
  meta.innerHTML = `
    ${theme.author ? `<div class="extension-author">by ${theme.author}</div>` : ""}
    ${theme.description ? `<div class="extension-desc">${theme.description}</div>` : ""}
  `;
}

// The Default (no theme) look isn't a real theme folder on the server -
// there's nothing there to delete - so the delete button only makes
// sense, and is only shown, once a real theme is selected in the dropdown.
function updateThemeDeleteButtonState() {
  const select = $("#theme-select");
  const deleteBtn = $("#theme-delete-btn");
  deleteBtn.classList.toggle("hidden", !select.value);
}

async function onSaveTheme() {
  const select = $("#theme-select");
  const result = $("#theme-save-result");
  result.textContent = "";
  result.className = "form-result";
  try {
    await api("/api/admin/theme", {
      method: "POST",
      body: JSON.stringify({ theme_id: select.value || null }),
    });
    result.textContent = "Saved - live on every open client.";
    result.className = "form-result ok";
    await loadAdminThemes();
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
    await loadAdminThemes(); // snap the dropdown back to the real state
  }
}

async function onDeleteTheme() {
  const select = $("#theme-select");
  const themeId = select.value;
  if (!themeId) return; // Default - nothing to delete
  const theme = ADMIN_THEMES.find((t) => t.id === themeId);
  const result = $("#theme-save-result");
  if (!confirm(`Delete "${theme ? theme.name : themeId}"? This removes its folder from the server and can't be undone.`)) return;
  try {
    await api(`/api/admin/themes/${themeId}`, { method: "DELETE" });
    result.textContent = "Deleted.";
    result.className = "form-result ok";
    await loadAdminThemes();
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

// ---- Addons: enable toggle plus a gear button (for addons that declare
// "configurable": true) that opens that addon's own configuration GUI in a
// modal - see openAddonConfigModal(). A "core" addon's toggle is shown but
// disabled, since the server refuses to turn it off anyway.
async function loadAdminAddons() {
  const el = $("#admin-addons-list");
  try {
    ADMIN_ADDONS = await api("/api/admin/addons");
    if (ADMIN_ADDONS.length === 0) {
      el.innerHTML = '<p class="extensions-empty">No addons found on the server yet.</p>';
      return;
    }
    el.innerHTML = ADMIN_ADDONS.map((a) => {
      // A toggle is unusable for two different reasons: this addon is
      // marked can_disable: false (it's meant to always run), or its
      // manifest's "core" version requirement isn't met by this server
      // right now (auto-disabled - see enabled_addon_ids() server-side).
      const toggleDisabled = !a.can_disable || !a.compatible;
      const toggleLabel = !a.can_disable ? "Always on" : !a.compatible ? "Unavailable" : "Enabled";
      return `
      <div class="extension-card">
        <div class="extension-info">
          <div class="extension-title">
            ${a.name} <span class="extension-version">v${a.version}</span>
            ${!a.can_disable ? '<span class="extension-core-badge">core</span>' : ""}
          </div>
          ${a.author ? `<div class="extension-author">by ${a.author}</div>` : ""}
          ${a.description ? `<div class="extension-desc">${a.description}</div>` : ""}
          ${!a.compatible ? `<div class="extension-compat-warning">${a.compatibility_note}</div>` : ""}
        </div>
        <div class="extension-actions">
          ${a.configurable ? `<button type="button" class="icon-btn" title="Configure ${a.name}" data-configure-addon="${a.id}">&#9881;</button>` : ""}
          ${a.can_disable ? `<button type="button" class="icon-btn icon-btn-danger" title="Delete ${a.name}" data-delete-addon="${a.id}">&#128465;</button>` : ""}
          <label class="toggle-row">
            <span class="toggle-switch">
              <input type="checkbox" data-toggle-addon="${a.id}" ${a.enabled ? "checked" : ""} ${toggleDisabled ? "disabled" : ""} />
              <span class="toggle-track"></span>
            </span>
            ${toggleLabel}
          </label>
        </div>
      </div>`;
    }).join("");
    $$("[data-toggle-addon]").forEach((input) => {
      if (input.disabled) return; // always-on or version-incompatible - nothing to wire up
      input.addEventListener("change", () => onToggleAddon(input.dataset.toggleAddon));
    });
    $$("[data-configure-addon]").forEach((btn) => {
      btn.addEventListener("click", () => openAddonConfigModal(btn.dataset.configureAddon));
    });
    $$("[data-delete-addon]").forEach((btn) => {
      btn.addEventListener("click", () => onDeleteAddon(btn.dataset.deleteAddon));
    });
  } catch (err) {
    el.innerHTML = `<p class="form-error">${err.message}</p>`;
  }
}

async function onToggleAddon(addonId) {
  try {
    await api(`/api/admin/addons/${addonId}/toggle`, { method: "POST" });
    await loadAdminAddons();
  } catch (err) {
    alert(err.message);
    await loadAdminAddons(); // snap the checkbox back to the real state
  }
}

async function onDeleteAddon(addonId) {
  const addon = ADMIN_ADDONS.find((a) => a.id === addonId);
  if (!confirm(`Delete "${addon ? addon.name : addonId}"? This removes its folder from the server and can't be undone.`)) return;
  try {
    await api(`/api/admin/addons/${addonId}`, { method: "DELETE" });
    await loadAdminAddons();
  } catch (err) {
    alert(err.message);
  }
}

// ---- Addon configuration modal
//
// An addon that declares "configurable": true and a "config_entry" script
// gets a gear button. Clicking it loads that addon's own config script
// (server/addons/<id>/<config_entry>) into this modal - the script builds
// whatever form it wants using window.OpenCTFAdmin, set up fresh below
// before the script loads. See docs/ADDON_DEVELOPMENT.md for the contract.
function openAddonConfigModal(addonId) {
  const addon = ADMIN_ADDONS.find((a) => a.id === addonId);
  $("#addon-config-title").textContent = `Configure ${addon ? addon.name : addonId}`;
  const container = $("#addon-config-body");
  container.innerHTML = '<p class="field-note">Loading...</p>';
  $("#modal-addon-config").classList.remove("hidden");

  // Drop any previous config script instance so state/listeners from a
  // prior open (of this or a different addon) don't pile up.
  const oldScript = document.getElementById("addon-config-script");
  if (oldScript) oldScript.remove();

  window.OpenCTFAdmin = {
    addonId,
    async get() {
      const body = await api(`/api/admin/addons/${addonId}/config`);
      return body.config;
    },
    async save(config) {
      const body = await api(`/api/admin/addons/${addonId}/config`, {
        method: "POST",
        body: JSON.stringify(config),
      });
      return body.config;
    },
    /** The addon's config script calls this once, with a function that
     * receives the modal's content container to render into. */
    mount(renderFn) {
      renderFn(container);
    },
  };

  const script = document.createElement("script");
  script.id = "addon-config-script";
  script.src = `${SERVER_URL}/api/addons/${addonId}/config-script`;
  script.onerror = () => {
    container.innerHTML = '<p class="form-error">Could not load this addon\u2019s configuration screen.</p>';
  };
  document.body.appendChild(script);
}

// ---- Custom drag-and-drop upload zone wiring (see .upload-dropzone in
// styles.css). The <input type="file"> is a real, fully transparent
// element covering the zone - clicking anywhere opens the native picker,
// and dropping a file onto it uses the browser's own native drop handling
// for file inputs, so there's no manual DataTransfer plumbing needed here.
// This just keeps the visible filename chip / Install button in sync with
// it and adds a drag-hover state.
function wireUploadDropzone({ zoneId, inputId, filenameId, btnId, resultId, kind }) {
  const zone = $(`#${zoneId}`);
  const input = $(`#${inputId}`);
  const filenameEl = $(`#${filenameId}`);
  const btn = $(`#${btnId}`);
  const result = $(`#${resultId}`);

  function syncFromInput() {
    const file = input.files[0];
    if (file) {
      filenameEl.textContent = file.name;
      filenameEl.classList.remove("hidden");
      btn.disabled = false;
    } else {
      filenameEl.textContent = "";
      filenameEl.classList.add("hidden");
      btn.disabled = true;
    }
  }

  input.addEventListener("change", syncFromInput);

  let dragEndTimer;
  zone.addEventListener("dragover", () => {
    zone.classList.add("drag-active");
    clearTimeout(dragEndTimer);
    dragEndTimer = setTimeout(() => zone.classList.remove("drag-active"), 150);
  });
  zone.addEventListener("drop", () => {
    zone.classList.remove("drag-active");
    setTimeout(syncFromInput, 0); // let the native drop populate input.files first
  });

  btn.addEventListener("click", async () => {
    await uploadExtension(kind, input, result);
    syncFromInput(); // uploadExtension clears input.value on success
  });
}
async function uploadExtension(kind, fileInput, resultEl) {
  const file = fileInput.files[0];
  if (!file) {
    resultEl.textContent = "Choose a .zip file first.";
    resultEl.className = "form-result err";
    return;
  }
  resultEl.textContent = "Uploading...";
  resultEl.className = "form-result";
  const formData = new FormData();
  formData.append("file", file);
  try {
    const res = await fetch(`${SERVER_URL}/api/admin/${kind}/upload`, {
      method: "POST",
      headers: TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {},
      body: formData,
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || `upload failed (${res.status})`);
    resultEl.textContent = `Installed "${body.name || body.id}".`;
    resultEl.className = "form-result ok";
    fileInput.value = "";
    if (kind === "themes") await loadAdminThemes();
    else await loadAdminAddons();
  } catch (err) {
    resultEl.textContent = err.message;
    resultEl.className = "form-result err";
  }
}

async function onCreateTeam(e) {
  e.preventDefault();
  const input = $("#new-team-name");
  const result = $("#team-form-result");
  result.textContent = "";
  result.className = "form-result";
  try {
    await api("/api/admin/teams", {
      method: "POST",
      body: JSON.stringify({ name: input.value }),
    });
    input.value = "";
    await loadAdminTeams();
    await loadAdminUsers(); // team dropdowns need the new option
    await loadAdminStats();
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

async function onDeleteTeam(teamId) {
  if (!confirm("Delete this team? This can't be undone.")) return;
  try {
    await api(`/api/admin/teams/${teamId}`, { method: "DELETE" });
    await loadAdminTeams();
    await loadAdminStats();
  } catch (err) {
    alert(err.message);
  }
}

function updateFlagPreview() {
  const preview = flagPreviewFor($("#cf-flag").value);
  const el = $("#cf-flag-preview");
  if (preview) {
    el.textContent = `Will save as: ${preview}`;
    el.classList.remove("hidden");
  } else {
    el.textContent = "";
    el.classList.add("hidden");
  }
}

function onGenerateFlag() {
  // Build a seed from the challenge's own info - title, category, type,
  // difficulty - plus a random component so two challenges with similar
  // titles still get unrelated flags, and regenerating gives a fresh one.
  const parts = [
    $("#cf-title").value.trim(),
    $("#cf-category").value.trim(),
    $("#cf-type").value,
    $("#cf-difficulty").value,
    $("#cf-points").value,
    Date.now().toString(36),
    Math.random().toString(36).slice(2),
  ].filter(Boolean);
  const seed = parts.join("|");
  $("#cf-flag").value = seed;
  updateFlagPreview();
}

function openChallengeForm(c) {
  EDITING_CHALLENGE_ID = c ? c.id : null;
  $("#challenge-form-title").textContent = c ? "Edit challenge" : "New challenge";
  $("#cf-id").value = c ? c.id : "";
  $("#cf-title").value = c ? c.title : "";
  $("#cf-category").value = c ? c.category : "";
  $("#cf-type").value = c ? c.type : "standard";
  $("#cf-preset").value = "custom";
  $("#cf-difficulty").value = c ? (c.difficulty || "medium") : "easy";
  $("#cf-points").value = c ? c.points : 100;
  $("#cf-description").value = c ? c.description : "";
  $("#cf-rules").value = c && c.rules ? c.rules : "";
  $("#cf-hint").value = c && c.hint ? c.hint : "";
  $("#cf-terminal-fs").value = c && c.terminal_fs ? c.terminal_fs : "";
  $("#cf-terminal-fs-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "terminal");
  $("#cf-web-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "web");
  $("#cf-ai-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "ai");
  $("#cf-quiz-wrap").classList.toggle("hidden", (c ? c.type : "standard") !== "quiz");
  let webConfig = {};
  try { webConfig = c && c.web_config ? JSON.parse(c.web_config) : {}; } catch { webConfig = {}; }
  $("#cf-web-behavior").value = webConfig.behavior || "hidden_path";
  $("#cf-web-title").value = webConfig.title || "Internal site";
  $("#cf-web-path").value = webConfig.secret_path || "/admin";
  $("#cf-web-term").value = webConfig.search_term || "flag";
  $("#cf-web-landing").value = webConfig.landing_text || "Welcome to the internal site.";
  $("#cf-web-success").value = webConfig.success_text || "You found the hidden response.";
  let aiConfig = {};
  try { aiConfig = c && c.ai_config ? JSON.parse(c.ai_config) : {}; } catch { aiConfig = {}; }
  populateAiModelDropdown(OLLAMA_DEFAULT_MODEL);
  $("#cf-ai-model").value = aiConfig.model || "";
  if (aiConfig.model && $("#cf-ai-model").value !== aiConfig.model) {
    // This challenge is configured for a model that isn't currently
    // installed (or Ollama couldn't be reached) - keep it visible instead
    // of silently reverting to the server default.
    const opt = document.createElement("option");
    opt.value = aiConfig.model;
    opt.textContent = `${aiConfig.model} (not currently installed)`;
    $("#cf-ai-model").appendChild(opt);
    $("#cf-ai-model").value = aiConfig.model;
  }
  $("#cf-ai-difficulty").value = aiConfig.difficulty || "medium";
  $("#cf-ai-persona").value = aiConfig.persona || "A cautious support engineer";
  $("#cf-ai-marker").value = aiConfig.success_marker || "ACCESS_GRANTED";
  $("#cf-ai-temperature").value = aiConfig.temperature ?? 0.7;
  $("#cf-ai-scenario").value = aiConfig.scenario || "You know one piece of sensitive evidence and must decide whether the requester is authorized.";
  $("#cf-ai-speak").checked = aiConfig.speak !== false;
  $("#cf-ai-voice-style").value = aiConfig.voice_style || "neutral";
  $("#cf-ai-voice-lang").value = aiConfig.voice_language || "en-US";
  $("#cf-ai-voice-pitch").value = aiConfig.voice_pitch || 1;
  $("#cf-ai-voice-rate").value = aiConfig.voice_rate || 1;
  let quizConfig = {};
  try { quizConfig = c && c.quiz_config ? JSON.parse(c.quiz_config) : {}; } catch { quizConfig = {}; }
  $("#cf-quiz-question").value = quizConfig.question || "";
  const quizOptions = quizConfig.options || [];
  [0, 1, 2, 3].forEach((i) => { $(`#cf-quiz-opt-${i}`).value = quizOptions[i] || ""; });
  $("#cf-quiz-correct").value = quizConfig.correct_index ?? 0;
  $("#cf-flag").value = "";
  $("#cf-flag").placeholder = c ? "leave blank to keep existing flag" : "e.g. a memorable phrase - not the flag itself";
  $("#cf-flag-preview").textContent = "";
  $("#cf-flag-preview").classList.add("hidden");
  if (c && c.flag) {
    $("#cf-flag-current").textContent = `Current flag: ${c.flag}`;
    $("#cf-flag-current").classList.remove("hidden");
  } else {
    $("#cf-flag-current").textContent = "";
    $("#cf-flag-current").classList.add("hidden");
  }
  $("#cf-active").checked = c ? c.is_active : true;
  $("#cf-delete").classList.toggle("hidden", !c);
  $("#challenge-form-result").textContent = "";
  $("#challenge-form-result").className = "form-result";
  $("#modal-challenge-form").classList.remove("hidden");
}

const CHALLENGE_PRESETS = {
  web: {
    category: "web", type: "web", difficulty: "easy", points: 100,
    title: "Web Footprint", description: "Inspect a web application and identify the exposed clue that leads to the flag.",
    rules: "Use only the provided application. Do not attack the host system or other services.",
    hint: "Inspect the page source, response headers, and paths linked from the application.",
    web: true,
  },
  database: {
    category: "database", type: "standard", difficulty: "hard", points: 300,
    title: "Query Under Pressure", description: "Investigate an unsafe database-backed endpoint and recover the secret record.",
    rules: "Stay within the supplied endpoint and keep requests focused on the challenge data.",
    hint: "Look for places where user input is joined directly into a query.",
  },
  terminal: {
    category: "terminal", type: "terminal", difficulty: "medium", points: 200,
    title: "The Forgotten Shell", description: "Explore a restricted virtual machine with safe read-only commands and find the hidden flag.",
    rules: "Only use the commands available in the challenge terminal. The filesystem is an isolated simulation.",
    hint: "Start with pwd and ls, then inspect unfamiliar directories and files.",
  },
  quiz: {
    category: "quiz", type: "quiz", difficulty: "easy", points: 100,
    title: "Quick Knowledge Check", description: "Answer the question correctly to reveal the flag.",
    rules: "",
    hint: "",
    quiz: true,
  },
};

function applyChallengePreset(name) {
  const preset = CHALLENGE_PRESETS[name];
  if (!preset) return;
  $("#cf-title").value = preset.title;
  $("#cf-category").value = preset.category;
  $("#cf-type").value = preset.type;
  $("#cf-difficulty").value = preset.difficulty;
  $("#cf-points").value = preset.points;
  $("#cf-description").value = preset.description;
  $("#cf-rules").value = preset.rules;
  $("#cf-hint").value = preset.hint;
  $("#cf-terminal-fs-wrap").classList.toggle("hidden", preset.type !== "terminal");
  if (preset.type === "terminal") {
    $("#cf-terminal-fs").value = JSON.stringify({ home: { player: { "readme.txt": "Find the next clue.", ".flag.txt": "flag{replace_me}" } } }, null, 2);
  }
  $("#cf-web-wrap").classList.toggle("hidden", preset.type !== "web");
  $("#cf-ai-wrap").classList.toggle("hidden", preset.type !== "ai");
  $("#cf-quiz-wrap").classList.toggle("hidden", preset.type !== "quiz");
  if (preset.web) {
    $("#cf-web-behavior").value = "xss";
    $("#cf-web-title").value = "Internal site";
    $("#cf-web-path").value = "/admin";
    $("#cf-web-landing").value = "Welcome to the internal site. Can you find the restricted area?";
    $("#cf-web-success").value = "Access granted. The response contains the evidence you need.";
  }
  if (preset.quiz) {
    $("#cf-quiz-question").value = "Which port does HTTPS use by default?";
    $("#cf-quiz-opt-0").value = "21";
    $("#cf-quiz-opt-1").value = "80";
    $("#cf-quiz-opt-2").value = "443";
    $("#cf-quiz-opt-3").value = "3306";
    $("#cf-quiz-correct").value = "2";
  }
}

function updatePointsForDifficulty() {
  const values = { easy: 100, medium: 200, hard: 300, expert: 400 };
  $("#cf-points").value = values[$("#cf-difficulty").value] || 100;
}

async function onSaveChallenge(e) {
  e.preventDefault();
  const result = $("#challenge-form-result");

  const payload = {
    title: $("#cf-title").value,
    category: $("#cf-category").value,
    type: $("#cf-type").value,
    points: Number($("#cf-points").value),
    difficulty: $("#cf-difficulty").value,
    description: $("#cf-description").value,
    rules: $("#cf-rules").value,
    hint: $("#cf-hint").value,
    is_active: $("#cf-active").checked,
  };
  if ($("#cf-type").value === "terminal") {
    payload.terminal_fs = $("#cf-terminal-fs").value;
  }
  const flag = $("#cf-flag").value.trim();
  if ($("#cf-type").value === "web") {
    // The flag revealed on success is always the challenge's own "Flag"
    // field, so the admin only has to type it once. When editing without
    // changing the flag, keep whatever secret the challenge already had.
    let existingSecret = "";
    if (EDITING_CHALLENGE_ID) {
      const existing = ADMIN_CHALLENGES.find((x) => x.id === EDITING_CHALLENGE_ID);
      try { existingSecret = existing && existing.web_config ? (JSON.parse(existing.web_config).secret || "") : ""; } catch { existingSecret = ""; }
    }
    payload.web_config = JSON.stringify({
      behavior: $("#cf-web-behavior").value,
      title: $("#cf-web-title").value,
      secret_path: $("#cf-web-path").value,
      search_term: $("#cf-web-term").value,
      landing_text: $("#cf-web-landing").value,
      success_text: $("#cf-web-success").value,
      secret: flag || existingSecret,
    });
  }
  if ($("#cf-type").value === "ai") {
    payload.ai_config = JSON.stringify({
      model: $("#cf-ai-model").value || null,
      difficulty: $("#cf-ai-difficulty").value,
      persona: $("#cf-ai-persona").value,
      success_marker: $("#cf-ai-marker").value,
      temperature: Number($("#cf-ai-temperature").value),
      scenario: $("#cf-ai-scenario").value,
      speak: $("#cf-ai-speak").checked,
      voice_style: $("#cf-ai-voice-style").value,
      voice_language: $("#cf-ai-voice-lang").value,
      voice_pitch: Number($("#cf-ai-voice-pitch").value),
      voice_rate: Number($("#cf-ai-voice-rate").value),
    });
  }
  if ($("#cf-type").value === "quiz") {
    const options = [0, 1, 2, 3]
      .map((i) => $(`#cf-quiz-opt-${i}`).value.trim())
      .filter((value) => value.length > 0);
    payload.quiz_config = JSON.stringify({
      question: $("#cf-quiz-question").value.trim(),
      options,
      correct_index: Number($("#cf-quiz-correct").value),
    });
  }
  if (flag) payload.flag = flag;

  try {
    let saved;
    if (EDITING_CHALLENGE_ID) {
      saved = await api(`/api/admin/challenges/${EDITING_CHALLENGE_ID}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
    } else {
      if (!flag) throw new Error("flag is required for a new challenge");
      saved = await api("/api/admin/challenges", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      // Further saves in this session update the challenge we just made
      // instead of creating duplicates.
      EDITING_CHALLENGE_ID = saved.id;
      $("#cf-id").value = saved.id;
      $("#challenge-form-title").textContent = "Edit challenge";
      $("#cf-delete").classList.remove("hidden");
    }
    $("#cf-flag").value = "";
    $("#cf-flag-preview").textContent = "";
    $("#cf-flag-preview").classList.add("hidden");
    if (saved.flag) {
      $("#cf-flag-current").textContent = `Current flag: ${saved.flag} - copy this into the challenge content (description, terminal files, etc.) wherever players need to find it.`;
      $("#cf-flag-current").classList.remove("hidden");
    }
    result.textContent = "Saved.";
    result.className = "form-result ok";
    await loadAdminChallenges();
    await loadAdminStats();
  } catch (err) {
    result.textContent = err.message;
    result.className = "form-result err";
  }
}

async function onDeleteChallenge() {
  if (!EDITING_CHALLENGE_ID) return;
  if (!confirm("Delete this challenge? This also removes its submission history.")) return;
  try {
    await api(`/api/admin/challenges/${EDITING_CHALLENGE_ID}`, { method: "DELETE" });
    $("#modal-challenge-form").classList.add("hidden");
    await loadAdminChallenges();
    await loadAdminStats();
  } catch (err) {
    alert(err.message);
  }
}

init();
