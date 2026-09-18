// motd-banner addon
//
// A minimal example addon: shows a dismissible "message of the day" strip
// at the top of the app once the player is logged in. Message text and
// color are configurable from Admin -> Addons & Themes -> gear icon,
// without editing this file - see config.js. Copy this folder as a
// starting point for your own addon - see docs/ADDON_DEVELOPMENT.md for
// the full API reference.
(function () {
  const STORAGE_KEY = "octf-addon-motd-dismissed";
  const FALLBACK = {
    message: "Welcome to OpenCTF! Check the Scoreboard tab to see how your team is doing.",
    color: "#e8a33d",
  };
  let CONFIG = { ...FALLBACK };

  function render() {
    const existing = document.getElementById("addon-motd-banner");
    if (existing) existing.remove();
    if (sessionStorage.getItem(STORAGE_KEY) === "1") return; // dismissed this session

    const bar = document.createElement("div");
    bar.id = "addon-motd-banner";
    bar.style.cssText = [
      `background: ${CONFIG.color || FALLBACK.color}`,
      "color: #14171f",
      "font-family: 'IBM Plex Sans', system-ui, sans-serif",
      "font-size: 13px",
      "font-weight: 600",
      "padding: 8px 16px",
      "display: flex",
      "align-items: center",
      "justify-content: center",
      "gap: 12px",
      "text-align: center",
    ].join(";");

    const text = document.createElement("span");
    text.textContent = CONFIG.message || FALLBACK.message;

    const close = document.createElement("button");
    close.textContent = "\u00d7";
    close.setAttribute("aria-label", "Dismiss");
    close.style.cssText = "background:none;border:none;color:inherit;font-size:16px;cursor:pointer;line-height:1;";
    close.addEventListener("click", () => {
      bar.remove();
      sessionStorage.setItem(STORAGE_KEY, "1");
    });

    bar.appendChild(text);
    bar.appendChild(close);
    document.body.prepend(bar);
  }

  function removeBanner() {
    const bar = document.getElementById("addon-motd-banner");
    if (bar) bar.remove();
  }

  async function loadConfig() {
    try {
      CONFIG = { ...FALLBACK, ...(await window.OpenCTF.getAddonConfig("motd-banner")) };
    } catch {
      CONFIG = { ...FALLBACK };
    }
  }

  // OpenCTF.on("auth:login", ...) fires once right after a successful
  // login/registration (and again if the addon happens to load after that
  // already happened - see the OpenCTF API docs). That's the right moment
  // for a "logged in" banner; showing it on the bare login screen would be
  // pointless since there's no user to greet yet.
  window.OpenCTF.on("auth:login", async () => {
    await loadConfig();
    render();
  });
  window.OpenCTF.on("auth:logout", removeBanner);

  // Live updates: an admin editing the message/color from the gear button
  // reaches every open client immediately, without anyone refreshing.
  window.OpenCTF.on("addon:config_changed", ({ id, config }) => {
    if (id !== "motd-banner") return;
    CONFIG = { ...FALLBACK, ...config };
    if (window.OpenCTF.getUser()) render();
  });

  // If an admin disables this addon on someone else's client, it's already
  // loaded and running there (addon scripts aren't unloaded once fetched) -
  // this is the well-behaved way to actually go away when that happens.
  window.OpenCTF.on("addon:disabled", ({ id }) => {
    if (id === "motd-banner") removeBanner();
  });
})();
