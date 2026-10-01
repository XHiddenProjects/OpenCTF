const { app, BrowserWindow, ipcMain, Menu } = require("electron");
const path = require("path");
const fs = require("fs");

const CONFIG_PATH = path.join(app.getPath("userData"), "config.json");
const DEFAULT_CONFIG = {
  // Change this to the lab server's LAN address before shipping the exe,
  // or let users set it from the in-app settings screen.
  serverUrl: "http://localhost:5000",
};

function readConfig() {
  try {
    return { ...DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8")) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function writeConfig(config) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

// Bundled copy of the app icon (used for the window/taskbar icon, mainly
// on Linux). The packaged installers use build/icon.ico / build/icon.png
// (-> auto-converted to .icns) for the OS-level app icon, set via the
// "build" config in package.json.
const ICON_PATH = path.join(__dirname, "assets", "icon.png");

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 720,
    minWidth: 800,
    minHeight: 600,
    backgroundColor: "#0f1115",
    icon: ICON_PATH,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      // Explicit (rather than relying on Electron's default) so DevTools
      // stays available even if someone later hardens webPreferences
      // elsewhere in this file - it's needed for the web-exploitation
      // challenges (view source, inspect cookies/requests on the
      // sandboxed target site rendered in the #web-target-frame iframe),
      // the same way a real browser's DevTools would be.
      devTools: true,
    },
  });

  win.loadFile(path.join(__dirname, "index.html"));

  // Electron shows no right-click context menu at all by default (unlike
  // a real browser) - add the one item that matters for this app: Inspect
  // Element, at the position that was actually clicked. This works for
  // the iframe'd target site too, not just the app's own chrome - Chrome's
  // underlying inspector can select into any frame on the page regardless
  // of origin.
  win.webContents.on("context-menu", (_event, params) => {
    Menu.buildFromTemplate([
      {
        label: "Inspect Element",
        click: () => win.webContents.inspectElement(params.x, params.y),
      },
    ]).popup({ window: win });
  });

  // Electron's built-in "Toggle Developer Tools" accelerator is
  // Ctrl+Shift+I / Cmd+Option+I; F12 is the more familiar shortcut from
  // an actual browser, so add it explicitly too.
  win.webContents.on("before-input-event", (_event, input) => {
    if (input.type === "keyDown" && input.key === "F12") {
      win.webContents.toggleDevTools();
    }
  });

  return win;
}

ipcMain.handle("config:get", () => readConfig());
ipcMain.handle("config:set", (_event, partial) => {
  const merged = { ...readConfig(), ...partial };
  writeConfig(merged);
  return merged;
});

// Explicit "Open DevTools" button in the web-challenge browser bar calls
// this (see #web-devtools in index.html / renderer.js) - same underlying
// action as the F12 shortcut and the right-click menu above, just
// discoverable without knowing either of those exist. `event.sender` is
// the calling window's own webContents, so this works correctly even if
// more than one window is ever open at once.
ipcMain.handle("devtools:toggle", (event) => {
  event.sender.toggleDevTools();
});

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
