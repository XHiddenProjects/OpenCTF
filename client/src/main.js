const { app, BrowserWindow, ipcMain } = require("electron");
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
    },
  });

  win.loadFile(path.join(__dirname, "index.html"));
}

ipcMain.handle("config:get", () => readConfig());
ipcMain.handle("config:set", (_event, partial) => {
  const merged = { ...readConfig(), ...partial };
  writeConfig(merged);
  return merged;
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
