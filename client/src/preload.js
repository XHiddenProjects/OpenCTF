const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ctfConfig", {
  get: () => ipcRenderer.invoke("config:get"),
  set: (partial) => ipcRenderer.invoke("config:set", partial),
});

contextBridge.exposeInMainWorld("ctfDevTools", {
  toggle: () => ipcRenderer.invoke("devtools:toggle"),
});
