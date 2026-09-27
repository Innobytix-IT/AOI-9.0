const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  minimize:      () => ipcRenderer.send('window-minimize'),
  maximize:      () => ipcRenderer.send('window-maximize'),
  maximizeForce: () => ipcRenderer.send('window-maximize-force'),
  restore:       () => ipcRenderer.send('window-restore'),
  close:         () => ipcRenderer.send('window-close'),
});
