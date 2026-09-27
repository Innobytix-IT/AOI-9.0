const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  platform:      process.platform,
  minimize:      () => ipcRenderer.send('window-minimize'),
  maximize:      () => ipcRenderer.send('window-maximize'),
  maximizeForce: () => ipcRenderer.send('window-maximize-force'),
  restore:       () => ipcRenderer.send('window-restore'),
  close:         () => ipcRenderer.send('window-close'),
  securityCheck:    () => ipcRenderer.invoke('security-check'),
  emailSaveConfig:  (cfg) => ipcRenderer.invoke('email-save-config', cfg),
  emailLoadConfig:  ()    => ipcRenderer.invoke('email-load-config'),
  emailTest:        (cfg) => ipcRenderer.invoke('email-test', cfg),
  emailFetch:       (cfg) => ipcRenderer.invoke('email-fetch', cfg),
  emailSend:        (args) => ipcRenderer.invoke('email-send', args),
  onWindowFocus: (cb) => ipcRenderer.on('window-focus-changed', (_, focused) => cb(focused)),
});
