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
  emailLoadConfig:  (u)   => ipcRenderer.invoke('email-load-config', u),
  emailTest:        (cfg) => ipcRenderer.invoke('email-test', cfg),
  emailListFolders: (cfg) => ipcRenderer.invoke('email-list-folders', cfg),
  emailFetch:       (cfg) => ipcRenderer.invoke('email-fetch', cfg),
  emailSend:        (args) => ipcRenderer.invoke('email-send', args),
  emailMarkRead:    (args) => ipcRenderer.invoke('email-mark-read', args),
  emailTrash:       (args) => ipcRenderer.invoke('email-trash', args),
  emailTrashMany:   (args) => ipcRenderer.invoke('email-trash-many', args),
  emailMoveMany:    (args) => ipcRenderer.invoke('email-move-many', args),
  readServerFile:   (name) => ipcRenderer.invoke('read-server-file', name),
  openExternal:     (url)  => ipcRenderer.invoke('open-external', url),
});
