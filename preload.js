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
  readServerFile:        (name)    => ipcRenderer.invoke('read-server-file', name),
  openExternal:          (url)     => ipcRenderer.invoke('open-external', url),
  isEncryptionAvailable: ()        => ipcRenderer.invoke('is-encryption-available'),
  tresorRead:            (u)       => ipcRenderer.invoke('tresor-read', u),
  tresorWrite:           (u, b)    => ipcRenderer.invoke('tresor-write', u, b),
  tresorDelete:          (u)       => ipcRenderer.invoke('tresor-delete', u),

  p2pInit:         (priv, pub)             => ipcRenderer.invoke('p2p-init', priv, pub),
  p2pGetAddr:      ()                      => ipcRenderer.invoke('p2p-get-addr'),
  p2pConnect:      (name, pub, addr, port) => ipcRenderer.invoke('p2p-connect', name, pub, addr, port),
  p2pSend:         (name, text)            => ipcRenderer.invoke('p2p-send', name, text),
  p2pDisconnect:   (name)                  => ipcRenderer.invoke('p2p-disconnect', name),
  p2pIsReady:      (name)                  => ipcRenderer.invoke('p2p-is-ready', name),
  getPlatform:     ()                      => ipcRenderer.invoke('get-platform'),
  firewallOpenP2P:  ()                      => ipcRenderer.invoke('firewall-open-p2p'),
  firewallCheckP2P: ()                      => ipcRenderer.invoke('firewall-check-p2p'),
  onP2pEvent:      (cb) => {
    ipcRenderer.on('p2p-connected', (_, d) => cb('connected', d));
    ipcRenderer.on('p2p-message',   (_, d) => cb('message',   d));
    ipcRenderer.on('p2p-error',     (_, d) => cb('error',     d));
  },
  onUpdate:      (cb) => ipcRenderer.on('aoi-update', (_, d) => cb(d)),
  updateDownload: ()  => ipcRenderer.send('update-download'),
  updateInstall:  ()  => ipcRenderer.send('update-install'),
});
