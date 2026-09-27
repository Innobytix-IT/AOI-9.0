const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1024,
    height: 768,
    minWidth: 800,
    minHeight: 600,
    title: 'AOI 9.0',
    icon: path.join(__dirname, 'assets', process.platform === 'win32' ? 'icon.ico' : 'icon.png'),
    frame: false,
    backgroundColor: '#008080',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webviewTag: true,
    }
  });

  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

ipcMain.on('window-minimize', () => BrowserWindow.getFocusedWindow()?.minimize());
ipcMain.on('window-maximize', () => { const w = BrowserWindow.getFocusedWindow(); w?.isMaximized() ? w.unmaximize() : w?.maximize(); });
ipcMain.on('window-maximize-force', () => BrowserWindow.getFocusedWindow()?.maximize());
ipcMain.on('window-restore',  () => { const w = BrowserWindow.getFocusedWindow(); if (w?.isMaximized()) w.unmaximize(); });
ipcMain.on('window-close',    () => BrowserWindow.getFocusedWindow()?.close());

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
