const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { exec } = require('child_process');

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

function run(cmd, timeout) {
  return new Promise(resolve => {
    exec(cmd, { timeout: timeout || 6000 }, (err, stdout) => {
      resolve({ ok: !err, out: (stdout || '').trim() });
    });
  });
}

ipcMain.handle('security-check', async () => {
  const plat = process.platform;

  if (plat === 'win32') {
    const [fwSecRaw, fwProfRaw, fwNetshRaw, avRaw, defRaw] = await Promise.all([
      // Primär: SecurityCenter2 (erkennt auch Drittanbieter-Firewalls)
      run('powershell -NoProfile -NonInteractive -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName FirewallProduct | Select-Object displayName,productState | ConvertTo-Json -Compress"'),
      // Fallback 1: Get-NetFirewallProfile mit explizitem String-Cast (umgeht GpoBoolean-JSON-Problem)
      run('powershell -NoProfile -NonInteractive -Command "Get-NetFirewallProfile | Select-Object Name,@{N=\'On\';E={($_.Enabled).ToString()}} | ConvertTo-Json -Compress"'),
      // Fallback 2: netsh — lokalisierungsunabhängig und zuverlässig
      run('netsh advfirewall show allprofiles state'),
      run('powershell -NoProfile -NonInteractive -Command "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState | ConvertTo-Json -Compress"'),
      run('powershell -NoProfile -NonInteractive -Command "Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,AntivirusSignatureAge,AntispywareSignatureAge | ConvertTo-Json -Compress"'),
    ]);

    // productState-Bit 15-12: 1 = aktiv/monitoring
    function sc2Enabled(state) { return ((parseInt(state) || 0) >> 12) & 0xF; }

    let firewalls = [];

    // Stufe 1: SecurityCenter2 FirewallProduct (Drittanbieter + neuere Windows-Versionen)
    try {
      let d = JSON.parse(fwSecRaw.out);
      if (!Array.isArray(d)) d = [d];
      if (d.length > 0 && d[0] && d[0].displayName) {
        firewalls = d.map(f => ({ name: f.displayName, enabled: sc2Enabled(f.productState) === 1 }));
      }
    } catch (_) {}

    // Stufe 2: Get-NetFirewallProfile mit String-Cast ('True'/'False' statt GpoBoolean-Integer)
    if (firewalls.length === 0) {
      try {
        let d = JSON.parse(fwProfRaw.out);
        if (!Array.isArray(d)) d = [d];
        firewalls = d.map(f => ({ name: f.Name, enabled: String(f.On).toLowerCase() === 'true' }));
      } catch (_) {}
    }

    // Stufe 3: netsh — text-basiert, kein Serialisierungsproblem
    if (firewalls.length === 0 || firewalls.every(f => !f.enabled)) {
      const netsh = fwNetshRaw.out;
      // "State ON" (EN) oder "Status EIN" (DE) im netsh-Output
      const netshActive = /\bON\b|\bEIN\b/i.test(netsh);
      if (netshActive) {
        // Profile aus netsh-Output parsen
        const profiles = [];
        const blocks = netsh.split(/\r?\n\r?\n/);
        let lastName = '';
        blocks.forEach(block => {
          const nameMatch = block.match(/^(.+?)\s+(Profile Settings|Profil Einstellungen)/im);
          const stateMatch = block.match(/\b(State|Status)\s+(ON|EIN|OFF|AUS)\b/i);
          if (nameMatch) lastName = nameMatch[1].trim();
          if (stateMatch) {
            profiles.push({
              name: lastName || 'Firewall',
              enabled: /ON|EIN/i.test(stateMatch[2]),
            });
          }
        });
        if (profiles.length > 0) firewalls = profiles;
        else firewalls = [{ name: 'Windows Firewall', enabled: true }];
      }
    }

    let antiviruses = [];
    try {
      let d = JSON.parse(avRaw.out);
      if (!Array.isArray(d)) d = [d];
      antiviruses = d.map(a => {
        const state  = parseInt(a.productState) || 0;
        const enabled = sc2Enabled(state) === 1;
        const defsOk  = ((state >> 4) & 0xF) === 0;
        return { name: a.displayName, enabled, defsOk };
      });
    } catch (_) {}

    // Supplement with Windows Defender details when available
    let defender = null;
    try {
      const d = JSON.parse(defRaw.out);
      if (d && typeof d.RealTimeProtectionEnabled !== 'undefined') {
        const sigAge = Math.max(d.AntivirusSignatureAge || 0, d.AntispywareSignatureAge || 0);
        defender = {
          name: 'Windows Defender',
          enabled: d.RealTimeProtectionEnabled === true,
          defsOk: sigAge <= 3,
          sigAge,
        };
        // Merge or add defender entry
        const idx = antiviruses.findIndex(a => /defender/i.test(a.name));
        if (idx >= 0) antiviruses[idx] = { ...antiviruses[idx], ...defender };
        else if (antiviruses.length === 0) antiviruses.push(defender);
      }
    } catch (_) {}

    return { platform: 'win32', firewalls, antiviruses };

  } else if (plat === 'darwin') {
    const [fwRaw, xpRaw, clamRaw] = await Promise.all([
      run("defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo 'unknown'"),
      run('ls /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist 2>/dev/null && echo ok || echo missing'),
      run('which clamscan 2>/dev/null && clamscan --version 2>/dev/null || echo missing'),
    ]);
    const fwState = parseInt(fwRaw.out);
    const firewalls = [{ name: 'macOS Firewall', enabled: fwState === 1 || fwState === 2 }];
    const xpOk = xpRaw.out.includes('ok');
    const antiviruses = [{ name: 'XProtect (Apple built-in)', enabled: xpOk, defsOk: xpOk }];
    if (!clamRaw.out.includes('missing')) {
      antiviruses.push({ name: 'ClamAV', enabled: true, defsOk: true });
    }
    return { platform: 'darwin', firewalls, antiviruses };

  } else {
    // Linux
    const [ufwRaw, fwdRaw, iptRaw, clamRaw, rkhRaw] = await Promise.all([
      run('ufw status 2>/dev/null || echo unavailable'),
      run('systemctl is-active firewalld 2>/dev/null || echo inactive'),
      run('iptables -L INPUT -n --line-numbers 2>/dev/null | head -5 || echo unavailable'),
      run('which clamscan 2>/dev/null && clamscan --version 2>/dev/null || echo missing'),
      run('which rkhunter 2>/dev/null && echo found || echo missing'),
    ]);
    const ufwActive  = ufwRaw.out.toLowerCase().includes('status: active');
    const fwdActive  = fwdRaw.out.trim() === 'active';
    const iptActive  = !iptRaw.out.includes('unavailable') && iptRaw.out.includes('ACCEPT');
    const firewalls = [
      { name: 'ufw',       enabled: ufwActive },
      { name: 'firewalld', enabled: fwdActive },
      { name: 'iptables',  enabled: iptActive },
    ].filter(f => ufwActive || fwdActive || iptActive ? true : true); // always show all on Linux
    const antiviruses = [];
    if (!clamRaw.out.includes('missing')) antiviruses.push({ name: 'ClamAV', enabled: true, defsOk: true });
    if (!rkhRaw.out.includes('missing'))  antiviruses.push({ name: 'rkhunter', enabled: true, defsOk: true });
    if (antiviruses.length === 0) antiviruses.push({ name: 'Kein AV gefunden', enabled: false, defsOk: false });
    return { platform: 'linux', firewalls, antiviruses };
  }
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
