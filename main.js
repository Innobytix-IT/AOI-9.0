const { app, BrowserWindow, ipcMain, safeStorage, session, shell } = require('electron');
// WebRTC ICE-Ports auf festen Bereich beschränken → Firewall-Regel reicht für 7777-7799
app.commandLine.appendSwitch('webrtc-min-port', '7778');
app.commandLine.appendSwitch('webrtc-max-port', '7799');
// EPIPE-Schutz: verhindert Crash wenn stdout/stderr geschlossen ist (z.B. nach npm start | head)
process.stdout.on('error', e => { if (e.code !== 'EPIPE') throw e; });
process.stderr.on('error', e => { if (e.code !== 'EPIPE') throw e; });
const path = require('path');
const { exec } = require('child_process');
const fs = require('fs');
const { ImapFlow } = require('imapflow');
const nodemailer = require('nodemailer');
const p2p = require('./p2p.js');
const { autoUpdater } = require('electron-updater');

function createWindow() {
  const win = new BrowserWindow({
    width: 1024,
    height: 768,
    minWidth: 800,
    minHeight: 600,
    title: 'AOI 9.0 Nostalgia',
    icon: path.join(__dirname, 'assets', process.platform === 'win32' ? 'icon.ico' : 'icon.png'),
    frame: false,
    backgroundColor: '#008080',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webviewTag: true,
    }
  });

  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.webContents.setBackgroundThrottling(false);
  win.webContents.on('before-input-event', (_, input) => {
    if (input.key === 'F12') win.webContents.toggleDevTools();
  });
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

ipcMain.handle('open-external', (_, url) => {
  const allowed = /^https:\/\/(github\.com|innobytix-it\.de)\//;
  if (allowed.test(url)) shell.openExternal(url);
});

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

/* ===== E-MAIL IPC ===== */
function emailConfigPath(username) {
  const safe = (username || 'default').replace(/[^a-zA-Z0-9_\-\.]/g, '_');
  return path.join(app.getPath('userData'), 'email_config_' + safe + '.json');
}

ipcMain.handle('email-save-config', async (_, cfg) => {
  try {
    if (!safeStorage.isEncryptionAvailable()) {
      return { ok: false, error: 'Systemverschlüsselung nicht verfügbar – E-Mail-Passwort kann nicht sicher gespeichert werden.' };
    }
    const toSave = { ...cfg };
    if (cfg.password) {
      toSave.password = safeStorage.encryptString(cfg.password).toString('base64');
      toSave.encrypted = true;
    }
    fs.writeFileSync(emailConfigPath(cfg.username), JSON.stringify(toSave, null, 2), 'utf8');
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-load-config', async (_, username) => {
  try {
    const filePath = emailConfigPath(username);
    if (!fs.existsSync(filePath)) return { ok: false, config: null };
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (raw.encrypted && raw.password && safeStorage.isEncryptionAvailable()) {
      raw.password = safeStorage.decryptString(Buffer.from(raw.password, 'base64'));
    }
    return { ok: true, config: raw };
  } catch (_) { return { ok: false, config: null }; }
});

/* ===== AOI TRESOR IPC ===== */
ipcMain.handle('is-encryption-available', async () => {
  return safeStorage.isEncryptionAvailable();
});

function tresorPath(username) {
  const safe = (username || 'default').replace(/[^a-zA-Z0-9_\-\.]/g, '_');
  return path.join(app.getPath('userData'), 'aoi_tresor_' + safe + '.enc');
}
ipcMain.handle('tresor-read', async (_, username) => {
  try {
    const p = tresorPath(username);
    if (!fs.existsSync(p)) return { ok: true, data: null };
    return { ok: true, data: fs.readFileSync(p, 'utf8') };
  } catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle('tresor-write', async (_, username, blob) => {
  try {
    fs.writeFileSync(tresorPath(username), blob, 'utf8');
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});
ipcMain.handle('tresor-delete', async (_, username) => {
  try {
    const p = tresorPath(username);
    if (fs.existsSync(p)) fs.unlinkSync(p);
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-test', async (_, cfg) => {
  const client = new ImapFlow({
    host: cfg.imapHost, port: cfg.imapPort,
    secure: cfg.imapSsl,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false, tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await client.connect();
    await client.logout();
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-list-folders', async (_, cfg) => {
  const client = new ImapFlow({
    host: cfg.imapHost, port: cfg.imapPort,
    secure: cfg.imapSsl,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false, tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await client.connect();
    const list = await client.list('', '*');
    await client.logout();
    return { ok: true, folders: list.map(f => ({
      path: f.path,
      name: f.name,
      delimiter: f.delimiter,
      specialUse: f.specialUse || null,
      flags: f.flags ? Array.from(f.flags) : [],
    })) };
  } catch (e) { return { ok: false, error: e.message }; }
});

function decodeMailBytes(raw, charset, encoding) {
  const enc = (charset || 'utf-8').toLowerCase().replace(/[^a-z0-9]/g, '');
  const nodeEnc = (enc === 'utf8' || enc === 'utf8') ? 'utf8'
    : (enc === 'iso88591' || enc === 'latin1' || enc === 'windows1252') ? 'latin1'
    : 'utf8';

  if (/quoted-printable/i.test(encoding)) {
    const stripped = raw.replace(/=\r?\n/g, '');
    const bytes = [];
    for (let i = 0; i < stripped.length; ) {
      if (stripped[i] === '=' && i + 2 < stripped.length && /[0-9A-Fa-f]{2}/.test(stripped.slice(i+1, i+3))) {
        bytes.push(parseInt(stripped.slice(i+1, i+3), 16));
        i += 3;
      } else {
        bytes.push(stripped.charCodeAt(i));
        i++;
      }
    }
    try { return Buffer.from(bytes).toString(nodeEnc); } catch(_) { return raw; }
  }

  if (/base64/i.test(encoding)) {
    try { return Buffer.from(raw.replace(/\s/g, ''), 'base64').toString(nodeEnc); } catch(_) { return raw; }
  }

  return raw;
}

function extractPlainText(raw) {
  if (!raw) return '';
  const str = raw.toString();
  if (!str.includes('Content-Type:')) return str.slice(0, 2000);
  const sections = str.split(/^--[^\r\n]+/m);

  for (const sec of sections) {
    if (/Content-Type:\s*text\/plain/i.test(sec)) {
      const charsetM  = sec.match(/charset=["']?([^"'\r\n;]+)["']?/i);
      const encodingM = sec.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
      const bodyM     = sec.match(/\r?\n\r?\n([\s\S]*)/);
      if (bodyM) {
        const decoded = decodeMailBytes(bodyM[1].trim(), charsetM && charsetM[1], encodingM && encodingM[1]);
        return decoded.slice(0, 2000);
      }
    }
  }

  for (const sec of sections) {
    if (/Content-Type:\s*text\/html/i.test(sec)) {
      const charsetM  = sec.match(/charset=["']?([^"'\r\n;]+)["']?/i);
      const encodingM = sec.match(/Content-Transfer-Encoding:\s*([^\r\n]+)/i);
      const bodyM     = sec.match(/\r?\n\r?\n([\s\S]*)/);
      if (bodyM) {
        const decoded = decodeMailBytes(bodyM[1].trim(), charsetM && charsetM[1], encodingM && encodingM[1]);
        return decoded.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 2000);
      }
    }
  }

  return str.slice(0, 2000);
}

ipcMain.handle('email-fetch', async (_, payload) => {
  const cfg     = (payload && payload.cfg) ? payload.cfg : payload;
  const folders = (payload && payload.folders) ? payload.folders : ['INBOX'];
  const client = new ImapFlow({
    host: cfg.imapHost, port: cfg.imapPort,
    secure: cfg.imapSsl,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false, tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await client.connect();
    let msgs = [];
    let lastErr = null;
    for (const folder of folders) {
      try {
        const lock = await client.getMailboxLock(folder);
        try {
          const status = await client.status(folder, { messages: true });
          const total = status.messages || 0;
          const from = Math.max(1, total - 29);
          if (total > 0) {
            for await (const msg of client.fetch(`${from}:${total}`, {
              uid: true, flags: true, envelope: true, bodyStructure: true,
              bodyParts: ['text'],
            })) {
              const isRead = msg.flags && msg.flags.has('\\Seen');
              const env = msg.envelope || {};
              const fromAddr = env.from && env.from[0]
                ? (env.from[0].name || env.from[0].address || '')
                : '?';
              const bodyPart = msg.bodyParts && (msg.bodyParts.get('text') || msg.bodyParts.get('TEXT'));
              const bodyText = extractPlainText(bodyPart);
              msgs.unshift({
                uid: msg.uid, seq: msg.seq, read: isRead,
                from: fromAddr,
                subject: env.subject || '(kein Betreff)',
                date: env.date ? new Date(env.date).toLocaleDateString('de-DE') : '?',
                body: bodyText,
              });
            }
          }
        } finally { lock.release(); }
        lastErr = null;
        break;
      } catch (e) { lastErr = e; }
    }
    await client.logout();
    if (lastErr) return { ok: false, error: 'Ordner nicht gefunden: ' + lastErr.message };
    return { ok: true, messages: msgs };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-send', async (_, { cfg, to, cc, subject, body }) => {
  const transport = nodemailer.createTransport({
    host: cfg.smtpHost, port: cfg.smtpPort,
    secure: cfg.smtpSsl,
    auth: { user: cfg.user, pass: cfg.password },
    tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await transport.sendMail({ from: cfg.user, to, cc: cc || undefined, subject, text: body });
    return { ok: true };
  } catch (e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-mark-read', async (_, {cfg, folder, uid}) => {
  const client = new ImapFlow({
    host: cfg.imapHost, port: cfg.imapPort, secure: cfg.imapSsl,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false, tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await client.connect();
    const lock = await client.getMailboxLock(folder);
    try { await client.messageFlagsAdd(uid, ['\\Seen'], {uid: true}); }
    finally { lock.release(); }
    await client.logout();
    return { ok: true };
  } catch(e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-trash', async (_, {cfg, folder, uid, trashFolder}) => {
  const client = new ImapFlow({
    host: cfg.imapHost, port: cfg.imapPort, secure: cfg.imapSsl,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false, tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await client.connect();
    const lock = await client.getMailboxLock(folder);
    try {
      if (trashFolder && trashFolder !== folder) {
        await client.messageMove(uid, trashFolder, {uid: true});
      } else {
        await client.messageFlagsAdd({uid}, ['\\Deleted'], {uid: true});
        await client.mailboxClose();
        const lock2 = await client.getMailboxLock(folder);
        try { await client.mailboxOpen(folder, {readOnly: false}); } finally { lock2.release(); }
      }
    } finally { lock.release(); }
    await client.logout();
    return { ok: true };
  } catch(e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-trash-many', async (_, {cfg, folder, uids, trashFolder}) => {
  const client = new ImapFlow({
    host: cfg.imapHost, port: cfg.imapPort, secure: cfg.imapSsl,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false, tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await client.connect();
    const lock = await client.getMailboxLock(folder);
    try {
      if (trashFolder && trashFolder !== folder) {
        await client.messageMove(uids, trashFolder, {uid: true});
      } else {
        await client.messageFlagsAdd(uids, ['\\Deleted'], {uid: true});
      }
    } finally { lock.release(); }
    await client.logout();
    return { ok: true };
  } catch(e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('email-move-many', async (_, {cfg, folder, uids, targetFolder}) => {
  const client = new ImapFlow({
    host: cfg.imapHost, port: cfg.imapPort, secure: cfg.imapSsl,
    auth: { user: cfg.user, pass: cfg.password },
    logger: false, tls: { rejectUnauthorized: !cfg.tlsIgnoreCert },
  });
  try {
    await client.connect();
    const lock = await client.getMailboxLock(folder);
    try { await client.messageMove(uids, targetFolder, {uid: true}); }
    finally { lock.release(); }
    await client.logout();
    return { ok: true };
  } catch(e) { return { ok: false, error: e.message }; }
});

ipcMain.handle('read-server-file', async (_, filename) => {
  const allowed = ['aoi_signal.php'];
  if (!allowed.includes(filename)) return null;
  try {
    return fs.readFileSync(path.join(__dirname, 'Webspace', filename), 'utf8');
  } catch (_e) { return null; }
});

app.on('web-contents-created', (_event, contents) => {
  contents.on('will-attach-webview', (_waEvent, webPreferences, params) => {
    // Kein eigenes Preload-Script erlaubt
    delete webPreferences.preload;
    delete webPreferences.preloadURL;
    // Node.js-Zugriff grundsätzlich verweigert
    webPreferences.nodeIntegration = false;
    webPreferences.contextIsolation = true;
    // Isolierte Storage-Partition je nach Webview-ID
    const src = params.src || '';
    if (src && !src.startsWith('file://') && src !== 'about:blank') {
      webPreferences.partition = params.partition || 'persist:aoi-browser';
    }
  });

  // Popups aus Webviews blockieren (window.open, target="_blank" usw.)
  if (contents.getType() === 'webview') {
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  }

  // Hauptfenster darf nicht von file:// wegnavigieren
  if (contents.getType() === 'window') {
    contents.on('will-navigate', (navEvent, url) => {
      if (!/^file:/.test(url)) navEvent.preventDefault();
    });
  }
});

// ── Auto-Update ───────────────────────────────────────────────────────────────
autoUpdater.autoDownload = false; // Nutzer entscheidet selbst
autoUpdater.autoInstallOnAppQuit = false;

autoUpdater.on('update-available', info => {
  getMainWindow()?.webContents.send('aoi-update', { event: 'available', version: info.version });
});
autoUpdater.on('download-progress', prog => {
  getMainWindow()?.webContents.send('aoi-update', { event: 'progress', percent: Math.round(prog.percent) });
});
autoUpdater.on('update-downloaded', info => {
  getMainWindow()?.webContents.send('aoi-update', { event: 'ready', version: info.version });
});
autoUpdater.on('error', err => {
  console.warn('[Update] Fehler:', err.message);
});

ipcMain.on('update-download', () => autoUpdater.downloadUpdate().catch(e => console.warn('[Update]', e.message)));
ipcMain.on('update-install',  () => autoUpdater.quitAndInstall());
ipcMain.handle('get-app-version', () => app.getVersion());
ipcMain.handle('check-for-updates', () => autoUpdater.checkForUpdates().catch(e => ({ error: e.message })));

app.whenReady().then(() => {
  // Haupt-App: Kamera/Mikrofon für Video-Anrufe + Fullscreen erlauben
  session.defaultSession.setPermissionRequestHandler((_wc, perm, cb) => cb(perm === 'fullscreen' || perm === 'media'));
  // Browser-/Radio-Webview: nur Fullscreen – kein Kamera-/Mikrofon-Zugriff für externe Sites
  const restrictedHandler = (_wc, perm, cb) => cb(perm === 'fullscreen');
  session.fromPartition('persist:aoi-browser').setPermissionRequestHandler(restrictedHandler);
  session.fromPartition('persist:aoi-radio').setPermissionRequestHandler(restrictedHandler);
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
  // Update-Check 5s nach Start (damit App erst vollständig geladen ist)
  setTimeout(() => autoUpdater.checkForUpdates().catch(e => console.warn('[Update]', e.message)), 5000);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ── P2P IPv6 (node:dgram + Noise IK) ──────────────────────────────────────

function getMainWindow() {
  return BrowserWindow.getAllWindows()[0] || null;
}

p2p.setEmitter((event, data) => {
  const win = getMainWindow();
  if (win) win.webContents.send(event, data);
});

ipcMain.handle('p2p-init', (_, privB64, pubB64) => {
  return new Promise(resolve => {
    p2p.init(privB64, pubB64, (err, info) => {
      if (err) { resolve({ ok: false, error: err.message }); return; }
      resolve({ ok: true, addr: info ? info.addr : null, port: info ? info.port : null });
    });
  });
});

ipcMain.handle('p2p-get-addr',    ()                         => p2p.getAddr());
ipcMain.handle('p2p-connect',     (_, name, pub, addr, port) => p2p.connect(name, pub, addr, port));
ipcMain.handle('p2p-send',        (_, name, text)            => p2p.send(name, text));
ipcMain.handle('p2p-disconnect',  (_, name)                  => { p2p.disconnect(name); return true; });
ipcMain.handle('p2p-is-ready',    (_, name)                  => p2p.isReady(name));

ipcMain.handle('get-platform', () => process.platform);

// Flag-Datei: merkt sich ob die Firewall-Regel je erfolgreich gesetzt wurde
const fwFlagPath = path.join(app.getPath('userData'), 'p2p_fw_enabled');

ipcMain.handle('firewall-check-p2p', async () => {
  const plat = process.platform;
  if (plat === 'darwin') return { ok: true, set: true, macos: true };
  if (plat === 'win32') {
    // Windows: sauber per PowerShell prüfbar ohne Root
    return new Promise(resolve => {
      exec(`powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName 'AOI P2P' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"`,
        (_, stdout) => resolve({ ok: true, set: !!(stdout && stdout.trim() !== '0') })
      );
    });
  }
  // Linux: Flag-Datei lesen (ufw status braucht Root, daher Flag-Ansatz)
  return { ok: true, set: fs.existsSync(fwFlagPath) };
});

ipcMain.handle('firewall-open-p2p', async () => {
  const { exec } = require('child_process');
  const os  = require('os');
  const fs  = require('fs');
  const path = require('path');
  const plat = process.platform;

  return new Promise(resolve => {
    if (plat === 'win32') {
      // Prüfe ob Regel bereits existiert
      exec(`powershell -NoProfile -Command "Get-NetFirewallRule -DisplayName 'AOI P2P' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"`,
        (_, stdout) => {
          if (stdout && stdout.trim() !== '0') { resolve({ ok: true, already: true }); return; }
          // Regel per Prozess-Pfad einschränken: nur AOI-Pakete dürfen durch
          const exePath = process.execPath;
          const script  = `New-NetFirewallRule -DisplayName 'AOI P2P' -Direction Inbound -Protocol UDP -LocalPort 7777-7799 -Program '${exePath}' -Action Allow`;
          const tmp = path.join(os.tmpdir(), 'aoi_fw_setup.ps1');
          try { fs.writeFileSync(tmp, script, 'utf8'); } catch(e) { resolve({ ok: false, error: e.message }); return; }
          exec(`powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -File \\"${tmp}\\"'"`,
            err2 => {
              try { fs.unlinkSync(tmp); } catch(_){}
              resolve(err2 ? { ok: false, error: err2.message } : { ok: true });
            }
          );
        }
      );
    } else if (plat === 'linux') {
      const linuxOk = () => { try { fs.writeFileSync(fwFlagPath, '1', 'utf8'); } catch(_){} resolve({ ok: true }); };
      exec('which ufw', errUfw => {
        if (!errUfw) {
          // allow + enable (--force verhindert SSH-Rückfrage); beide Befehle idempotent
          exec('pkexec sh -c "ufw allow 7777:7799/udp; ufw --force enable"',
            e => e ? resolve({ ok: false, error: e.message }) : linuxOk());
        } else {
          exec('which firewall-cmd', errFw => {
            if (!errFw) {
              exec('pkexec firewall-cmd --add-port=7777-7799/udp --permanent', e => {
                if (e) { resolve({ ok: false, error: e.message }); return; }
                exec('pkexec firewall-cmd --reload', e2 => e2 ? resolve({ ok: false, error: e2.message }) : linuxOk());
              });
            } else {
              resolve({ ok: false, manual: true });
            }
          });
        }
      });
    } else if (plat === 'darwin') {
      resolve({ ok: true, already: true, macos: true });
    } else {
      resolve({ ok: false, error: 'Unbekanntes Betriebssystem' });
    }
  });
});
