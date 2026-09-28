# Sicherheitsarchitektur – AOI 9.0

## Allgemeine Prinzipien

| Bereich | Ansatz |
|---|---|
| Passwörter | Nur als SHA-256-Hash im lokalen `localStorage`, nie übertragen |
| E-Mail-Passwörter | Electron `safeStorage` (Windows DPAPI / macOS Keychain) |
| Chat-Inhalte | End-to-End-verschlüsselt via WebRTC DTLS/SRTP – kein Server sieht den Inhalt |
| Server-Datendateien | `<?php exit; ?>` Header + `.htaccess 604` – kein Direktzugriff per Browser |
| Schreiboperationen | Atomares Schreiben (`.tmp` + rename) – keine Race Conditions |

---

## TLS bei E-Mail (IMAP/SMTP)

`rejectUnauthorized` ist standardmäßig `true` (Zertifikatsprüfung aktiv).

Nutzer können im E-Mail-Dialog explizit **„Selbst-signierte Zertifikate erlauben"**
aktivieren – gedacht für private Heimserver mit eigenem Zertifikat.
Diese Option wird zusammen mit der Konfiguration gespeichert.

---

## Föderations-Sicherheit (aoi_signal.php)

### SSRF-Schutz (`fed_url_safe()`)

Server-URLs werden vor der Aufnahme in die Peer-Liste validiert:

- **Erlaubt:** `http://` und `https://`
- **Blockiert:** alle privaten IP-Bereiche:
  - `127.0.0.0/8` (Loopback)
  - `10.0.0.0/8` (Class A privat)
  - `172.16.0.0/12` (Class B privat)
  - `192.168.0.0/16` (Class C privat)
  - `169.254.0.0/16` (Link-local / Cloud-Metadaten wie AWS `169.254.169.254`)
  - `0.0.0.0/8`

**Warum HTTP erlaubt?**
Eine reine HTTPS-Pflicht würde kostenlose Webspaces (z. B. beplaced.net) ausschließen,
die kein TLS anbieten. Der eigentliche SSRF-Schutz ist der private-IP-Check –
nicht das Protokoll. WebRTC-Chat-Inhalte sind immer E2E-verschlüsselt (DTLS/SRTP);
lediglich Signalmetadaten (*wer verbindet sich mit wem*) könnten über einen
HTTP-Federation-Server unverschlüsselt weitergeleitet werden.
Wer maximale Privatsphäre für Signalmetadaten will, betreibt einen HTTPS-Server.

### Rate-Limiting (`federation_signal`)

`federation_signal` ist ohne Token erreichbar (Fremde Server kennen das lokale
Passwort nicht). Schutz gegen Inbox-Flooding:

- Max. **30 Anfragen pro 60 Sekunden pro IP**
- Zähler in `DATEN_DIR/rl_<iphash>.php` (automatisch rotierend)
- Überschreitung → HTTP 429

### XSS-Schutz

Alle fremden Daten (Buddy-Namen, Nachrichten) werden vor der DOM-Ausgabe mit
`escHtml()` escapt. Eingehende P2P-Nachrichten (`aoiReceiveIM`) nutzen
ausschließlich `escHtml()`, kein rohes `innerHTML` mit Benutzereingaben.

### WebRTC & IP-Sichtbarkeit

Bei P2P-Verbindungen tauschen beide Clients ihre ICE-Kandidaten (öffentliche IPs)
aus – das ist technisch unvermeidbar. Buddies können damit den groben
Standort/Provider des Gegenübers sehen. AOI ist für private Netzwerke unter
bekannten Personen konzipiert; ein anonymes Netz ist kein Designziel.

---

## Was absichtlich *nicht* zentral gespeichert wird

- Chat-Nachrichten (nur lokal im `localStorage`)
- Offline-Nachrichten nach Zustellung (werden nach Poll gelöscht)
- WebRTC-Signale (TTL-basierend, werden automatisch bereinigt)
