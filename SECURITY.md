# Sicherheitsarchitektur – AOI 9.1

## Allgemeine Prinzipien

| Bereich | Ansatz |
|---|---|
| Login-Passwörter | Nur als SHA-256-Hash im lokalen `localStorage`, nie übertragen |
| E-Mail-Passwörter | Electron `safeStorage` (Windows DPAPI / macOS Keychain); kein Klartext-Fallback – Speichern schlägt fehl wenn Systemverschlüsselung nicht verfügbar |
| Noise-Privat-Key | AOI Tresor (Linux/Mac) oder `localStorage` (Windows DPAPI-Pfad) |
| Server-Token | AOI Tresor; verlässt das Gerät nur im Noise-verschlüsselten Payload |
| Chat-Inhalte | P2P via WebRTC DTLS/SRTP – kein Server sieht den Inhalt |
| Server-Datendateien | `<?php exit; ?>` Header + `.htaccess 604` – kein Direktzugriff per Browser |
| Schreiboperationen | Atomares Schreiben (`.tmp` + rename) – keine Race Conditions |

---

## AOI Tresor

Der AOI Tresor ist ein lokaler Schlüsselspeicher, der sensible Werte verschlüsselt in `localStorage` ablegt.

| Parameter | Wert |
|---|---|
| Algorithmus | AES-256-GCM |
| Schlüsselableitung | PBKDF2 – SHA-256, 100 000 Iterationen, 32-Byte-Ausgabe |
| Salt | 16 Byte zufällig pro Nutzer, in `localStorage` gespeichert |
| IV | 12 Byte zufällig pro Schreibvorgang |
| Plattform | Linux / macOS (aktiv) – Windows nutzt transparenten DPAPI-Fallback via `safeStorage` |

Gespeicherte Felder: `noise_priv` (X25519-Langzeitschlüssel), `signal_token`, `email_cfg`.

---

## Noise IK – Signaling-Verschlüsselung

Jeder AOI-Client generiert beim ersten Login ein X25519-Langzeitschlüsselpaar (SPK).  
Der öffentliche Teil wird beim Signaling-Server registriert; der private Teil verlässt das Gerät nie.

**Handshake (`noise_register`):**

1. Client generiert ein ephemeres X25519-Paar (`ek`)
2. DH: `ek_priv × server_pub` → HKDF-SHA256 → Sitzungsschlüssel
3. Payload (inkl. Server-Token und eigenem `spk_pub`) wird mit AES-256-GCM + AAD verschlüsselt
4. Server dekryptiert, verifiziert den Token, speichert `spk_pub`

Das Ergebnis: Der Server-Token verlässt das Gerät ausschließlich im verschlüsselten Noise-Payload – niemals im Klartext über das Netz.

---

## TOFU – Server-Key-Pinning

Beim ersten Verbinden wird der öffentliche Noise-Schlüssel des Signaling-Servers (`noise_pub`) in `localStorage` gepinnt (Trust On First Use).

- Bei allen folgenden Verbindungen wird der aktuelle Server-Key gegen den gepinnten verglichen
- Abweichung → Verbindung wird abgebrochen, Warnung in der Statusleiste
- Legitimer Server-Schlüsselwechsel (z. B. nach Neuinstallation): Nutzer kann den Pin unter **Server-Setup → Pin zurücksetzen** löschen

---

## TLS bei E-Mail (IMAP/SMTP)

`rejectUnauthorized` ist standardmäßig `true` (Zertifikatsprüfung aktiv).

Nutzer können im E-Mail-Dialog explizit **„Selbst-signierte Zertifikate erlauben"**
aktivieren – gedacht für private Heimserver mit eigenem Zertifikat.
Diese Option wird zusammen mit der Konfiguration gespeichert.

---

## Föderations-Sicherheit (aoi_signal.php)

### Server-zu-Server-Verschlüsselung (`fed_post_noise`)

Server-zu-Server-Requests im Föderationsnetz werden seit v9.1 verschlüsselt übertragen:

1. Empfänger-Server-Pub-Key wird einmalig abgerufen und lokal gecacht (TOFU analog zum Client)
2. Pro Request: ephemeres X25519-Paar generiert, DH → HKDF-SHA256 (`aoi-fed-req-v1`) → AES-256-GCM
3. Envelope: `{"v":"fed1","epk":"…","iv":"…","body":"…"}` (Ciphertext + 16-Byte GCM-Tag)
4. Fallback auf unverschlüsselt nur wenn der Empfänger-Server keinen Noise-Pub-Key bereitstellt

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

## Offline-Nachrichten

Nachrichten an offline Buddies werden **ausschließlich lokal** auf dem Absender-Gerät
in `localStorage` (`aoi_pending_offline`) gespeichert – niemals auf dem Server.
Sobald der Empfänger online kommt und ein WebRTC-DataChannel geöffnet wird,
liefert `aoiDeliverPendingMsgs()` die ausstehenden Nachrichten direkt P2P aus.

Einschränkung: Wenn der Absender offline geht bevor der Empfänger zurückkehrt,
warten die Nachrichten auf dem Absender-Gerät bis beide gleichzeitig online sind
(AIM-konformes Verhalten).

---

## Was absichtlich *nicht* zentral gespeichert wird

- Chat-Nachrichten (nur lokal im `localStorage`)
- Offline-Nachrichten (liegen beim Absender, nie auf dem Server)
- WebRTC-Signale (TTL-basierend, werden automatisch bereinigt)
