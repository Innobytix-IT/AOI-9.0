# AOI 9.0 Nostalgia

<p align="center">
  <img src="docs/logo.svg" alt="AOI 9.0 Nostalgia Logo" width="300"/>
</p>

<p align="center">
  <a href="https://github.com/Innobytix-IT/AOI-9.0/releases/latest"><img src="https://img.shields.io/github/v/release/Innobytix-IT/AOI-9.0?label=Release&color=brightgreen" alt="Release"/></a>
  <a href="https://github.com/Innobytix-IT/AOI-9.0/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/Innobytix-IT/AOI-9.0/build.yml?label=Build" alt="Build"/></a>
  <a href="https://www.gnu.org/licenses/agpl-3.0"><img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg" alt="License: AGPL v3"/></a>
  <a href="https://www.electronjs.org/"><img src="https://img.shields.io/badge/Electron-44-47848F?logo=electron&logoColor=white" alt="Electron"/></a>
  <a href="https://github.com/Innobytix-IT/AOI-9.0/releases/latest"><img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey" alt="Platform"/></a>
</p>

**Retro AOL-style Electron desktop app with WebRTC P2P messaging**

AOI 9.0 Nostalgia bringt das Feeling der frühen 2000er zurück – mit moderner Technik darunter.  
Ein klassischer Instant-Messenger-Look, echter P2P-Chat via WebRTC und ein integrierter Webbrowser.

---

## Screenshots

| Anmelden | Verbinden |
|----------|-----------|
| ![Login](docs/screenshots/login.png) | ![Verbinden](docs/screenshots/verbinden.png) |

| Desktop mit Chat & Sport | Finanzen & Chat |
|--------------------------|-----------------|
| ![Desktop](docs/screenshots/desktop.webp) | ![Finanzen](docs/screenshots/finanzen.webp) |

| E-Mail-Postfach |
|-----------------|
| ![Postfach](docs/screenshots/postfach.png) |

| Radio, Postfach & Chat gleichzeitig |
|-------------------------------------|
| ![Radio Postfach Chat](docs/screenshots/radio_postfach_chat.webp) |

---

## Features

- **Retro-Design** – Klassische AOL-Optik mit Buddy-Liste, Sounds und Modem-Verbindungsanimation
- **WebRTC P2P Messaging** – Direkte Nachrichten zwischen Buddies ohne zentralen Nachrichtenserver
- **Video- & Audioanrufe** – Echte P2P-Video- und Audioanrufe via WebRTC direkt zwischen Buddies
- **Dateiübertragung ohne Limit** – Beliebige Dateien direkt P2P via DataChannel, kein Umweg über Server
- **LAN-Direktverbindung** – Automatische Erkennung von Buddies im lokalen Netz (IPv4 LAN Fallback)
- **Buddy-Verwaltung** – Gruppen, Online/Offline-Status, Sortierung, Kontextmenü, Buddy-Suche
- **Screen Names** – Mehrere Namen pro Installation, Eindeutigkeitsprüfung via Server
- **Integrierter Browser** – Webviewer mit Navigationsliste (Wetter, Sport, Musik, Suche …)
- **Integriertes E-Mail-Postfach** – IMAP/SMTP mit Ordnernavigation, Hintergrundpolling, Benachrichtigung
- **Sounds** – Modem-Einwahl, Türklingeln bei Buddy-Login, E-Mail-Benachrichtigung (optional)
- **Eigener Signaling-Server** – PHP 7.2+, läuft auf jedem Standard-Webspace
- **Föderations-Netzwerk** – Dezentrales Gossip-Netz; AOI-Instanzen finden sich ohne Root-Server
- **AGPL-3.0** – Quelloffene Software; wer das Netzwerk nutzt, muss den Quellcode teilen

### Neu in v9.2

- **Video- & Audioanrufe** – Vollständige WebRTC-basierte Video- und Audioanrufe zwischen Buddies; In-Band-Signaling über den bestehenden DataChannel, kein separater Signaling-Kanal nötig
- **LAN-Direktverbindung** – Automatischer IPv4-LAN-Fallback: Buddies im selben Netz verbinden sich direkt ohne Umweg über den Signaling-Server
- **Animiertes P2P-Logo** – Neues Erscheinungsbild mit animierten Datenpunkten zwischen Netzwerkknoten; symbolisiert das dezentrale P2P-Konzept; CSS-basierte Animation (kein SMIL-Delay beim Start)

### Neu in v9.1

- **AOI Tresor** – Lokaler AES-256-GCM-Schlüsselspeicher (PBKDF2, 100 000 Iterationen) für private Schlüssel und Token; auf Windows transparenter DPAPI-Fallback
- **Noise IK Handshake** – Jeder Client hat ein X25519-Langzeitschlüsselpaar; `noise_register` läuft vollständig verschlüsselt über diesen Kanal, Token verlassen das Gerät nie im Klartext
- **TOFU-Pinning** – Der öffentliche Schlüssel des Signaling-Servers wird beim ersten Verbinden gepinnt; Schlüsselwechsel ohne expliziten Reset löst eine Warnung aus
- **Federation-Verschlüsselung** – Server-zu-Server-Requests werden mit ephemeralen X25519-Schlüsseln + AES-256-GCM verschlüsselt (`v:'fed1'`)
- **safeStorage-Fallback blockiert** – E-Mail-Passwörter werden nur gespeichert wenn Systemverschlüsselung verfügbar ist; kein Klartext-Fallback

---

## Technik

| Schicht | Technologie |
|---------|-------------|
| Desktop-App | [Electron 44](https://www.electronjs.org/) |
| Chat P2P | WebRTC DataChannel (DTLS/SRTP E2E) |
| Video- & Audioanrufe | WebRTC MediaStream – In-Band-Signaling via DataChannel |
| LAN-Direktverbindung | IPv4-LAN-Fallback, automatische Peer-Erkennung |
| Signaling-Verschlüsselung | Noise IK – X25519 + HKDF-SHA256 + AES-256-GCM |
| Server-Vertrauen | TOFU-Pinning des Server-Noise-Pub-Keys |
| Schlüsselspeicher | AOI Tresor (AES-256-GCM + PBKDF2) / Windows DPAPI |
| Federation | Dezentrales Gossip-Netz, ephemerales X25519+AES-256-GCM |
| Signaling-Server | PHP 7.2+ (TTL-basierte Präsenz, kein Cronjob nötig) |
| E-Mail | IMAP/SMTP via ImapFlow + nodemailer |
| Persistenz (lokal) | `localStorage` + AOI Tresor |
| STUN | `stun:stun.l.google.com:19302` |

---

## Voraussetzungen

- **Node.js** ≥ 18 und **npm**
- Einen **Webspace mit PHP 7.2+** für den Signaling-Server
- Electron wird automatisch per `npm install` mitgeladen

---

## Installation

```bash
git clone https://github.com/Innobytix-IT/AOI-9.0.git
cd AOI-9.0
npm install
npm start
```

---

## Signaling-Server einrichten

Der Signaling-Server läuft auf deinem eigenen Webspace.  
Er sieht **nur**, wer online ist und wer mit wem verbinden will – niemals den Inhalt der Gespräche.

1. **`aoi_signal.php`** in ein Verzeichnis auf deinem Webspace hochladen
2. **`.htaccess_aoi`** als **`.htaccess`** in dasselbe Verzeichnis hochladen
3. Eine Datei **`aoi_token.php`** selbst anlegen – **PHP-Format empfohlen** (schützt vor Direktzugriff falls `.htaccess` nicht greift, z. B. auf Nginx):
   ```php
   <?php
   defined('AOI_SIGNAL_ACTIVE') or die('403 Forbidden');
   return 'mein-geheimes-passwort-hier';
   ```
   Alternativ (Plaintext, nur wenn `.htaccess` zuverlässig aktiv ist):
   ```
   mein-geheimes-passwort-hier
   ```
4. Das Verzeichnis `aoi_data/` legt das Script beim ersten Aufruf automatisch an

**Selbsttest:** GET-Anfrage an die PHP-URL → `{"ok":true,"server":"AOI 9.0 Signal",...}`

### AHPT-Server in der App

Im Anmeldefenster kannst du unter **AHPT-Server** die URL deines eigenen Signaling-Servers eintragen.  
Standard ist `https://innobytix-it.de/AOI_9/AOI_Treffpunkt/aoi_signal.php`.

---

## Projekt-Struktur

```
AOI-9.0/
├── main.js              # Electron Main Process
├── preload.js           # Context Bridge
├── renderer/
│   └── index.html       # Komplette UI + WebRTC-Client
├── Alt/                 # Sounds und Assets
├── Webspace/            # Webspace-Dateien (aoi_token.php → NICHT ins Git!)
├── aoi_signal.php       # PHP Signaling-Server
├── .htaccess_aoi        # Als .htaccess auf den Webspace hochladen
├── package.json
└── LICENSE
```

> **Sicherheit:** `Webspace/aoi_token.php` enthält das Shared Secret und ist in `.gitignore` ausgeschlossen – diese Datei niemals committen!

---

## Lizenz

[GNU Affero General Public License v3.0](LICENSE)  
Copyright © 2026 Manuel Person (Innobytix-IT)

Wer AOI 9.0 oder eine abgeleitete Version auf einem öffentlich zugänglichen Server betreibt,  
muss den Quellcode dieser Version veröffentlichen.
